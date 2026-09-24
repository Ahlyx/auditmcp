use rusqlite::{Connection, OpenFlags};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncBufReadExt;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::io::BufReader;
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};
use uuid::Uuid;

const BINARY: &str = env!("CARGO_BIN_EXE_auditmcp");

struct TestDir(PathBuf);

impl TestDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!("auditmcp-stdio-{label}-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct RunningProxy {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
}

struct Harness {
    config: PathBuf,
    db: PathBuf,
    _dir: TestDir,
}

#[cfg(windows)]
fn python() -> &'static str {
    "python"
}

#[cfg(not(windows))]
fn python() -> &'static str {
    "python3"
}

fn toml_string(value: &str) -> String {
    serde_json::to_string(value).unwrap()
}

fn make_harness(label: &str) -> Harness {
    make_harness_with_cadence(label, 1, 1)
}

fn make_harness_with_cadence(label: &str, cadence_min: u64, cadence_max: u64) -> Harness {
    let dir = TestDir::new(label);
    let config = dir.0.join("config.toml");
    let db = dir.0.join("audit.db");
    let key = dir.0.join("chain.key");
    let contents = format!(
        "[target]\nserver_name = \"fixture\"\n\n[logging]\ndb_path = {}\ndefault_tier = \"minimal\"\n\n[chain]\nkey_path = {}\n\n[heartbeat]\nenabled = true\ncadence_min_secs = {cadence_min}\ncadence_max_secs = {cadence_max}\n\n[anchor]\nenabled = false\n",
        toml_string(&db.to_string_lossy()),
        toml_string(&key.to_string_lossy())
    );
    std::fs::write(&config, contents).unwrap();
    Harness {
        config,
        db,
        _dir: dir,
    }
}

async fn spawn_proxy(
    harness: &Harness,
    extra_env: Option<(&str, &str)>,
    capture_stdout: bool,
) -> RunningProxy {
    spawn_proxy_inner(harness, extra_env, capture_stdout, false).await
}

async fn spawn_proxy_with_stderr(harness: &Harness, capture_stdout: bool) -> RunningProxy {
    spawn_proxy_inner(harness, None, capture_stdout, true).await
}

async fn spawn_proxy_inner(
    harness: &Harness,
    extra_env: Option<(&str, &str)>,
    capture_stdout: bool,
    capture_stderr: bool,
) -> RunningProxy {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("test-fixtures")
        .join("fake_server.py");

    let mut command = Command::new(BINARY);
    command
        .arg("run")
        .arg("--config")
        .arg(&harness.config)
        .arg("--")
        .arg(python())
        .arg(fixture)
        .stdin(Stdio::piped())
        .stdout(if capture_stdout {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stderr(if capture_stderr {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .kill_on_drop(true);
    if let Some((name, value)) = extra_env {
        command.env(name, value);
    }
    let mut child = command.spawn().unwrap();
    let stdin = child.stdin.take();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    RunningProxy {
        child,
        stdin,
        stdout,
        stderr,
    }
}

fn block_lease_storage(db: &Path) {
    let mut lease_dir = db.as_os_str().to_os_string();
    lease_dir.push(".leases");
    std::fs::write(PathBuf::from(lease_dir), b"not a directory").unwrap();
}

fn session_start_liveness(db: &Path) -> Option<serde_json::Value> {
    let conn = Connection::open_with_flags(db, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let args_json: String = conn
        .query_row(
            "SELECT args_json FROM tool_calls WHERE tool_name = '__session_start' ORDER BY id LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    serde_json::from_str::<serde_json::Value>(&args_json).unwrap()["liveness"]
        .as_object()
        .cloned()
        .map(serde_json::Value::Object)
}

async fn wait_for_row(db: &Path, tool_name: &str, timeout: Duration) {
    tokio::time::timeout(timeout, async {
        loop {
            if db.exists() {
                if let Ok(conn) = Connection::open_with_flags(db, OpenFlags::SQLITE_OPEN_READ_ONLY)
                {
                    let found: bool = conn
                        .query_row(
                            "SELECT EXISTS(SELECT 1 FROM tool_calls WHERE tool_name = ?1)",
                            [tool_name],
                            |row| row.get(0),
                        )
                        .unwrap_or(false);
                    if found {
                        return;
                    }
                }
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {tool_name} in {}", db.display()));
}

async fn wait_for_start_count(db: &Path, count: usize, timeout: Duration) {
    tokio::time::timeout(timeout, async {
        loop {
            if db.exists() {
                if let Ok(conn) = Connection::open_with_flags(db, OpenFlags::SQLITE_OPEN_READ_ONLY)
                {
                    let found: i64 = conn
                        .query_row(
                            "SELECT COUNT(*) FROM tool_calls WHERE tool_name = '__session_start'",
                            [],
                            |row| row.get(0),
                        )
                        .unwrap_or(0);
                    if found as usize >= count {
                        return;
                    }
                }
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "timed out waiting for {count} session starts in {}",
            db.display()
        )
    });
}

fn session_ids(db: &Path, tool_name: &str) -> Vec<String> {
    let conn = Connection::open_with_flags(db, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let mut statement = conn
        .prepare("SELECT session_id FROM tool_calls WHERE tool_name = ?1 ORDER BY id")
        .unwrap();
    statement
        .query_map([tool_name], |row| row.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

fn rows(db: &Path) -> Vec<(String, String, String)> {
    let conn = Connection::open_with_flags(db, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let mut statement = conn
        .prepare("SELECT tool_name, status, session_id FROM tool_calls ORDER BY id")
        .unwrap();
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

async fn assert_verify(config: &Path) {
    let output = Command::new(BINARY)
        .arg("verify")
        .arg("--config")
        .arg(config)
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "verify failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

async fn close_cleanly(mut running: RunningProxy) {
    drop(running.stdin.take());
    let output = tokio::time::timeout(Duration::from_secs(8), running.child.wait_with_output())
        .await
        .expect("proxy did not complete clean EOF shutdown")
        .unwrap();
    assert!(
        output.status.success(),
        "proxy stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn client_eof_drains_pending_calls_before_one_clean_end() {
    let harness = make_harness("eof");
    let mut running = spawn_proxy(&harness, None, false).await;
    wait_for_row(&harness.db, "__session_start", Duration::from_secs(5)).await;
    // The database-observed heartbeat synchronizes this test with the live
    // task; after EOF, no later heartbeat may cross the session boundary.
    wait_for_row(&harness.db, "__heartbeat", Duration::from_secs(5)).await;

    let stdin = running.stdin.as_mut().unwrap();
    stdin
        .write_all(
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"echo\",\"arguments\":{\"text\":\"ok\"}}}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"no_response\",\"arguments\":{}}}\n",
        )
        .await
        .unwrap();
    drop(running.stdin.take());

    let output = tokio::time::timeout(Duration::from_secs(8), running.child.wait_with_output())
        .await
        .expect("proxy did not stop after client EOF")
        .unwrap();
    assert!(
        output.status.success(),
        "proxy stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let rows = rows(&harness.db);
    let ends: Vec<_> = rows
        .iter()
        .enumerate()
        .filter(|(_, row)| row.0 == "__session_end")
        .collect();
    assert_eq!(ends.len(), 1, "session must have exactly one clean end");
    let timeout_index = rows
        .iter()
        .position(|row| row.0 == "no_response" && row.1 == "timeout")
        .expect("the unresolved call must be logged as timeout");
    assert!(
        timeout_index < ends[0].0,
        "timeout must precede session end"
    );
    let end_index = ends[0].0;
    assert!(
        rows.iter()
            .enumerate()
            .all(|(index, row)| row.0 != "__heartbeat" || index < end_index),
        "no heartbeat may appear after session end"
    );
    assert_verify(&harness.config).await;
}

#[tokio::test]
async fn unavailable_lease_storage_warns_but_stdio_proxy_still_logs_and_ends_cleanly() {
    let harness = make_harness("lease-unavailable-clean");
    block_lease_storage(&harness.db);
    let mut running = spawn_proxy_with_stderr(&harness, true).await;
    wait_for_row(&harness.db, "__session_start", Duration::from_secs(5)).await;
    assert_eq!(session_start_liveness(&harness.db), None);

    let mut stderr = running.stderr.take().unwrap();
    let stderr_task = tokio::spawn(async move {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).await.unwrap();
        String::from_utf8_lossy(&bytes).into_owned()
    });

    running
        .stdin
        .as_mut()
        .unwrap()
        .write_all(
            b"{\"jsonrpc\":\"2.0\",\"id\":77,\"method\":\"tools/call\",\"params\":{\"name\":\"echo\",\"arguments\":{\"text\":\"lease fallback\"}}}\n",
        )
        .await
        .unwrap();
    let mut stdout = BufReader::new(running.stdout.take().unwrap());
    let mut response = String::new();
    tokio::time::timeout(Duration::from_secs(5), stdout.read_line(&mut response))
        .await
        .expect("proxy did not forward the echo response")
        .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&response).unwrap()["id"],
        77
    );
    drop(stdout);
    drop(running.stdin.take());
    let status = tokio::time::timeout(Duration::from_secs(8), running.child.wait())
        .await
        .expect("proxy did not cleanly shut down without lease storage")
        .unwrap();
    assert!(status.success());

    let logs = stderr_task.await.unwrap();
    assert!(
        logs.contains("continuing without hard-kill recovery evidence"),
        "lease failure warning should explain the degraded recovery behavior: {logs}"
    );
    let rows = rows(&harness.db);
    assert!(rows.iter().any(|row| row.0 == "echo" && row.1 == "success"));
    assert_eq!(
        rows.iter().filter(|row| row.0 == "__session_end").count(),
        1,
        "graceful EOF still records a clean end"
    );
    assert!(session_start_liveness(&harness.db).is_none());
    assert_verify(&harness.config).await;
}

#[tokio::test]
async fn hard_killed_lease_less_session_remains_unknown_on_later_startup() {
    let harness = make_harness("lease-unavailable-killed");
    block_lease_storage(&harness.db);
    let mut killed = spawn_proxy(&harness, None, false).await;
    wait_for_row(&harness.db, "__session_start", Duration::from_secs(5)).await;
    let killed_session = session_ids(&harness.db, "__session_start")[0].clone();

    killed.child.start_kill().unwrap();
    let _ = killed.child.wait().await.unwrap();
    drop(killed.stdin.take());
    assert!(!rows(&harness.db)
        .iter()
        .any(|row| row.0 == "__session_end" && row.2 == killed_session));

    let successor = spawn_proxy(&harness, None, false).await;
    wait_for_start_count(&harness.db, 2, Duration::from_secs(5)).await;
    assert!(
        session_ids(&harness.db, "__session_abandoned").is_empty(),
        "a missing lease must leave the forcibly killed session unknown"
    );
    assert!(session_start_liveness(&harness.db).is_none());
    close_cleanly(successor).await;
    assert!(session_ids(&harness.db, "__session_abandoned").is_empty());
    assert_verify(&harness.config).await;
}

#[tokio::test]
async fn target_exit_first_still_writes_exactly_one_session_end() {
    let harness = make_harness("child-first");
    let running = spawn_proxy(&harness, Some(("FAKE_SERVER_EXIT_IMMEDIATELY", "1")), false).await;
    wait_for_row(&harness.db, "__session_start", Duration::from_secs(5)).await;
    wait_for_row(&harness.db, "__session_end", Duration::from_secs(5)).await;
    let output = tokio::time::timeout(Duration::from_secs(8), running.child.wait_with_output())
        .await
        .expect("proxy did not stop after its target exited")
        .unwrap();
    assert!(
        output.status.success(),
        "proxy stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rows = rows(&harness.db);
    assert_eq!(
        rows.iter().filter(|row| row.0 == "__session_end").count(),
        1
    );
    assert_verify(&harness.config).await;
}

#[tokio::test]
async fn simultaneous_client_eof_and_child_exit_write_only_one_session_end() {
    let harness = make_harness("eof-child-race");
    let mut running =
        spawn_proxy(&harness, Some(("FAKE_SERVER_EXIT_IMMEDIATELY", "1")), false).await;
    wait_for_row(&harness.db, "__session_start", Duration::from_secs(5)).await;
    // The target exits during startup while the client closes its pipe. The
    // main select may observe either event first, but both use one shutdown
    // path and must produce the same single boundary.
    drop(running.stdin.take());
    let output = tokio::time::timeout(Duration::from_secs(8), running.child.wait_with_output())
        .await
        .expect("proxy did not complete the EOF/child-exit race")
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        rows(&harness.db)
            .iter()
            .filter(|row| row.0 == "__session_end")
            .count(),
        1
    );
    assert_verify(&harness.config).await;
}

#[tokio::test]
async fn target_that_ignores_eof_is_terminated_after_a_bounded_grace() {
    let harness = make_harness("ignore-eof");
    let mut running = spawn_proxy(&harness, Some(("FAKE_SERVER_IGNORE_EOF", "1")), false).await;
    wait_for_row(&harness.db, "__session_start", Duration::from_secs(5)).await;
    drop(running.stdin.take());
    let output = tokio::time::timeout(Duration::from_secs(8), running.child.wait_with_output())
        .await
        .expect("proxy did not terminate a target that ignored EOF")
        .unwrap();
    assert!(
        output.status.success(),
        "proxy stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        rows(&harness.db)
            .iter()
            .filter(|row| row.0 == "__session_end")
            .count(),
        1
    );
    assert_verify(&harness.config).await;
}

#[tokio::test]
async fn recovery_only_marks_the_killed_session_among_overlapping_same_name_processes() {
    let harness = make_harness_with_cadence("overlapping", 30, 90);
    let mut a = spawn_proxy(&harness, None, false).await;
    wait_for_start_count(&harness.db, 1, Duration::from_secs(5)).await;
    let session_a = session_ids(&harness.db, "__session_start")[0].clone();

    let b = spawn_proxy(&harness, None, false).await;
    wait_for_start_count(&harness.db, 2, Duration::from_secs(5)).await;
    let session_b = session_ids(&harness.db, "__session_start")[1].clone();
    assert_ne!(session_a, session_b);
    assert_eq!(session_ids(&harness.db, "__session_abandoned").len(), 0);

    // Force-terminate only A. Its target sees its pipe close and exits; B's
    // independently locked lease remains held in the same database.
    a.child.start_kill().unwrap();
    let _ = a.child.wait().await;
    drop(a.stdin.take());
    assert!(!rows(&harness.db)
        .iter()
        .any(|row| row.0 == "__session_end" && row.2 == session_a));

    let c = spawn_proxy(&harness, None, false).await;
    wait_for_row(&harness.db, "__session_abandoned", Duration::from_secs(5)).await;
    wait_for_start_count(&harness.db, 3, Duration::from_secs(5)).await;
    let abandoned = session_ids(&harness.db, "__session_abandoned");
    assert_eq!(abandoned, vec![session_a.clone()]);
    assert!(!abandoned.contains(&session_b));

    // A repeated startup sees A's recovery row, while B and C still own
    // their leases. No second marker is appended and neither live session
    // is selected merely because it shares the logical server name.
    let d = spawn_proxy(&harness, None, false).await;
    wait_for_start_count(&harness.db, 4, Duration::from_secs(5)).await;
    assert_eq!(
        session_ids(&harness.db, "__session_abandoned"),
        vec![session_a]
    );

    close_cleanly(d).await;
    close_cleanly(c).await;
    close_cleanly(b).await;
    let final_rows = rows(&harness.db);
    for session_id in [
        session_b,
        session_ids(&harness.db, "__session_start")[2].clone(),
    ] {
        assert!(final_rows
            .iter()
            .any(|row| row.0 == "__session_end" && row.2 == session_id));
    }
    assert_verify(&harness.config).await;
}

#[cfg(unix)]
#[tokio::test]
async fn operating_system_signal_still_uses_the_clean_shutdown_path() {
    let harness = make_harness("sigterm");
    let mut running = spawn_proxy(&harness, None, true).await;
    wait_for_row(&harness.db, "__session_start", Duration::from_secs(5)).await;

    // Get a response from the real target first. This proves the proxy has
    // reached its active select loop before SIGTERM is sent.
    running
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n")
        .await
        .unwrap();
    let mut stdout = BufReader::new(running.stdout.take().unwrap());
    let mut response = String::new();
    tokio::time::timeout(Duration::from_secs(5), stdout.read_line(&mut response))
        .await
        .expect("proxy did not forward initialize response")
        .unwrap();
    let response: serde_json::Value =
        serde_json::from_str(&response).expect("forwarded response must remain valid JSON");
    assert_eq!(response["id"], 1);

    let pid = running.child.id().unwrap().to_string();
    let signal = Command::new("kill")
        .arg("-TERM")
        .arg(pid)
        .status()
        .await
        .unwrap();
    assert!(signal.success());
    let mut rest = String::new();
    let _ = tokio::time::timeout(Duration::from_secs(8), stdout.read_to_string(&mut rest)).await;
    let status = tokio::time::timeout(Duration::from_secs(8), running.child.wait())
        .await
        .expect("proxy did not complete SIGTERM shutdown")
        .unwrap();
    assert!(status.success());
    assert_eq!(
        rows(&harness.db)
            .iter()
            .filter(|row| row.0 == "__session_end")
            .count(),
        1
    );
    assert_verify(&harness.config).await;
}
