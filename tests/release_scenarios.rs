use rusqlite::{Connection, OpenFlags};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use uuid::Uuid;

const BINARY: &str = env!("CARGO_BIN_EXE_auditmcp");
const FAKE_API_KEY: &str = "sk-FAKE1234567890abcdefFAKEKEYFAKE00";

struct TestDir(PathBuf);

impl TestDir {
    fn new(label: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("auditmcp-release-{label}-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
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

fn write_config(dir: &Path, db_path: &Path, key_path: &Path) -> PathBuf {
    let config = dir.join("config.toml");
    let content = format!(
        "[target]\nserver_name = \"release_fixture\"\n\n[logging]\ndb_path = {}\ndefault_tier = \"minimal\"\n\n[chain]\nkey_path = {}\n\n[heartbeat]\nenabled = false\n\n[anchor]\nenabled = false\n",
        toml_string(&db_path.to_string_lossy()),
        toml_string(&key_path.to_string_lossy()),
    );
    std::fs::write(&config, content).unwrap();
    config
}

fn write_http_config(
    dir: &Path,
    db_path: &Path,
    key_path: &Path,
    upstream: &str,
    listen: &str,
) -> PathBuf {
    let config = dir.join("http-config.toml");
    let content = format!(
        "[[server]]\nname = \"http_release_fixture\"\nupstream = {}\nlisten = {}\n\n\
         [logging]\ndb_path = {}\ndefault_tier = \"minimal\"\n\n\
         [chain]\nkey_path = {}\n\n\
         [heartbeat]\nenabled = false\n\n\
         [anchor]\nenabled = false\n",
        toml_string(upstream),
        toml_string(listen),
        toml_string(&db_path.to_string_lossy()),
        toml_string(&key_path.to_string_lossy()),
    );
    std::fs::write(&config, content).unwrap();
    config
}

fn free_ports() -> (u16, u16) {
    let upstream = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    (
        upstream.local_addr().unwrap().port(),
        proxy.local_addr().unwrap().port(),
    )
}

async fn wait_for_tcp(address: &str) {
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            if tokio::net::TcpStream::connect(address).await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("listener did not become ready at {address}"));
}

async fn post_http_rpc(address: &str, message: Value) -> Vec<u8> {
    let body = serde_json::to_vec(&message).unwrap();
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    let request = format!(
        "POST /mcp HTTP/1.1\r\nHost: {address}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.write_all(&body).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    response
}

fn rpc_call(id: u64, name: &str, arguments: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": { "name": name, "arguments": arguments },
    })
}

async fn run_proxy(config: &Path, calls: &[Value], response_count: usize) -> Vec<Value> {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("test-fixtures")
        .join("release_status_server.py");
    let mut child = Command::new(BINARY)
        .arg("run")
        .arg("--config")
        .arg(config)
        .arg("--")
        .arg(python())
        .arg(fixture)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut stdout = BufReader::new(stdout);

    for call in calls {
        let mut line = serde_json::to_vec(call).unwrap();
        line.push(b'\n');
        stdin.write_all(&line).await.unwrap();
    }

    let mut responses = Vec::new();
    for _ in 0..response_count {
        let mut line = String::new();
        let bytes = tokio::time::timeout(Duration::from_secs(5), stdout.read_line(&mut line))
            .await
            .expect("timed out waiting for fake target response")
            .unwrap();
        assert!(
            bytes > 0,
            "target closed stdout before all responses arrived"
        );
        responses.push(serde_json::from_str(&line).unwrap());
    }

    drop(stdin);
    let status = tokio::time::timeout(Duration::from_secs(8), child.wait())
        .await
        .expect("auditmcp did not complete stdio EOF shutdown")
        .unwrap();
    assert!(status.success(), "auditmcp exited unsuccessfully: {status}");
    responses
}

async fn command_ok(command: &mut Command) -> std::process::Output {
    let output = command.output().await.unwrap();
    assert!(
        output.status.success(),
        "command failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

async fn verify(config: &Path) {
    command_ok(
        Command::new(BINARY)
            .arg("verify")
            .arg("--config")
            .arg(config),
    )
    .await;
}

async fn export_file(config: &Path, output: &Path) -> Vec<Value> {
    command_ok(
        Command::new(BINARY)
            .arg("export")
            .arg("--config")
            .arg(config)
            .arg("--format")
            .arg("jsonl")
            .arg("--output")
            .arg(output),
    )
    .await;
    std::fs::read_to_string(output)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[tokio::test]
async fn real_binary_status_paths_are_visible_in_query_export_and_verify() {
    let dir = TestDir::new("status-paths");
    let db = dir.0.join("audit.db");
    let key = dir.0.join("chain.key");
    let config = write_config(&dir.0, &db, &key);
    let calls = [
        rpc_call(1, "jsonrpc_error", json!({})),
        rpc_call(2, "simulate_tool_failure", json!({})),
        rpc_call(3, "deferred", json!({})),
        rpc_call(4, "secret", json!({})),
        rpc_call(
            5,
            "echo",
            json!({ "url": "https://first.example", "text": "same" }),
        ),
        rpc_call(
            6,
            "echo",
            json!({ "url": "https://second.example", "text": "same" }),
        ),
        rpc_call(7, "no_response", json!({})),
    ];
    let replies = run_proxy(&config, &calls, 6).await;
    assert_eq!(replies.len(), 6);

    verify(&config).await;
    let all_query = command_ok(
        Command::new(BINARY)
            .arg("query")
            .arg("--config")
            .arg(&config),
    )
    .await;
    let all_text = String::from_utf8_lossy(&all_query.stdout);
    for name in [
        "jsonrpc_error",
        "simulate_tool_failure",
        "deferred",
        "secret",
        "echo",
        "no_response",
    ] {
        assert!(all_text.contains(name), "query output omitted {name}");
    }
    assert!(all_text.contains("timeout"));
    assert!(all_text.contains("deferred"));

    for (status, expected_tool) in [
        ("error", "jsonrpc_error"),
        ("timeout", "no_response"),
        ("deferred", "deferred"),
    ] {
        let output = command_ok(
            Command::new(BINARY)
                .arg("query")
                .arg("--config")
                .arg(&config)
                .arg("--status")
                .arg(status),
        )
        .await;
        let rendered = String::from_utf8_lossy(&output.stdout);
        assert!(
            rendered.contains(expected_tool),
            "query --status {status} omitted {expected_tool}"
        );
    }

    let anomalous = command_ok(
        Command::new(BINARY)
            .arg("query")
            .arg("--config")
            .arg(&config)
            .arg("--anomalous"),
    )
    .await;
    let anomalous = String::from_utf8_lossy(&anomalous.stdout);
    assert!(anomalous.contains("novel_destination"));

    let export_path = dir.0.join("export.jsonl");
    let exported = export_file(&config, &export_path).await;
    let jsonrpc_error = exported
        .iter()
        .find(|row| row["tool_name"] == "jsonrpc_error")
        .unwrap();
    assert_eq!(jsonrpc_error["status"], "error");
    assert!(jsonrpc_error["error_message"]
        .as_str()
        .unwrap()
        .contains("fixture error"));
    let mcp_error = exported
        .iter()
        .find(|row| row["tool_name"] == "simulate_tool_failure")
        .unwrap();
    assert_eq!(mcp_error["status"], "error");
    let mcp_result: Value =
        serde_json::from_str(mcp_error["result_json"].as_str().unwrap()).unwrap();
    assert_eq!(mcp_result["isError"], true);
    let deferred = exported
        .iter()
        .find(|row| row["tool_name"] == "deferred")
        .unwrap();
    assert_eq!(deferred["status"], "deferred");
    let deferred_result: Value =
        serde_json::from_str(deferred["result_json"].as_str().unwrap()).unwrap();
    assert_eq!(deferred_result["taskId"], "fixture-task-1");
    let timeout = exported
        .iter()
        .find(|row| row["tool_name"] == "no_response")
        .unwrap();
    assert_eq!(timeout["status"], "timeout");
    assert!(timeout["result_json"].is_null());

    let secret_row = exported
        .iter()
        .find(|row| row["tool_name"] == "secret")
        .unwrap();
    let redacted_result: Value =
        serde_json::from_str(secret_row["result_json"].as_str().unwrap()).unwrap();
    assert!(!secret_row["result_json"]
        .as_str()
        .unwrap()
        .contains(FAKE_API_KEY));
    assert!(redacted_result.to_string().contains("[REDACTED:"));
    let hash = secret_row["redaction_flags"][0]["sha256"].as_str().unwrap();
    command_ok(
        Command::new(BINARY)
            .arg("unmask")
            .arg("--config")
            .arg(&config)
            .arg(hash)
            .arg("--note")
            .arg("fixture allowlist regression"),
    )
    .await;

    run_proxy(&config, &[rpc_call(1, "secret", json!({}))], 1).await;
    verify(&config).await;
    let verbose = command_ok(
        Command::new(BINARY)
            .arg("query")
            .arg("--config")
            .arg(&config)
            .arg("--verbose"),
    )
    .await;
    assert!(String::from_utf8_lossy(&verbose.stdout).contains("future occurrences not redacted"));

    let exported_after_allowlist = export_file(&config, &dir.0.join("after-allowlist.jsonl")).await;
    let allowlisted = exported_after_allowlist
        .iter()
        .rev()
        .find(|row| row["tool_name"] == "secret")
        .unwrap();
    assert_eq!(allowlisted["redaction_count"], 0);
    let allowed_result: Value =
        serde_json::from_str(allowlisted["result_json"].as_str().unwrap()).unwrap();
    assert_eq!(allowed_result["api_key"], FAKE_API_KEY);
}

#[tokio::test]
async fn copied_database_keeps_old_hashes_and_supports_query_export_append_and_reset() {
    let dir = TestDir::new("copy-upgrade");
    let source_db = dir.0.join("source.db");
    let source_key = dir.0.join("source.key");
    let source_config = write_config(&dir.0, &source_db, &source_key);
    run_proxy(
        &source_config,
        &[rpc_call(1, "echo", json!({ "text": "before-copy" }))],
        1,
    )
    .await;

    // Make the source database a stable copy candidate after the writer has
    // exited, then preserve both database and verification key as a user
    // would when trying an update on a safe duplicate.
    let conn = Connection::open(&source_db).unwrap();
    let _: (i64, i64, i64) = conn
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .unwrap();
    drop(conn);

    let copy_dir = dir.0.join("copy");
    std::fs::create_dir_all(&copy_dir).unwrap();
    let copy_db = copy_dir.join("audit.db");
    let copy_key = copy_dir.join("chain.key");
    std::fs::copy(&source_db, &copy_db).unwrap();
    std::fs::copy(&source_key, &copy_key).unwrap();
    let copy_config = write_config(&copy_dir, &copy_db, &copy_key);

    verify(&copy_config).await;
    let before = row_facts(&copy_db);
    assert_eq!(before.len(), 1);
    assert_eq!(before[0].4, "echo");
    let query = command_ok(
        Command::new(BINARY)
            .arg("query")
            .arg("--config")
            .arg(&copy_config),
    )
    .await;
    assert!(String::from_utf8_lossy(&query.stdout).contains("echo"));
    let exported = export_file(&copy_config, &copy_dir.join("before.jsonl")).await;
    assert_eq!(exported.len(), before.len());

    run_proxy(
        &copy_config,
        &[rpc_call(2, "echo", json!({ "text": "after-copy" }))],
        1,
    )
    .await;
    verify(&copy_config).await;
    let after = row_facts(&copy_db);
    assert!(after.len() > before.len());
    assert_eq!(
        &after[..before.len()],
        before.as_slice(),
        "opening and appending rewrote old row facts"
    );

    command_ok(
        Command::new(BINARY)
            .arg("reset")
            .arg("--config")
            .arg(&copy_config)
            .arg("--yes")
            .arg("--keep-old"),
    )
    .await;
    let archived = std::fs::read_dir(&copy_dir)
        .unwrap()
        .filter_map(Result::ok)
        .any(|entry| entry.file_name().to_string_lossy().contains("reset-bak"));
    assert!(archived, "reset --keep-old must leave an archive copy");
    verify(&copy_config).await;
    assert!(row_facts(&copy_db).is_empty());
}

#[tokio::test]
async fn real_http_binary_logs_non_json_and_capture_truncation_for_query_export_and_verify() {
    let dir = TestDir::new("http-status-paths");
    let db = dir.0.join("http-audit.db");
    let key = dir.0.join("http-chain.key");
    let (upstream_port, listen_port) = free_ports();
    let upstream = format!("http://127.0.0.1:{upstream_port}/mcp");
    let listen_address = format!("127.0.0.1:{listen_port}");
    let config = write_http_config(&dir.0, &db, &key, &upstream, &listen_address);
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("test-fixtures")
        .join("fake_http_server.py");

    let mut upstream_process = Command::new(python())
        .arg(fixture)
        .arg(upstream_port.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut proxy = Command::new(BINARY)
        .arg("serve")
        .arg("--config")
        .arg(&config)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    wait_for_tcp(&listen_address).await;

    let malformed = post_http_rpc(
        &listen_address,
        json!({
            "jsonrpc": "2.0", "id": 31, "method": "tools/call",
            "params": { "name": "return_non_json", "arguments": {} }
        }),
    )
    .await;
    assert!(String::from_utf8_lossy(&malformed).starts_with("HTTP/1.1 502"));

    let large = post_http_rpc(
        &listen_address,
        json!({
            "jsonrpc": "2.0", "id": 32, "method": "tools/call",
            "params": { "name": "large_response", "arguments": {} }
        }),
    )
    .await;
    assert!(String::from_utf8_lossy(&large).starts_with("HTTP/1.1 200"));
    assert!(
        large.len() > 1_100_000,
        "proxy did not forward the complete body"
    );

    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let rows_written = (|| -> rusqlite::Result<i64> {
                let conn = Connection::open(&db)?;
                conn.query_row(
                    "SELECT COUNT(*) FROM tool_calls WHERE tool_name IN ('return_non_json', 'large_response')",
                    [],
                    |row| row.get(0),
                )
            })();
            if matches!(rows_written, Ok(2)) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("HTTP response rows were not written");
    let exported_path = dir.0.join("http-export.jsonl");
    let exported = export_file(&config, &exported_path).await;

    let non_json = exported
        .iter()
        .find(|row| row["tool_name"] == "return_non_json")
        .expect("non-JSON HTTP call missing from export");
    assert_eq!(non_json["status"], "error");
    assert!(non_json["error_message"]
        .as_str()
        .unwrap()
        .contains("502 Bad Gateway from fixture"));

    let truncated = exported
        .iter()
        .find(|row| row["tool_name"] == "large_response")
        .unwrap();
    assert_eq!(truncated["status"], "success");
    assert!(truncated["bytes_out"].as_i64().unwrap() > 1_100_000);
    let result: Value = serde_json::from_str(truncated["result_json"].as_str().unwrap()).unwrap();
    assert_eq!(result["__auditmcp_truncated"], true);
    assert_eq!(result["original_bytes"], truncated["bytes_out"]);
    assert!(result["message"]
        .as_str()
        .unwrap()
        .contains("forwarded to the client"));

    let query = command_ok(
        Command::new(BINARY)
            .arg("query")
            .arg("--config")
            .arg(&config)
            .arg("--status")
            .arg("error"),
    )
    .await;
    assert!(String::from_utf8_lossy(&query.stdout).contains("return_non_json"));
    proxy.start_kill().unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(5), proxy.wait()).await;
    upstream_process.start_kill().unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(5), upstream_process.wait()).await;
    verify(&config).await;
}

fn row_facts(db: &Path) -> Vec<(i64, String, Option<String>, String, String)> {
    let conn = Connection::open_with_flags(db, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let mut statement = conn
        .prepare("SELECT id, hash, prev_hash, timestamp, tool_name FROM tool_calls ORDER BY id")
        .unwrap();
    statement
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })
        .unwrap()
        .map(Result::unwrap)
        .collect()
}
