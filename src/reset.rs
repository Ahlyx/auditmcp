//! `auditmcp reset` — the migration escape hatch and the only supported
//! "start fresh" path (see the Phase 3.5 spec's "No in-place upgrade"
//! stance: retrofitting HMAC onto an existing chain, or rotating an
//! existing key, are both deliberately unsupported).
//!
//! Destructive by nature, so it refuses to run without `--yes`. With
//! `--keep-old`, the database, key, and anchor files are archived with a
//! timestamped `.reset-bak-<stamp>` suffix rather than deleted; without it,
//! they're removed outright (equivalent to `rm` + fresh start).

use crate::config::Config;
use std::path::{Path, PathBuf};

pub fn run(config_path: &Path, yes: bool, keep_old: bool) -> anyhow::Result<()> {
    if !yes {
        return Err(anyhow::anyhow!(
            "refusing to run without --yes: `reset` is destructive (it discards or archives \
             the existing audit database, chain key, and anchor). Re-run with \
             `auditmcp reset --yes` (add --keep-old to archive rather than delete)."
        ));
    }

    let config = Config::load(config_path)?;
    let db_path = PathBuf::from(&config.logging.db_path);
    let key_path = config.chain.resolved_key_path()?;
    let anchor_path = crate::anchor::resolve_anchor_path(&config.anchor.path)?;

    let stamp = chrono::Utc::now().format("%Y-%m-%d-%H%M%S").to_string();
    let mut summary = Vec::new();

    // Sidecar WAL/SHM files carry no data that isn't also reachable through
    // the main db file once checkpointed, and a fresh `open_for_write`
    // below recreates them as needed -- they're removed rather than
    // archived even under --keep-old.
    for sidecar_ext in ["db-wal", "db-shm"] {
        let sidecar = db_path.with_extension(sidecar_ext);
        let _ = std::fs::remove_file(&sidecar);
    }

    archive_or_remove(&db_path, "database", keep_old, &stamp, &mut summary)?;
    archive_or_remove(&key_path, "key", keep_old, &stamp, &mut summary)?;
    archive_or_remove(&anchor_path, "anchor", keep_old, &stamp, &mut summary)?;

    // Fresh chain: same bootstrap path `run` uses, which -- because
    // nothing exists at `db_path` any more -- takes the "no DB, no key"
    // branch: generates a new root key and writes genesis chain_metadata.
    crate::chain::bootstrap(
        &db_path,
        &key_path,
        config.heartbeat.cadence_min_secs,
        config.heartbeat.cadence_max_secs,
    )?;

    println!("Reset complete.");
    for line in &summary {
        println!("  {line}");
    }
    println!(
        "  created: fresh HMAC-protected chain at {}",
        db_path.display()
    );
    println!("  created: new chain key at {}", key_path.display());

    Ok(())
}

fn archive_or_remove(
    path: &Path,
    label: &str,
    keep_old: bool,
    stamp: &str,
    summary: &mut Vec<String>,
) -> anyhow::Result<()> {
    if !path.exists() {
        return Ok(());
    }

    if keep_old {
        let backup_path = append_suffix(path, &format!(".reset-bak-{stamp}"));
        std::fs::rename(path, &backup_path).map_err(|e| {
            anyhow::anyhow!(
                "failed to archive {label} file {} to {}: {e}",
                path.display(),
                backup_path.display()
            )
        })?;
        summary.push(format!(
            "archived {label}: {} -> {}",
            path.display(),
            backup_path.display()
        ));
    } else {
        std::fs::remove_file(path).map_err(|e| {
            anyhow::anyhow!("failed to remove {label} file {}: {e}", path.display())
        })?;
        summary.push(format!("removed {label}: {}", path.display()));
    }
    Ok(())
}

/// Appends `suffix` to a path's filename, e.g. `audit.db` + `.reset-bak-X`
/// -> `audit.db.reset-bak-X`. Deliberately not `Path::with_extension`,
/// which would REPLACE `db`'s extension rather than append to it.
fn append_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(suffix);
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_support::{remove_db_files, temp_db_path};

    struct Fixture {
        db_path: PathBuf,
        key_path: PathBuf,
        anchor_path: PathBuf,
        config_path: PathBuf,
    }

    impl Fixture {
        fn new(label: &str) -> Self {
            let db_path = temp_db_path(label);
            let key_path = std::env::temp_dir().join(format!(
                "auditmcp_test_reset_key_{label}_{}.key",
                uuid::Uuid::new_v4()
            ));
            let anchor_path = std::env::temp_dir().join(format!(
                "auditmcp_test_reset_anchor_{label}_{}.log",
                uuid::Uuid::new_v4()
            ));
            let config_path = db_path.with_extension("toml");
            std::fs::write(
                &config_path,
                format!(
                    "[target]\n[logging]\ndb_path = '{}'\n[chain]\nkey_path = '{}'\n\
                     [anchor]\npath = '{}'\n",
                    db_path.to_string_lossy(),
                    key_path.to_string_lossy(),
                    anchor_path.to_string_lossy(),
                ),
            )
            .unwrap();
            Fixture {
                db_path,
                key_path,
                anchor_path,
                config_path,
            }
        }

        fn seed(&self) {
            let mode = crate::chain::bootstrap(&self.db_path, &self.key_path, 30, 90).unwrap();
            let mut conn = crate::db::open_for_write(&self.db_path).unwrap();
            crate::db::insert_row_with_key(
                &mut conn,
                &crate::db::test_support::sample_entry(),
                &mode.hash_key(),
            )
            .unwrap();
            std::fs::write(&self.anchor_path, "{}\n").unwrap();
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            remove_db_files(&self.db_path);
            let _ = std::fs::remove_file(&self.key_path);
            let _ = std::fs::remove_file(&self.anchor_path);
            let _ = std::fs::remove_file(&self.config_path);
            // Sweep any archived backups this test's own runs created.
            if let Some(parent) = self.db_path.parent() {
                if let Ok(entries) = std::fs::read_dir(parent) {
                    let stem = self
                        .db_path
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .to_string();
                    for e in entries.flatten() {
                        let name = e.file_name().to_string_lossy().to_string();
                        if name.starts_with(&stem) && name.contains("reset-bak") {
                            let _ = std::fs::remove_file(e.path());
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn reset_without_yes_is_refused() {
        let fx = Fixture::new("reset_refuse");
        let err = run(&fx.config_path, false, false).unwrap_err();
        assert!(err.to_string().contains("--yes"));
    }

    #[test]
    fn reset_without_keep_old_deletes_and_creates_fresh() {
        let fx = Fixture::new("reset_delete");
        fx.seed();
        assert!(fx.db_path.exists());

        run(&fx.config_path, true, false).unwrap();

        assert!(
            fx.db_path.exists(),
            "a fresh database must exist after reset"
        );
        assert!(fx.key_path.exists(), "a fresh key must exist after reset");

        let conn = crate::db::open_readonly(&fx.db_path).unwrap();
        assert!(
            crate::db::read_all_rows(&conn).unwrap().is_empty(),
            "fresh db must start empty"
        );
    }

    #[test]
    fn reset_with_keep_old_archives_rather_than_deletes() {
        let fx = Fixture::new("reset_keep");
        fx.seed();

        run(&fx.config_path, true, true).unwrap();

        assert!(fx.db_path.exists(), "a fresh database must exist");
        let parent = fx.db_path.parent().unwrap();
        let has_backup = std::fs::read_dir(parent)
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| e.file_name().to_string_lossy().contains("reset-bak"));
        assert!(has_backup, "the old database must be archived, not deleted");
    }

    #[test]
    fn reset_on_a_never_run_config_still_creates_a_fresh_chain() {
        let fx = Fixture::new("reset_never_run");
        assert!(!fx.db_path.exists());

        run(&fx.config_path, true, false).unwrap();
        assert!(fx.db_path.exists());
        assert!(fx.key_path.exists());
    }
}
