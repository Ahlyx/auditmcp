//! OS-owned per-session liveness leases.
//!
//! A lease is an empty file whose exclusive OS lock is held for the whole
//! proxy session. The file itself is only an identifier: its existence and
//! age are never evidence. `File::try_lock` is released by the operating
//! system when the owning process dies, so PID reuse and process-tree kills
//! do not affect the liveness test.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub(crate) struct SessionLease {
    id: String,
    _file: File,
}

impl SessionLease {
    /// Creates and locks a unique lease for a new session. The file remains
    /// after clean shutdown: deleting it after releasing its lock could race
    /// a recovery process that already opened the old file and allow a new
    /// file at the same path to be locked independently.
    pub(crate) fn create(db_path: &Path) -> anyhow::Result<Self> {
        let id = Uuid::new_v4().to_string();
        let dir = lease_dir(db_path);
        std::fs::create_dir_all(&dir).map_err(|e| {
            anyhow::anyhow!(
                "failed to create session lease directory {}: {e}",
                dir.display()
            )
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| anyhow::anyhow!("failed to restrict session lease directory: {e}"))?;
        }

        let path = lease_path(db_path, &id);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|e| {
                anyhow::anyhow!("failed to create session lease {}: {e}", path.display())
            })?;
        file.try_lock().map_err(|e| {
            anyhow::anyhow!("failed to lock new session lease {}: {e}", path.display())
        })?;
        Ok(Self { id, _file: file })
    }

    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    /// Attempts to acquire a lease left by an earlier process. `None`
    /// means either that the file does not exist or another process still
    /// owns the OS lock. Other errors are returned so recovery can leave
    /// the session unknown rather than guessing.
    pub(crate) fn try_recover(db_path: &Path, id: &str) -> anyhow::Result<Option<Self>> {
        if Uuid::parse_str(id).is_err() {
            return Ok(None);
        }
        let path = lease_path(db_path, id);
        let file = match OpenOptions::new().read(true).write(true).open(&path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "failed to open session lease {}: {e}",
                    path.display()
                ));
            }
        };
        match file.try_lock() {
            Ok(()) => Ok(Some(Self {
                id: id.to_string(),
                _file: file,
            })),
            Err(std::fs::TryLockError::WouldBlock) => Ok(None),
            Err(std::fs::TryLockError::Error(e)) => Err(anyhow::anyhow!(
                "failed to test session lease {}: {e}",
                path.display()
            )),
        }
    }
}

fn lease_dir(db_path: &Path) -> PathBuf {
    let mut path = db_path.as_os_str().to_os_string();
    path.push(".leases");
    PathBuf::from(path)
}

fn lease_path(db_path: &Path, id: &str) -> PathBuf {
    lease_dir(db_path).join(format!("{id}.lease"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("auditmcp-lease-{label}-{}.db", Uuid::new_v4()))
    }

    #[test]
    fn a_live_lease_cannot_be_recovered_and_releases_after_drop() {
        let db = db_path("live");
        let lease = SessionLease::create(&db).unwrap();
        assert!(SessionLease::try_recover(&db, lease.id())
            .unwrap()
            .is_none());
        let id = lease.id().to_string();
        drop(lease);
        assert!(SessionLease::try_recover(&db, &id).unwrap().is_some());
        let _ = std::fs::remove_dir_all(lease_dir(&db));
    }

    #[test]
    fn missing_or_invalid_lease_is_not_recovery_evidence() {
        let db = db_path("missing");
        assert!(SessionLease::try_recover(&db, &Uuid::new_v4().to_string())
            .unwrap()
            .is_none());
        assert!(SessionLease::try_recover(&db, "../other")
            .unwrap()
            .is_none());
    }
}
