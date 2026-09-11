//! Deterministic per-user state paths.
//!
//! Configless operation uses the platform's normal state directory. Explicit
//! database paths still get separate default key and anchor files, identified
//! by a short hash of the resolved database path. That keeps two independent
//! audit databases from sharing reset-sensitive state or contaminating each
//! other's anchor chain.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub fn state_dir() -> anyhow::Result<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        let base = std::env::var_os("LOCALAPPDATA").ok_or_else(|| {
            anyhow::anyhow!("%LOCALAPPDATA% is not set; cannot resolve auditmcp state directory")
        })?;
        Ok(PathBuf::from(base).join("auditmcp"))
    }
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var_os("HOME").ok_or_else(|| {
            anyhow::anyhow!("$HOME is not set; cannot resolve auditmcp state directory")
        })?;
        Ok(PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("auditmcp"))
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(xdg) = std::env::var_os("XDG_STATE_HOME") {
            return Ok(PathBuf::from(xdg).join("auditmcp"));
        }
        let home = std::env::var_os("HOME").ok_or_else(|| {
            anyhow::anyhow!("$HOME is not set; cannot resolve auditmcp state directory")
        })?;
        Ok(PathBuf::from(home)
            .join(".local")
            .join("state")
            .join("auditmcp"))
    }
}

pub fn default_db_path() -> anyhow::Result<PathBuf> {
    Ok(state_dir()?.join("audit.db"))
}

pub fn default_key_path(db_path: &Path) -> anyhow::Result<PathBuf> {
    Ok(state_dir()?
        .join("keys")
        .join(format!("{}.key", database_path_id(db_path)?)))
}

pub fn default_anchor_path(db_path: &Path) -> anyhow::Result<PathBuf> {
    Ok(state_dir()?
        .join("anchors")
        .join(format!("{}.log", database_path_id(db_path)?)))
}

/// Expands `~`, then resolves a relative config path against the directory
/// containing that config. Configless defaults are already absolute.
pub fn resolve_config_path(raw: &str, config_dir: &Path) -> anyhow::Result<PathBuf> {
    let expanded = crate::keys::expand_tilde(raw)?;
    let resolved = if expanded.is_absolute() {
        expanded
    } else {
        config_dir.join(expanded)
    };
    Ok(std::path::absolute(resolved)?)
}

fn database_path_id(db_path: &Path) -> anyhow::Result<String> {
    let absolute = std::path::absolute(db_path)?;
    let identity = absolute.to_string_lossy().into_owned();
    #[cfg(windows)]
    let identity = identity.to_ascii_lowercase();
    let digest = Sha256::digest(identity.as_bytes());
    Ok(crate::hex::hex_encode(&digest)[..16].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separate_databases_get_separate_keys_and_anchors() {
        let base = std::env::temp_dir().join("auditmcp-path-test");
        let a = base.join("a.db");
        let b = base.join("b.db");
        assert_ne!(default_key_path(&a).unwrap(), default_key_path(&b).unwrap());
        assert_ne!(
            default_anchor_path(&a).unwrap(),
            default_anchor_path(&b).unwrap()
        );
    }

    #[test]
    fn relative_paths_are_based_at_the_config_directory() {
        let base = std::env::temp_dir().join("auditmcp-config-base");
        assert_eq!(
            resolve_config_path("data/audit.db", &base).unwrap(),
            base.join("data/audit.db")
        );
    }
}
