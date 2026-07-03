//! `auditmcp verify` — walk the hash chain from the beginning and confirm
//! no row was altered or removed; report the first broken link if any.

use crate::config::Config;
use crate::db;
use std::path::Path;

pub fn run(config_path: &Path) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;
    let conn = db::open_readonly(Path::new(&config.logging.db_path))?;

    match db::verify_chain(&conn)? {
        Ok(count) => {
            println!("OK: {count} row(s) verified, hash chain intact.");
            Ok(())
        }
        Err(issue) => {
            eprintln!("FAILED: {issue}");
            // Nonzero exit so this is scriptable (CI, cron, etc.) without
            // the caller having to parse stdout to know the chain broke.
            std::process::exit(1);
        }
    }
}
