use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub target: TargetConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Deserialize)]
pub struct TargetConfig {
    /// Kept for config-file completeness; `run` currently takes the target
    /// command from CLI trailing args instead. Reserved for a future
    /// `auditmcp run --config config.toml` (no trailing command) mode.
    #[serde(default)]
    pub command: Vec<String>,
    /// Logged into every row's `server_name` column. Optional; falls back
    /// to the target command's program name. Setting it explicitly matters
    /// most when several servers share one db_path: most MCP servers launch
    /// via the same interpreter (`npx`, `python`, `node`, ...), so the
    /// program-name fallback would make rows from different servers
    /// indistinguishable in a shared DB.
    pub server_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LoggingConfig {
    pub db_path: String,
    #[serde(default = "default_tier")]
    pub default_tier: Tier,
    #[serde(default)]
    pub tool_overrides: HashMap<String, Tier>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    Minimal,
    Standard,
    Full,
}

fn default_tier() -> Tier {
    Tier::Minimal
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("failed to read config file {}: {e}", path.display()))?;
        let config: Config = toml::from_str(&raw)
            .map_err(|e| anyhow::anyhow!("failed to parse config file {}: {e}", path.display()))?;
        Ok(config)
    }

    pub fn tier_for_tool(&self, tool_name: &str) -> Tier {
        self.logging
            .tool_overrides
            .get(tool_name)
            .copied()
            .unwrap_or(self.logging.default_tier)
    }

    /// The name logged into every row's `server_name` column: the config's
    /// `[target].server_name` if set, else the target command's program
    /// name — the pre-Phase-2 behavior, which configs written before the
    /// field existed must keep getting unchanged.
    pub fn server_name_for(&self, program: &str) -> String {
        self.target
            .server_name
            .clone()
            .unwrap_or_else(|| program.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL_TOML: &str = r#"
[target]
command = ["python", "server.py"]

[logging]
db_path = "./test.db"
"#;

    /// Backward compatibility: a config written before `server_name`
    /// existed (the field absent entirely) must still parse, and must fall
    /// back to the old behavior — server_name = the target command's
    /// program name.
    #[test]
    fn config_without_server_name_falls_back_to_program_name() {
        let config: Config = toml::from_str(MINIMAL_TOML).unwrap();
        assert_eq!(config.target.server_name, None);
        assert_eq!(config.server_name_for("python"), "python");
    }

    #[test]
    fn explicit_server_name_overrides_program_name() {
        let raw = r#"
[target]
command = ["python", "server.py"]
server_name = "vault_reader"

[logging]
db_path = "./test.db"
"#;
        let config: Config = toml::from_str(raw).unwrap();
        assert_eq!(config.server_name_for("python"), "vault_reader");
    }
}
