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
    /// Target MCP server command. Used when `auditmcp run` is invoked with
    /// no trailing `-- <command...>`; trailing args, when present, take
    /// precedence (see `Config::resolve_target`). Optional so a config can
    /// rely entirely on trailing args.
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

    /// Resolves which command to launch as the target MCP server.
    ///
    /// CLI trailing args win when given, so an explicit
    /// `-- python server.py` always overrides whatever the config says and
    /// the pre-existing invocation style keeps working unchanged. Falling
    /// back to `[target].command` is what makes a bare
    /// `auditmcp run --config config.toml` work. An empty result from both
    /// is an error rather than a silent no-op: there is nothing to proxy.
    pub fn resolve_target(&self, cli_target: Vec<String>) -> anyhow::Result<Vec<String>> {
        if !cli_target.is_empty() {
            return Ok(cli_target);
        }
        if !self.target.command.is_empty() {
            return Ok(self.target.command.clone());
        }
        Err(anyhow::anyhow!(
            "no target command: pass one after `--` (e.g. `-- python server.py`) \
             or set [target].command in the config file"
        ))
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
    fn cli_trailing_args_win_over_config_command() {
        let config: Config = toml::from_str(MINIMAL_TOML).unwrap();
        let resolved = config
            .resolve_target(vec!["node".into(), "other.js".into()])
            .unwrap();
        assert_eq!(resolved, vec!["node", "other.js"]);
    }

    #[test]
    fn config_command_used_when_no_trailing_args() {
        let config: Config = toml::from_str(MINIMAL_TOML).unwrap();
        let resolved = config.resolve_target(vec![]).unwrap();
        assert_eq!(resolved, vec!["python", "server.py"]);
    }

    /// Both sources empty is a hard error, not a silent no-op: there would
    /// be no server to proxy and nothing to audit.
    #[test]
    fn no_target_anywhere_is_an_error() {
        let raw = r#"
[target]

[logging]
db_path = "./test.db"
"#;
        let config: Config = toml::from_str(raw).unwrap();
        assert!(config.resolve_target(vec![]).is_err());
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
