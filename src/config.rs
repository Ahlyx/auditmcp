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
}
