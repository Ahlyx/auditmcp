use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct Config {
    /// Used by `run` (stdio). Optional so a config that only describes HTTP
    /// servers doesn't have to carry an empty `[target]` section purely to
    /// satisfy the parser — a section that exists only to be ignored is
    /// noise that reads like a requirement.
    #[serde(default)]
    pub target: TargetConfig,
    /// Used by `serve` (HTTP). One entry per upstream, each getting its own
    /// loopback port. Optional so existing stdio-only configs keep parsing
    /// exactly as they did.
    #[serde(default)]
    pub server: Vec<ServerConfig>,
    pub logging: LoggingConfig,
}

#[derive(Debug, Default, Deserialize)]
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

/// One HTTP upstream and the loopback port that mirrors it.
///
/// Each listener is an origin-level mirror of exactly one upstream: every
/// path and method is forwarded unchanged. That is deliberate rather than
/// path-prefix routing under a single port, because OAuth discovery derives
/// `.well-known/oauth-protected-resource` from the URL the client is
/// talking to — a path transform there would mean a second place where the
/// proxy rewrites traffic, and one deliberate break of transparency (the
/// legacy `endpoint` event) is the limit.
#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    /// Recorded in every row's `server_name`. Must be unique: two servers
    /// sharing a name would make their rows indistinguishable in the log,
    /// which is the exact confusion `server_name` exists to prevent.
    pub name: String,
    /// Upstream MCP server origin, e.g. `https://mcp.example.com/mcp`.
    pub upstream: String,
    /// Loopback address to bind. Required rather than defaulted, so two
    /// servers can never silently collide on one port. The documented
    /// convention is to start at 8787 and count upward.
    pub listen: String,
    /// Origins accepted on inbound requests. Defaults to loopback only.
    #[serde(default)]
    pub allowed_origins: Option<Vec<String>>,
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
        config
            .validate_servers()
            .map_err(|e| anyhow::anyhow!("invalid config file {}: {e}", path.display()))?;
        Ok(config)
    }

    /// Checks every `[[server]]` before anything binds or proxies.
    ///
    /// All of these are startup errors rather than runtime surprises: a
    /// duplicate name silently merges two servers' rows, a duplicate port
    /// fails on the second bind after the first is already serving, and a
    /// non-loopback bind turns a single-user audit tool into an
    /// unauthenticated open proxy to someone's MCP servers.
    fn validate_servers(&self) -> Result<(), String> {
        let mut names = HashSet::new();
        let mut addrs = HashSet::new();

        for s in &self.server {
            if s.name.trim().is_empty() {
                return Err("a [[server]] has an empty name".to_string());
            }
            if !names.insert(s.name.as_str()) {
                return Err(format!(
                    "two [[server]] entries are both named '{}'; their rows would be \
                     indistinguishable in the log",
                    s.name
                ));
            }

            let addr = s.socket_addr()?;
            if !addr.ip().is_loopback() {
                return Err(format!(
                    "[[server]] '{}' listens on {}, which is not a loopback address. \
                     auditmcp has no authentication, so binding beyond localhost would \
                     expose your MCP servers to anything that can reach this host.",
                    s.name, addr
                ));
            }
            if !addrs.insert(addr) {
                return Err(format!(
                    "[[server]] '{}' reuses listen address {}; each server needs its own port",
                    s.name, addr
                ));
            }

            s.upstream_uri()?;
        }
        Ok(())
    }

    /// The validated HTTP servers, for `serve`. Empty is an error here
    /// rather than a process that binds nothing and looks healthy.
    pub fn http_servers(&self) -> anyhow::Result<&[ServerConfig]> {
        if self.server.is_empty() {
            return Err(anyhow::anyhow!(
                "no [[server]] entries in the config: `serve` needs at least one \
                 upstream to mirror. (Proxying a stdio server is `auditmcp run`.)"
            ));
        }
        Ok(&self.server)
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

impl ServerConfig {
    pub fn socket_addr(&self) -> Result<SocketAddr, String> {
        self.listen.parse::<SocketAddr>().map_err(|e| {
            format!(
                "[[server]] '{}' has an unparseable listen address '{}': {e} \
                 (expected e.g. \"127.0.0.1:8787\")",
                self.name, self.listen
            )
        })
    }

    /// The upstream as a URI, checked for the parts the proxy actually
    /// needs: a scheme it can speak and a host to connect to.
    pub fn upstream_uri(&self) -> Result<http::Uri, String> {
        let uri: http::Uri = self.upstream.parse().map_err(|e| {
            format!(
                "[[server]] '{}' has an unparseable upstream '{}': {e}",
                self.name, self.upstream
            )
        })?;
        match uri.scheme_str() {
            Some("http") | Some("https") => {}
            other => {
                return Err(format!(
                    "[[server]] '{}' upstream '{}' has scheme {:?}; expected http or https",
                    self.name, self.upstream, other
                ))
            }
        }
        if uri.authority().is_none() {
            return Err(format!(
                "[[server]] '{}' upstream '{}' has no host",
                self.name, self.upstream
            ));
        }
        Ok(uri)
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

    fn servers_toml(body: &str) -> Result<Config, String> {
        let cfg: Config =
            toml::from_str(&format!("{body}\n[logging]\ndb_path = './t.db'\n")).unwrap();
        cfg.validate_servers()?;
        Ok(cfg)
    }

    /// A config that only describes HTTP servers must not need an empty
    /// `[target]` section to satisfy the parser.
    #[test]
    fn config_without_target_section_parses() {
        let cfg = servers_toml(
            "[[server]]\nname='a'\nupstream='http://x.test/mcp'\nlisten='127.0.0.1:8787'",
        )
        .unwrap();
        assert!(cfg.target.command.is_empty());
        assert_eq!(cfg.server.len(), 1);
    }

    /// And a config written before `[[server]]` existed keeps working.
    #[test]
    fn stdio_only_config_still_parses_and_has_no_servers() {
        let cfg: Config = toml::from_str(MINIMAL_TOML).unwrap();
        cfg.validate_servers().unwrap();
        assert!(cfg.server.is_empty());
        assert!(
            cfg.http_servers().is_err(),
            "serve needs at least one server"
        );
    }

    #[test]
    fn duplicate_server_names_are_rejected() {
        let err = servers_toml(
            "[[server]]\nname='dup'\nupstream='http://a.test'\nlisten='127.0.0.1:8787'\n\
             [[server]]\nname='dup'\nupstream='http://b.test'\nlisten='127.0.0.1:8788'",
        )
        .unwrap_err();
        assert!(err.contains("both named 'dup'"), "{err}");
    }

    #[test]
    fn duplicate_listen_addresses_are_rejected() {
        let err = servers_toml(
            "[[server]]\nname='a'\nupstream='http://a.test'\nlisten='127.0.0.1:8787'\n\
             [[server]]\nname='b'\nupstream='http://b.test'\nlisten='127.0.0.1:8787'",
        )
        .unwrap_err();
        assert!(err.contains("reuses listen address"), "{err}");
    }

    /// auditmcp has no authentication, so a non-loopback bind would be an
    /// open proxy to the user's MCP servers.
    #[test]
    fn non_loopback_listen_addresses_are_refused() {
        for addr in ["0.0.0.0:8787", "192.168.1.10:8787", "[::]:8787"] {
            let err = servers_toml(&format!(
                "[[server]]\nname='a'\nupstream='http://a.test'\nlisten='{addr}'"
            ))
            .unwrap_err();
            assert!(err.contains("not a loopback address"), "{addr}: {err}");
        }
    }

    /// Both schemes are usable: https for remote servers, http because an
    /// upstream on loopback in cleartext is a normal local setup.
    #[test]
    fn http_and_https_upstreams_are_both_accepted() {
        for upstream in ["http://a.test/mcp", "https://a.test/mcp"] {
            servers_toml(&format!(
                "[[server]]\nname='a'\nupstream='{upstream}'\nlisten='127.0.0.1:8787'"
            ))
            .unwrap_or_else(|e| panic!("{upstream} should be accepted: {e}"));
        }
    }

    #[test]
    fn loopback_listen_addresses_are_accepted() {
        for addr in ["127.0.0.1:8787", "[::1]:8787", "127.0.0.2:9000"] {
            servers_toml(&format!(
                "[[server]]\nname='a'\nupstream='http://a.test'\nlisten='{addr}'"
            ))
            .unwrap_or_else(|e| panic!("{addr} should be accepted: {e}"));
        }
    }

    #[test]
    fn unusable_upstreams_are_rejected_with_a_reason() {
        let cases = [
            ("not a url", "unparseable"),
            ("ftp://a.test", "expected http"),
            ("/just/a/path", "expected http"),
        ];
        for (upstream, expected) in cases {
            let err = servers_toml(&format!(
                "[[server]]\nname='a'\nupstream='{upstream}'\nlisten='127.0.0.1:8787'"
            ))
            .unwrap_err();
            assert!(err.contains(expected), "{upstream}: got {err}");
        }
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
