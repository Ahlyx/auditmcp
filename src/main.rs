mod anchor;
mod anomaly;
mod audit;
mod chain;
mod config;
mod db;
mod export;
mod extract;
mod heartbeat;
mod hex;
mod http;
mod jsonrpc;
mod keys;
mod lease;
mod paths;
mod proxy;
mod query;
mod recovery;
mod reset;
mod secrets;
mod session;
mod shutdown;
mod truncate;
mod unmask;
mod verify;

use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "auditmcp",
    version,
    about = "Local-first audit logging proxy for MCP tool calls"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// The one flag every subcommand shares. Flattened rather than redeclared
/// per variant so the nine copies cannot drift apart (help text, required-
/// ness, or name) -- the codebase's own duplication rule, applied to its
/// own CLI.
#[derive(clap::Args)]
struct ConfigArg {
    /// Optional TOML config. Without it, auditmcp uses per-user state paths
    /// and built-in defaults.
    #[arg(long)]
    config: Option<PathBuf>,
}

impl ConfigArg {
    fn path(&self) -> &Path {
        self.config.as_deref().unwrap_or_else(|| Path::new(""))
    }
}

#[derive(Subcommand)]
enum Command {
    /// Transparently proxy a stdio MCP server, logging every tool call
    Run {
        #[command(flatten)]
        config_args: ConfigArg,
        /// Command to launch the target MCP server, e.g. -- python
        /// server.py. Optional: if omitted, `[target].command` from the
        /// config file is used instead.
        #[arg(trailing_var_arg = true)]
        target: Vec<String>,
    },
    /// Reverse-proxy one or more HTTP MCP servers, logging every tool call.
    /// Binds one loopback port per `[[server]]` in the config; each mirrors
    /// exactly one upstream. Runs until stopped.
    Serve {
        #[command(flatten)]
        config_args: ConfigArg,
    },
    /// Read logged tool calls back in a table format
    Query {
        #[command(flatten)]
        config_args: ConfigArg,
        #[arg(long)]
        tool: Option<String>,
        #[arg(long)]
        session: Option<String>,
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        status: Option<String>,
        /// Show only rows that Phase 3's anomaly rules flagged (i.e. rows
        /// with a non-NULL `anomaly_score`). Each matching row is annotated
        /// with the score and the rule names that fired; --verbose still
        /// controls whether the secrets summary appears.
        #[arg(long)]
        anomalous: bool,
        /// Show a compact per-row secrets-detection summary (pattern,
        /// severity) for rows with redactions. Default output never shows
        /// this -- it stays clean and safe to glance at or paste elsewhere.
        #[arg(long)]
        verbose: bool,
        /// Show synthetic chain rows (`__heartbeat`, `__session_start`,
        /// `__session_end`, `__session_abandoned`, `__audit_gap`), hidden by default since they
        /// are audit plumbing rather than tool-call activity.
        #[arg(long)]
        include_synthetic: bool,
    },
    /// Walk the hash chain and confirm no row was altered or removed.
    /// Exit codes: 0 = clean; 1 = hash-chain tamper/failure; 2 = index
    /// drift or missing/unloadable chain key (chain intact); 3 = heartbeat
    /// gap; 4 = anchor file's internal HMAC chain broken; 5 = anchor
    /// references rows that are missing or hash differently; 6 = durable
    /// audit-gap markers prove calls were dropped.
    Verify {
        #[command(flatten)]
        config_args: ConfigArg,
        /// Rebuild the derived redactions index from redaction_flags (the
        /// source of truth) for drifted rows. Only ever adds/removes rows
        /// in the redactions table -- never touches tool_calls or any
        /// hash. Dry run by default: reports what it would change; add
        /// --yes to apply.
        #[arg(long)]
        repair_index: bool,
        /// Actually apply --repair-index changes (without this, repair is
        /// a dry run that writes nothing).
        #[arg(long)]
        yes: bool,
    },
    /// Dump logged tool calls as JSONL for downstream analysis/compliance
    /// tooling. Read-only; redaction stays exactly as stored -- no
    /// --unmask flag here, ever (see export.rs's module doc for why).
    Export {
        #[command(flatten)]
        config_args: ConfigArg,
        #[arg(long)]
        format: export::ExportFormat,
        #[arg(long)]
        tool: Option<String>,
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        server: Option<String>,
        /// Restrict to rows Phase 3's anomaly rules flagged. Same
        /// contract as `query --anomalous`, kept parallel so the two
        /// commands can never quietly filter to different sets.
        #[arg(long)]
        anomalous: bool,
        /// Write to this file instead of stdout. Written atomically: a
        /// temp file in the same directory is renamed into place only on
        /// success, so an aborted export never leaves a truncated file
        /// that looks complete. Omit to stream JSONL to stdout (composes
        /// with `| jq`, `| gzip`, etc.) -- stdout has no such guarantee on
        /// abort, since the nonzero exit code is the signal there.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Mark a redacted secret's hash as a confirmed false positive, so
    /// future occurrences of that exact value are no longer redacted.
    /// Never recovers plaintext of a past redaction -- none is ever stored.
    /// This is a deliberate, separate write, never a flag on `query`/`export`.
    Unmask {
        #[command(flatten)]
        config_args: ConfigArg,
        /// Full sha256 or an unambiguous prefix of one, as shown by
        /// `query --verbose` (prefix matching works like a git commit hash).
        hash: String,
        /// Why this hash is a confirmed false positive. Required: this is
        /// itself a security decision worth an audit trail, not just a hash.
        #[arg(long)]
        note: String,
    },
    /// Phase 3.5 chain-key operations: inspect or back up the HMAC root
    /// key. No `generate` (happens automatically on first `run`) and no
    /// `rotate`/`import` -- deliberate design decisions, see
    /// `keys.rs`'s module doc.
    Key {
        #[command(subcommand)]
        action: KeyAction,
    },
    /// Destructive: archives (`--keep-old`) or deletes the current
    /// database, chain key, and anchor, then bootstraps a fresh
    /// HMAC-protected chain. The only supported way to migrate a legacy
    /// (pre-Phase-3.5) chain, or to get a new chain key.
    Reset {
        #[command(flatten)]
        config_args: ConfigArg,
        /// Required: `reset` is destructive and refuses to run without it.
        #[arg(long)]
        yes: bool,
        /// Archive the old database/key/anchor with a timestamped
        /// `.reset-bak-<stamp>` suffix instead of deleting them outright.
        #[arg(long)]
        keep_old: bool,
    },
}

#[derive(Subcommand)]
enum KeyAction {
    /// Print the resolved key file path (does not require the key to exist).
    Path {
        #[command(flatten)]
        config_args: ConfigArg,
    },
    /// Print the first 16 hex characters of sha256(root_key) (64 bits,
    /// display-only) -- safe to share out-of-band to confirm two
    /// people/machines are looking at the same key.
    Fingerprint {
        #[command(flatten)]
        config_args: ConfigArg,
    },
    /// Atomically copy the key file to `dest`, with the same restrictive
    /// permissions as the original. Refuses to overwrite an existing file
    /// unless `--force`.
    Backup {
        #[command(flatten)]
        config_args: ConfigArg,
        dest: PathBuf,
        /// Replace `dest` if it already exists. Destroys whatever is
        /// there; if that is another database's key, its chain becomes
        /// permanently unverifiable.
        #[arg(long)]
        force: bool,
    },
}

/// Loads the config and the existing root key it names, for the `key`
/// subcommands that operate on a key that must already exist.
fn load_existing_key(config_path: &Path) -> anyhow::Result<(config::Config, keys::KeyFile)> {
    let cfg = config::Config::load(config_path)?;
    let key_path = cfg.chain.resolved_key_path()?;
    let key = keys::KeyFile::load(&key_path)?.ok_or_else(|| {
        anyhow::anyhow!(
            "no key file at {} (has `auditmcp run` been used yet?)",
            key_path.display()
        )
    })?;
    Ok((cfg, key))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Default to `warn`, not to silence. Every fail-open path in this
    // codebase reports by warning and continuing -- entries dropped, index
    // drift, a pipe error -- and with `EnvFilter::from_default_env()` alone
    // an unset RUST_LOG enables nothing, so all of it went to nowhere. A
    // tool whose job is a complete record must not be quiet about the ways
    // that record can be incomplete. RUST_LOG still overrides, in both
    // directions.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Run {
            config_args,
            target,
        } => proxy::run(config_args.path(), target).await,
        Command::Serve { config_args } => http::serve(config_args.path()).await,
        Command::Query {
            config_args,
            tool,
            session,
            since,
            status,
            anomalous,
            verbose,
            include_synthetic,
        } => query::run(
            config_args.path(),
            tool,
            session,
            since,
            status,
            anomalous,
            verbose,
            include_synthetic,
        ),
        Command::Verify {
            config_args,
            repair_index,
            yes,
        } => {
            // The only place a verify outcome ends the process, so the
            // exit-code policy itself stays testable in `verify::tests`.
            // `Clean` returns normally rather than exiting, keeping the
            // ordinary success path identical to every other subcommand's.
            let outcome = verify::run(config_args.path(), repair_index, yes)?;
            if outcome != verify::VerifyOutcome::Clean {
                std::process::exit(outcome.exit_code());
            }
            Ok(())
        }
        Command::Export {
            config_args,
            format,
            tool,
            since,
            status,
            server,
            anomalous,
            output,
        } => export::run(
            config_args.path(),
            format,
            tool,
            since,
            status,
            server,
            anomalous,
            output,
        ),
        Command::Unmask {
            config_args,
            hash,
            note,
        } => unmask::run(config_args.path(), &hash, &note),
        Command::Key { action } => match action {
            KeyAction::Path { config_args } => {
                let cfg = config::Config::load(config_args.path())?;
                println!("{}", cfg.chain.resolved_key_path()?.display());
                Ok(())
            }
            KeyAction::Fingerprint { config_args } => {
                let (_cfg, key) = load_existing_key(config_args.path())?;
                println!("{}", key.fingerprint()?);
                Ok(())
            }
            KeyAction::Backup {
                config_args,
                dest,
                force,
            } => {
                let (_cfg, key) = load_existing_key(config_args.path())?;
                key.backup(&dest, force)?;
                println!("Key backed up to {}", dest.display());
                Ok(())
            }
        },
        Command::Reset {
            config_args,
            yes,
            keep_old,
        } => reset::run(config_args.path(), yes, keep_old),
    }
}
