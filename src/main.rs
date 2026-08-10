mod audit;
mod config;
mod db;
mod export;
mod jsonrpc;
mod proxy;
mod query;
mod secrets;
mod session;
mod truncate;
mod unmask;
mod verify;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

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

#[derive(Subcommand)]
enum Command {
    /// Transparently proxy a stdio MCP server, logging every tool call
    Run {
        #[arg(long)]
        config: PathBuf,
        /// Command to launch the target MCP server, e.g. -- python
        /// server.py. Optional: if omitted, `[target].command` from the
        /// config file is used instead.
        #[arg(trailing_var_arg = true)]
        target: Vec<String>,
    },
    /// Read logged tool calls back in a table format
    Query {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        tool: Option<String>,
        #[arg(long)]
        session: Option<String>,
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        status: Option<String>,
        /// Show a compact per-row secrets-detection summary (pattern,
        /// severity) for rows with redactions. Default output never shows
        /// this -- it stays clean and safe to glance at or paste elsewhere.
        #[arg(long)]
        verbose: bool,
    },
    /// Walk the hash chain and confirm no row was altered or removed.
    /// Exit codes: 0 = clean, 1 = hash-chain tamper/failure,
    /// 2 = redactions-index drift only (chain intact).
    Verify {
        #[arg(long)]
        config: PathBuf,
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
        #[arg(long)]
        config: PathBuf,
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
        #[arg(long)]
        config: PathBuf,
        /// Full sha256 or an unambiguous prefix of one, as shown by
        /// `query --verbose` (prefix matching works like a git commit hash).
        hash: String,
        /// Why this hash is a confirmed false positive. Required: this is
        /// itself a security decision worth an audit trail, not just a hash.
        #[arg(long)]
        note: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Run { config, target } => proxy::run(&config, target).await,
        Command::Query {
            config,
            tool,
            session,
            since,
            status,
            verbose,
        } => query::run(&config, tool, session, since, status, verbose),
        Command::Verify {
            config,
            repair_index,
            yes,
        } => {
            // The only place a verify outcome ends the process, so the
            // exit-code policy itself stays testable in `verify::tests`.
            // `Clean` returns normally rather than exiting, keeping the
            // ordinary success path identical to every other subcommand's.
            let outcome = verify::run(&config, repair_index, yes)?;
            if outcome != verify::VerifyOutcome::Clean {
                std::process::exit(outcome.exit_code());
            }
            Ok(())
        }
        Command::Export {
            config,
            format,
            tool,
            since,
            status,
            server,
            output,
        } => export::run(&config, format, tool, since, status, server, output),
        Command::Unmask { config, hash, note } => unmask::run(&config, &hash, &note),
    }
}
