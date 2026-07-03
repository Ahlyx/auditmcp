mod config;
mod db;
mod jsonrpc;
mod proxy;
mod query;
mod verify;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "auditmcp", version, about = "Local-first audit logging proxy for MCP tool calls")]
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
        /// Command to launch the target MCP server, e.g. -- python server.py
        #[arg(trailing_var_arg = true, required = true)]
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
    },
    /// Walk the hash chain and confirm no row was altered or removed
    Verify {
        #[arg(long)]
        config: PathBuf,
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
        Command::Query { config, tool, session, since, status } => {
            query::run(&config, tool, session, since, status)
        }
        Command::Verify { config } => verify::run(&config),
    }
}
