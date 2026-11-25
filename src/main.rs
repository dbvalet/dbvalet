use std::process::ExitCode;

use clap::Parser;
use dbvalet::cli::{self, Cli};

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<ExitCode> {
    Ok(cli::run(Cli::parse()).await?)
}
