use std::process::ExitCode;

use clap::Parser;
use dbvalet::cli::{self, Cli};

fn main() -> anyhow::Result<ExitCode> {
    // Keep the single-threaded runtime so child spawns stay on the main thread; Linux
    // delivers PR_SET_PDEATHSIG when the spawning thread exits, not when the process does.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    Ok(runtime.block_on(cli::run(Cli::parse()))?)
}
