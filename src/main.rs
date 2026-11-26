use std::process::ExitCode;

use clap::Parser;
use dbvalet::cli::{self, Cli};
use dbvalet::signals;

fn main() -> anyhow::Result<ExitCode> {
    signals::maybe_exec_with_pdeathsig();
    signals::enable_pdeathsig_shim();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    Ok(runtime.block_on(cli::run(Cli::parse()))?)
}
