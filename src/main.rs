mod cli;
mod dissect;
mod pcap;
mod pipeline;
mod print;

use std::process::ExitCode;

use clap::Parser;

fn main() -> ExitCode {
    let args = cli::Args::parse();
    match pipeline::run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("rshark: {e:#}");
            ExitCode::from(2)
        }
    }
}
