mod cli;
mod dfilter;
mod dissect;
mod field;
mod pcap;
mod pcapng;
mod pipeline;
mod print;
mod roce;

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
