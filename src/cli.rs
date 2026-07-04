use clap::Parser;

/// Parallel tshark-style pcap dissector.
///
/// A lightweight Rust port of tshark focused on reading capture files and
/// printing per-packet summary lines. Dissection is parallelised across
/// worker threads; output order matches the input capture order.
#[derive(Parser, Debug)]
#[command(name = "rshark", version, about, long_about = None)]
pub struct Args {
    /// Read packets from this capture file (use "-" for stdin).
    #[arg(short = 'r', long = "read-file", value_name = "FILE")]
    pub read_file: String,

    /// Stop after N packets.
    #[arg(short = 'c', value_name = "COUNT")]
    pub count: Option<u64>,

    /// Number of worker threads for dissection (0 = rayon default).
    #[arg(short = 'j', long = "jobs", value_name = "N", default_value_t = 0)]
    pub jobs: usize,

    /// Packets per parallel batch.
    #[arg(long = "batch", value_name = "N", default_value_t = 4096)]
    pub batch: usize,

    /// Disable parallel dissection (single-threaded, for comparison).
    #[arg(long = "no-parallel")]
    pub no_parallel: bool,

    /// Be quiet: suppress per-packet output (useful for benchmarking).
    #[arg(short = 'q', long = "quiet")]
    pub quiet: bool,

    /// Verbose: print the full protocol detail tree for each packet
    /// (like tshark -V) instead of the one-line summary.
    #[arg(short = 'V', long = "verbose")]
    pub verbose: bool,

    /// Print only the value of this field for each packet (like
    /// tshark -e). Repeatable; values are tab-separated in the order
    /// given. Implies field output (overrides -V). Example:
    /// `-e infiniband.bth.psn -e infiniband.bth.destqp`.
    #[arg(short = 'e', long = "field", value_name = "FIELD")]
    pub fields: Vec<String>,

    /// Display filter (like tshark -Y): only packets matching the
    /// expression are printed. Supports ==, !=, <, <=, >, >= (and the
    /// eq/ne/lt/le/gt/ge aliases), &&/||/! (and/or/not), parentheses,
    /// and bare field/protocol existence tests. Example:
    /// `-Y 'infiniband.bth.destqp == 0x123 && ip.dsfield.ecn == 3'`.
    #[arg(short = 'Y', long = "display-filter", value_name = "FILTER")]
    pub display_filter: Option<String>,

    /// Collect a statistics report (like tshark -z), printed after the
    /// packet listing. Supported specs:
    ///   `roce,psn`  — per-QP PSN analysis (drops, reordering, retransmits);
    ///   `roce,cong` — per-QP congestion (ECN CE-marked packets and CNPs).
    /// Analysis covers all packets read, independent of any -Y filter.
    #[arg(short = 'z', long = "statistics", value_name = "SPEC")]
    pub statistics: Option<String>,
}

/// How each packet should be rendered, derived from the flags above.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    Summary,
    Verbose,
    Fields,
}

impl Args {
    pub fn output_mode(&self) -> OutputMode {
        if !self.fields.is_empty() {
            OutputMode::Fields
        } else if self.verbose {
            OutputMode::Verbose
        } else {
            OutputMode::Summary
        }
    }
}
