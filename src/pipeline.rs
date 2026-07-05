use std::io::{BufWriter, Write};

use anyhow::{Result, anyhow, bail};
use rayon::prelude::*;

use crate::analysis::{self, Rec};
use crate::cli::{Args, OutputMode};
use crate::dfilter::Filter;
use crate::dissect::{self, Dissection, DissectConfig};
use crate::field;
use crate::pcap::{CaptureReader, RawPacket};
use crate::print::{FrameMeta, column, format_fields, format_line, frame_node};

pub fn run(args: &Args) -> Result<()> {
    if args.jobs > 0 {
        // Build a pool with the requested thread count. Ignored if already
        // initialised by someone else in-process.
        let _ = rayon::ThreadPoolBuilder::new()
            .num_threads(args.jobs)
            .build_global();
    }

    // Compile the display filter once up front so a syntax error fails
    // before we read any packets.
    let filter = match &args.display_filter {
        Some(src) => Some(
            Filter::compile(src).map_err(|e| anyhow!("invalid display filter: {e}"))?,
        ),
        None => None,
    };

    // Which statistics report, if any, to accumulate.
    let stat = match args.statistics.as_deref() {
        None => None,
        Some("roce,psn") | Some("roce-psn") | Some("rdma,psn") => Some(StatKind::Psn),
        Some("roce,cong") | Some("roce-cong") | Some("rdma,cong") => Some(StatKind::Cong),
        Some(other) => bail!(
            "unknown -z statistics spec {other:?}; supported: roce,psn | roce,cong"
        ),
    };
    let analyze = stat.is_some();

    let cfg = DissectConfig {
        nvme_force: args.nvme,
    };

    let mut reader = CaptureReader::open(&args.read_file)?;

    let stdout = std::io::stdout();
    let mut out = BufWriter::with_capacity(1 << 20, stdout.lock());

    let mut reference: Option<(u32, u32)> = None;
    let mut frame_number: u64 = 0;
    let max = args.count.unwrap_or(u64::MAX);
    let batch_cap = args.batch.max(1);

    let mut batch: Vec<(FrameMeta, RawPacket)> = Vec::with_capacity(batch_cap);
    // PSN-analysis records, accumulated in capture order across batches.
    let mut records: Vec<Rec> = Vec::new();

    while frame_number < max {
        let take_now = batch_cap.min((max - frame_number) as usize);
        fill_batch(&mut reader, &mut batch, take_now, &mut reference, &mut frame_number)?;
        if batch.is_empty() {
            break;
        }

        flush_batch(
            &mut out,
            &mut batch,
            args,
            filter.as_ref(),
            analyze,
            &mut records,
            &cfg,
        )?;
    }

    match stat {
        Some(StatKind::Psn) => write!(out, "{}", analysis::analyze_psn(&records))?,
        Some(StatKind::Cong) => write!(out, "{}", analysis::analyze_cong(&records))?,
        None => {}
    }

    out.flush()?;
    Ok(())
}

/// Which `-z` statistics report was requested.
#[derive(Debug, Clone, Copy)]
enum StatKind {
    Psn,
    Cong,
}

fn fill_batch<R: std::io::Read>(
    reader: &mut CaptureReader<R>,
    batch: &mut Vec<(FrameMeta, RawPacket)>,
    cap: usize,
    reference: &mut Option<(u32, u32)>,
    frame_number: &mut u64,
) -> Result<()> {
    batch.clear();
    while batch.len() < cap {
        match reader.next_packet()? {
            Some(pkt) => {
                *frame_number += 1;
                let (ref_sec, ref_nsec) = *reference
                    .get_or_insert((pkt.ts_sec, pkt.ts_nsec));
                let rel = column::rel_time(pkt.ts_sec, pkt.ts_nsec, ref_sec, ref_nsec);
                batch.push((column::meta(*frame_number, rel), pkt));
            }
            None => break,
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn flush_batch<W: Write>(
    out: &mut W,
    batch: &mut Vec<(FrameMeta, RawPacket)>,
    args: &Args,
    filter: Option<&Filter>,
    analyze: bool,
    records: &mut Vec<Rec>,
    cfg: &DissectConfig,
) -> Result<()> {
    // Dissect. Parallelism here is safe because `dissect::dissect` is pure
    // over a single packet. The batch is an owned `Vec`, so `par_iter` hands
    // each worker a slice of it with no aliasing.
    let results: Vec<Dissection> = if args.no_parallel {
        batch.iter().map(|(_, p)| dissect::dissect(p, cfg)).collect()
    } else {
        batch
            .par_iter()
            .map(|(_, p)| dissect::dissect(p, cfg))
            .collect()
    };

    // Fast path: nothing to print and no analysis to accumulate.
    if args.quiet && !analyze {
        batch.clear();
        return Ok(());
    }

    let mode = args.output_mode();
    for (i, d) in results.into_iter().enumerate() {
        let (meta, pkt) = &batch[i];
        let Dissection { summary, tree } = d;

        // Analysis sees every packet read, independent of the display
        // filter, so drops aren't hidden by a narrowing -Y.
        if analyze {
            if let Some(r) = analysis::record(meta.number, &summary.dst, &tree) {
                records.push(r);
            }
        }

        if args.quiet {
            continue;
        }

        // The searchable node set is needed when filtering, in verbose or
        // field mode, and includes a synthesised Frame node so that
        // `frame.*` fields are both filterable and extractable.
        if filter.is_some() || mode != OutputMode::Summary {
            let mut nodes = Vec::with_capacity(tree.len() + 1);
            nodes.push(frame_node(*meta, pkt.orig_len, pkt.data.len()));
            nodes.extend(tree);

            if let Some(f) = filter {
                if !f.matches(&nodes) {
                    continue;
                }
            }
            match mode {
                OutputMode::Summary => writeln!(out, "{}", format_line(*meta, &summary))?,
                OutputMode::Verbose => {
                    field::write_verbose(out, &nodes)?;
                    writeln!(out)?; // blank line between packets
                }
                OutputMode::Fields => {
                    writeln!(out, "{}", format_fields(&nodes, &args.fields))?
                }
            }
        } else {
            writeln!(out, "{}", format_line(*meta, &summary))?;
        }
    }
    batch.clear();
    Ok(())
}
