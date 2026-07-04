use std::io::{BufWriter, Write};

use anyhow::Result;
use rayon::prelude::*;

use crate::cli::{Args, OutputMode};
use crate::dissect::{self, Dissection};
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

    let mut reader = CaptureReader::open(&args.read_file)?;

    let stdout = std::io::stdout();
    let mut out = BufWriter::with_capacity(1 << 20, stdout.lock());

    let mut reference: Option<(u32, u32)> = None;
    let mut frame_number: u64 = 0;
    let max = args.count.unwrap_or(u64::MAX);
    let batch_cap = args.batch.max(1);

    let mut batch: Vec<(FrameMeta, RawPacket)> = Vec::with_capacity(batch_cap);

    while frame_number < max {
        let take_now = batch_cap.min((max - frame_number) as usize);
        fill_batch(&mut reader, &mut batch, take_now, &mut reference, &mut frame_number)?;
        if batch.is_empty() {
            break;
        }

        flush_batch(&mut out, &mut batch, args)?;
    }

    out.flush()?;
    Ok(())
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

fn flush_batch<W: Write>(
    out: &mut W,
    batch: &mut Vec<(FrameMeta, RawPacket)>,
    args: &Args,
) -> Result<()> {
    // Dissect. Parallelism here is safe because `dissect::dissect` is pure
    // over a single packet. The batch is an owned `Vec`, so `par_iter` hands
    // each worker a slice of it with no aliasing.
    let results: Vec<Dissection> = if args.no_parallel {
        batch.iter().map(|(_, p)| dissect::dissect(p)).collect()
    } else {
        batch
            .par_iter()
            .map(|(_, p)| dissect::dissect(p))
            .collect()
    };

    // Print in original order. `results` is index-aligned with `batch`.
    if args.quiet {
        batch.clear();
        return Ok(());
    }

    let mode = args.output_mode();
    for (i, d) in results.into_iter().enumerate() {
        let (meta, pkt) = &batch[i];
        match mode {
            OutputMode::Summary => {
                writeln!(out, "{}", format_line(*meta, &d.summary))?;
            }
            OutputMode::Verbose => {
                // Frame pseudo-protocol node, then each dissected layer.
                let mut nodes = Vec::with_capacity(d.tree.len() + 1);
                nodes.push(frame_node(*meta, pkt.orig_len, pkt.data.len()));
                nodes.extend(d.tree);
                field::write_verbose(out, &nodes)?;
                writeln!(out)?; // blank line between packets
            }
            OutputMode::Fields => {
                // Frame fields are addressable too (frame.number, ...).
                let mut nodes = Vec::with_capacity(d.tree.len() + 1);
                nodes.push(frame_node(*meta, pkt.orig_len, pkt.data.len()));
                nodes.extend(d.tree);
                writeln!(out, "{}", format_fields(&nodes, &args.fields))?;
            }
        }
    }
    batch.clear();
    Ok(())
}
