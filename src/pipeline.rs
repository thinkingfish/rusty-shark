use std::io::{BufWriter, Write};

use anyhow::Result;
use rayon::prelude::*;

use crate::cli::Args;
use crate::dissect::{self, Summary};
use crate::pcap::{LinkType, PcapReader, RawPacket};
use crate::print::{FrameMeta, column, format_line};

pub fn run(args: &Args) -> Result<()> {
    if args.jobs > 0 {
        // Build a pool with the requested thread count. Ignored if already
        // initialised by someone else in-process.
        let _ = rayon::ThreadPoolBuilder::new()
            .num_threads(args.jobs)
            .build_global();
    }

    let mut reader = PcapReader::open(&args.read_file)?;
    let link = reader.link_type();

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

        flush_batch(&mut out, link, &mut batch, args)?;
    }

    out.flush()?;
    Ok(())
}

fn fill_batch<R: std::io::Read>(
    reader: &mut PcapReader<R>,
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
    link: LinkType,
    batch: &mut Vec<(FrameMeta, RawPacket)>,
    args: &Args,
) -> Result<()> {
    // Dissect. Parallelism here is safe because `dissect::dissect` is pure
    // over a single packet. The batch is an owned `Vec`, so `par_iter` hands
    // each worker a slice of it with no aliasing.
    let summaries: Vec<Summary> = if args.no_parallel {
        batch.iter().map(|(_, p)| dissect::dissect(link, p)).collect()
    } else {
        batch
            .par_iter()
            .map(|(_, p)| dissect::dissect(link, p))
            .collect()
    };

    // Print in original order. `summaries` is index-aligned with `batch`.
    if !args.quiet {
        for (i, s) in summaries.iter().enumerate() {
            let (meta, _) = &batch[i];
            writeln!(out, "{}", format_line(*meta, s))?;
        }
    }
    batch.clear();
    Ok(())
}
