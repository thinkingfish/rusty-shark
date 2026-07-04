use std::fmt::Write;

use crate::dissect::Summary;
use crate::field::{self, Node, Value};

/// Per-frame metadata computed cheaply on the reader thread: frame number
/// (1-based) and time relative to the first frame.
#[derive(Debug, Clone, Copy)]
pub struct FrameMeta {
    pub number: u64,
    pub rel_time_sec: f64,
}

/// Render a single summary line in tshark's default text format.
pub fn format_line(meta: FrameMeta, s: &Summary) -> String {
    let mut out = String::with_capacity(128);
    let _ = write!(
        &mut out,
        "{num:>5} {ts:>11.6} {src:<15} \u{2192} {dst:<15} {proto:<6} {len:>5} {info}",
        num = meta.number,
        ts = meta.rel_time_sec,
        src = s.src,
        dst = s.dst,
        proto = s.protocol,
        len = s.length,
        info = s.info,
    );
    out
}

/// Build the "Frame" pseudo-protocol node shown at the top of `-V`
/// output. It carries capture metadata (number, time, length) that isn't
/// part of any on-wire protocol but is addressable as `frame.*` fields.
pub fn frame_node(meta: FrameMeta, orig_len: u32, cap_len: usize) -> Node {
    let mut n = Node::proto(format!(
        "Frame {}: {} bytes on wire ({} bits), {} bytes captured ({} bits)",
        meta.number,
        orig_len,
        orig_len as u64 * 8,
        cap_len,
        cap_len as u64 * 8
    ));
    n.add(
        "frame.number",
        Value::Uint(meta.number),
        format!("Frame Number: {}", meta.number),
    );
    n.add(
        "frame.len",
        Value::Uint(orig_len as u64),
        format!("Frame Length: {orig_len} bytes"),
    );
    n.add(
        "frame.time_relative",
        Value::Str(format!("{:.6}", meta.rel_time_sec)),
        format!("Time since reference: {:.6} seconds", meta.rel_time_sec),
    );
    n
}

/// Render the tab-separated field values for `-e` output: for each
/// requested field, the first matching value in `tree`, or empty if
/// absent (matching tshark's behaviour).
pub fn format_fields(tree: &[Node], fields: &[String]) -> String {
    let mut out = String::new();
    for (i, f) in fields.iter().enumerate() {
        if i != 0 {
            out.push('\t');
        }
        if let Some(v) = field::extract(tree, f) {
            let _ = write!(&mut out, "{v}");
        }
    }
    out
}

/// Column module dummy — kept separate because `FrameMeta` is the natural
/// boundary between ordered reader state and per-packet dissection.
pub mod column {
    use super::FrameMeta;

    /// Compute relative time from (ts_sec, ts_nsec) given the capture's
    /// reference timestamp.
    pub fn rel_time(ts_sec: u32, ts_nsec: u32, ref_sec: u32, ref_nsec: u32) -> f64 {
        let delta_sec = ts_sec as i64 - ref_sec as i64;
        let delta_nsec = ts_nsec as i64 - ref_nsec as i64;
        (delta_sec as f64) + (delta_nsec as f64) * 1e-9
    }

    pub fn meta(number: u64, rel_time_sec: f64) -> FrameMeta {
        FrameMeta { number, rel_time_sec }
    }
}
