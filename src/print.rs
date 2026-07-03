use std::fmt::Write;

use crate::dissect::Summary;

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
