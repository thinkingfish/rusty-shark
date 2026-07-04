//! RoCE per-queue-pair analyses. Two reports, both keyed by (destination
//! IP, destination QP) and both fed by one lightweight record collected
//! per RoCE packet during the (already parallel) dissection walk:
//!
//! - **PSN analysis** (M5, `-z roce,psn`): reliable-connection sequence
//!   tracking. An RC QP carries a 24-bit Packet Sequence Number that
//!   increments by one per packet, so walking the stream in arrival order
//!   reveals drops (a forward jump of `delta` PSNs), and retransmits /
//!   out-of-order / duplicates (a backward step). RC only (BTH service
//!   type 0) — PSN tracking is not meaningful for CNP/UC/UD.
//!
//! - **Congestion analysis** (M4, `-z roce,cong`): per-QP counts of ECN
//!   CE-marked packets (congestion experienced) and CNPs (congestion
//!   notified), exposing the DCQCN loop. This one counts every RoCE
//!   packet, CNPs included.
//!
//! Why this fits the parallel design: every QP's state is independent, so
//! the analyses shard perfectly — each QP is reduced with no reference to
//! any other. Grouping is by an ordered map so output is deterministic;
//! the per-QP reductions are embarrassingly parallelisable when captures
//! get large.

use std::collections::BTreeMap;
use std::fmt;

use crate::field::{self, Node, Value};

/// 24-bit PSN space.
const PSN_MASK: u32 = 0x00ff_ffff;
const PSN_HALF: u32 = 0x0080_0000;
const PSN_SPACE: i64 = 0x0100_0000;

/// One RoCE packet reduced to what the analyses need.
#[derive(Debug, Clone)]
pub struct Rec {
    pub framenum: u64,
    pub dst: String,
    pub qp: u32,
    pub psn: u32,
    /// BTH opcode (service type in bits 7..5, operation in 4..0).
    pub opcode: u8,
    /// Whether the packet's IP header carried the ECN CE codepoint (3).
    pub ce: bool,
}

impl Rec {
    /// A reliable-connection packet (BTH service type 0) — the only class
    /// where PSN tracking is meaningful.
    fn is_rc(&self) -> bool {
        self.opcode >> 5 == 0
    }

    /// The RoCEv2 Congestion Notification Packet opcode.
    fn is_cnp(&self) -> bool {
        self.opcode == 0x81
    }
}

/// Extract an analysis record from a dissected packet's field tree, or
/// `None` if it isn't a RoCE (BTH) packet. All RoCE packets are captured
/// here — the PSN analysis filters to reliable connections itself, while
/// the congestion analysis needs CNPs too.
pub fn record(framenum: u64, dst: &str, tree: &[Node]) -> Option<Rec> {
    let opcode = as_uint(field::extract(tree, "infiniband.bth.opcode"))? as u8;
    let qp = as_uint(field::extract(tree, "infiniband.bth.destqp"))? as u32;
    let psn = as_uint(field::extract(tree, "infiniband.bth.psn"))? as u32;
    Some(Rec {
        framenum,
        dst: dst.to_string(),
        qp,
        psn,
        opcode,
        ce: ce_marked(tree),
    })
}

/// True if the enclosing IP header (v4 or v6) carried the ECN CE mark.
fn ce_marked(tree: &[Node]) -> bool {
    matches!(as_uint(field::extract(tree, "ip.dsfield.ecn")), Some(3))
        || matches!(as_uint(field::extract(tree, "ipv6.dsfield.ecn")), Some(3))
}

fn as_uint(v: Option<&Value>) -> Option<u64> {
    match v {
        Some(Value::Uint(u)) => Some(*u),
        _ => None,
    }
}

/// Signed distance `a - b` in the 24-bit PSN space (RFC 1982 style), so
/// that wrap-around near 0xffffff → 0x000000 reads as +1, not a huge jump.
fn seq_diff(a: u32, b: u32) -> i32 {
    let d = a.wrapping_sub(b) & PSN_MASK;
    if d >= PSN_HALF {
        (d as i64 - PSN_SPACE) as i32
    } else {
        d as i32
    }
}

#[derive(Default)]
struct QpState {
    packets: u64,
    first_psn: u32,
    last_psn: u32,
    expected: Option<u32>,
    gap_events: u64,
    missing: u64,
    retransmits: u64,
    first_issue_frame: Option<u64>,
}

impl QpState {
    fn observe(&mut self, psn: u32, framenum: u64) {
        self.packets += 1;
        match self.expected {
            None => {
                self.first_psn = psn;
                self.last_psn = psn;
            }
            Some(exp) => {
                let d = seq_diff(psn, exp);
                if d > 0 {
                    // Forward jump: `d` PSNs went missing.
                    self.gap_events += 1;
                    self.missing += d as u64;
                    self.last_psn = psn;
                    self.first_issue_frame.get_or_insert(framenum);
                } else if d < 0 {
                    // Behind expected: retransmit / out-of-order / duplicate.
                    self.retransmits += 1;
                    self.first_issue_frame.get_or_insert(framenum);
                    return; // don't advance `expected`
                } else {
                    self.last_psn = psn;
                }
            }
        }
        self.expected = Some((psn + 1) & PSN_MASK);
    }
}

/// One row of the report: the analysis for a single queue pair.
#[derive(Debug, Clone)]
pub struct QpReport {
    pub dst: String,
    pub qp: u32,
    pub packets: u64,
    pub first_psn: u32,
    pub last_psn: u32,
    pub gap_events: u64,
    pub missing: u64,
    pub retransmits: u64,
    pub first_issue_frame: Option<u64>,
}

/// The full per-QP report plus totals.
#[derive(Debug, Clone, Default)]
pub struct Report {
    pub rows: Vec<QpReport>,
    pub total_packets: u64,
    pub total_gap_events: u64,
    pub total_missing: u64,
    pub total_retransmits: u64,
}

/// Reduce the collected records into a per-QP PSN report (RC only).
pub fn analyze_psn(records: &[Rec]) -> Report {
    // Key by (dst IP, dest QP): a QP endpoint lives on its destination
    // node, and each direction of a connection targets a distinct QP, so
    // this cleanly separates the two directions' PSN streams.
    let mut qps: BTreeMap<(String, u32), QpState> = BTreeMap::new();
    for r in records {
        if !r.is_rc() {
            continue; // PSN tracking only meaningful for reliable connections
        }
        qps.entry((r.dst.clone(), r.qp))
            .or_default()
            .observe(r.psn, r.framenum);
    }

    let mut report = Report::default();
    for ((dst, qp), st) in qps {
        report.total_packets += st.packets;
        report.total_gap_events += st.gap_events;
        report.total_missing += st.missing;
        report.total_retransmits += st.retransmits;
        report.rows.push(QpReport {
            dst,
            qp,
            packets: st.packets,
            first_psn: st.first_psn,
            last_psn: st.last_psn,
            gap_events: st.gap_events,
            missing: st.missing,
            retransmits: st.retransmits,
            first_issue_frame: st.first_issue_frame,
        });
    }
    report
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "===================================================================")?;
        writeln!(f, "RoCE PSN analysis (reliable connections, per destination QP)")?;
        writeln!(f, "===================================================================")?;
        if self.rows.is_empty() {
            writeln!(f, "No RoCE RC packets found.")?;
            return Ok(());
        }
        writeln!(
            f,
            "{:<18} {:>10} {:>8} {:>9} {:>9} {:>6} {:>8} {:>8} {:>11}",
            "Dst IP",
            "QP",
            "Packets",
            "FirstPSN",
            "LastPSN",
            "Gaps",
            "Missing",
            "Retrans",
            "1stIssue@"
        )?;
        writeln!(f, "-------------------------------------------------------------------------------")?;
        for r in &self.rows {
            let issue = match r.first_issue_frame {
                Some(fr) => fr.to_string(),
                None => "-".to_string(),
            };
            writeln!(
                f,
                "{:<18} {:>#10x} {:>8} {:>9} {:>9} {:>6} {:>8} {:>8} {:>11}",
                r.dst,
                r.qp,
                r.packets,
                r.first_psn,
                r.last_psn,
                r.gap_events,
                r.missing,
                r.retransmits,
                issue
            )?;
        }
        writeln!(f, "-------------------------------------------------------------------------------")?;
        writeln!(
            f,
            "Totals: QPs={} Packets={} Gaps={} Missing={} Retrans={}",
            self.rows.len(),
            self.total_packets,
            self.total_gap_events,
            self.total_missing,
            self.total_retransmits
        )?;
        Ok(())
    }
}

// ---- congestion analysis ----

#[derive(Default)]
struct CongState {
    packets: u64,
    ce_marked: u64,
    cnps: u64,
}

/// One row of the congestion report for a single queue pair.
#[derive(Debug, Clone)]
pub struct CongQp {
    pub dst: String,
    pub qp: u32,
    pub packets: u64,
    pub ce_marked: u64,
    pub cnps: u64,
}

/// Per-QP congestion report.
#[derive(Debug, Clone, Default)]
pub struct CongReport {
    pub rows: Vec<CongQp>,
    pub total_packets: u64,
    pub total_ce: u64,
    pub total_cnps: u64,
}

/// Reduce records into a per-QP congestion view: how many packets
/// destined to each QP were ECN CE-marked (congestion experienced), and
/// how many CNPs it received (congestion notified). Together these show
/// the DCQCN loop — CE marks upstream, CNPs coming back.
pub fn analyze_cong(records: &[Rec]) -> CongReport {
    let mut qps: BTreeMap<(String, u32), CongState> = BTreeMap::new();
    for r in records {
        let st = qps.entry((r.dst.clone(), r.qp)).or_default();
        st.packets += 1;
        if r.ce {
            st.ce_marked += 1;
        }
        if r.is_cnp() {
            st.cnps += 1;
        }
    }

    let mut report = CongReport::default();
    for ((dst, qp), st) in qps {
        report.total_packets += st.packets;
        report.total_ce += st.ce_marked;
        report.total_cnps += st.cnps;
        report.rows.push(CongQp {
            dst,
            qp,
            packets: st.packets,
            ce_marked: st.ce_marked,
            cnps: st.cnps,
        });
    }
    report
}

impl fmt::Display for CongReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "===================================================================")?;
        writeln!(f, "RoCE congestion analysis (per destination QP)")?;
        writeln!(f, "===================================================================")?;
        if self.rows.is_empty() {
            writeln!(f, "No RoCE packets found.")?;
            return Ok(());
        }
        writeln!(
            f,
            "{:<18} {:>10} {:>8} {:>10} {:>6}",
            "Dst IP", "QP", "Packets", "CE-marked", "CNPs"
        )?;
        writeln!(f, "-----------------------------------------------------------")?;
        for r in &self.rows {
            writeln!(
                f,
                "{:<18} {:>#10x} {:>8} {:>10} {:>6}",
                r.dst, r.qp, r.packets, r.ce_marked, r.cnps
            )?;
        }
        writeln!(f, "-----------------------------------------------------------")?;
        writeln!(
            f,
            "Totals: QPs={} Packets={} CE-marked={} CNPs={}",
            self.rows.len(),
            self.total_packets,
            self.total_ce,
            self.total_cnps
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(framenum: u64, dst: &str, qp: u32, psn: u32) -> Rec {
        // RC RDMA WRITE Only (0x0a), not CE-marked — the default for PSN tests.
        Rec {
            framenum,
            dst: dst.into(),
            qp,
            psn,
            opcode: 0x0a,
            ce: false,
        }
    }

    #[test]
    fn clean_sequence_no_issues() {
        let recs = vec![
            rec(1, "10.0.0.2", 0x123, 100),
            rec(2, "10.0.0.2", 0x123, 101),
            rec(3, "10.0.0.2", 0x123, 102),
        ];
        let rep = analyze_psn(&recs);
        assert_eq!(rep.rows.len(), 1);
        let r = &rep.rows[0];
        assert_eq!(r.packets, 3);
        assert_eq!(r.first_psn, 100);
        assert_eq!(r.last_psn, 102);
        assert_eq!(r.gap_events, 0);
        assert_eq!(r.missing, 0);
        assert_eq!(r.retransmits, 0);
    }

    #[test]
    fn detects_gap_and_retransmit() {
        // 100, 101, 103 (drop of 102), 102 (retransmit/ooo)
        let recs = vec![
            rec(1, "10.0.0.2", 0x123, 100),
            rec(2, "10.0.0.2", 0x123, 101),
            rec(3, "10.0.0.2", 0x123, 103),
            rec(4, "10.0.0.2", 0x123, 102),
        ];
        let rep = analyze_psn(&recs);
        let r = &rep.rows[0];
        assert_eq!(r.packets, 4);
        assert_eq!(r.gap_events, 1);
        assert_eq!(r.missing, 1); // one PSN (102) skipped
        assert_eq!(r.retransmits, 1); // 102 arrives late
        assert_eq!(r.last_psn, 103);
        assert_eq!(r.first_issue_frame, Some(3)); // gap first seen at frame 3
    }

    #[test]
    fn detects_duplicate() {
        let recs = vec![
            rec(1, "10.0.0.2", 0x123, 5),
            rec(2, "10.0.0.2", 0x123, 5),
        ];
        let rep = analyze_psn(&recs);
        assert_eq!(rep.rows[0].retransmits, 1);
    }

    #[test]
    fn larger_gap_counts_all_missing() {
        // 10 then 15 → four missing (11,12,13,14)
        let recs = vec![
            rec(1, "10.0.0.2", 0x1, 10),
            rec(2, "10.0.0.2", 0x1, 15),
        ];
        let rep = analyze_psn(&recs);
        assert_eq!(rep.rows[0].gap_events, 1);
        assert_eq!(rep.rows[0].missing, 4);
    }

    #[test]
    fn psn_wraparound_is_not_a_gap() {
        let recs = vec![
            rec(1, "10.0.0.2", 0x1, 0x00ff_fffe),
            rec(2, "10.0.0.2", 0x1, 0x00ff_ffff),
            rec(3, "10.0.0.2", 0x1, 0x0000_0000),
            rec(4, "10.0.0.2", 0x1, 0x0000_0001),
        ];
        let rep = analyze_psn(&recs);
        assert_eq!(rep.rows[0].gap_events, 0);
        assert_eq!(rep.rows[0].missing, 0);
        assert_eq!(rep.rows[0].retransmits, 0);
    }

    #[test]
    fn separate_qps_and_hosts_tracked_independently() {
        let recs = vec![
            rec(1, "10.0.0.2", 0x123, 100),
            rec(2, "10.0.0.3", 0x123, 200), // same QP number, different host
            rec(3, "10.0.0.2", 0x456, 5),
        ];
        let rep = analyze_psn(&recs);
        assert_eq!(rep.rows.len(), 3);
        assert_eq!(rep.total_packets, 3);
    }

    #[test]
    fn seq_diff_basics() {
        assert_eq!(seq_diff(101, 100), 1);
        assert_eq!(seq_diff(100, 101), -1);
        assert_eq!(seq_diff(0x000000, 0x00ffffff), 1); // wrap forward
        assert_eq!(seq_diff(0x00ffffff, 0x000000), -1); // wrap backward
    }

    fn cong_rec(dst: &str, qp: u32, opcode: u8, ce: bool) -> Rec {
        Rec {
            framenum: 0,
            dst: dst.into(),
            qp,
            psn: 0,
            opcode,
            ce,
        }
    }

    #[test]
    fn congestion_counts_ce_and_cnp() {
        let recs = vec![
            // QP 0x123 on 10.0.0.2: two data packets, one CE-marked.
            cong_rec("10.0.0.2", 0x123, 0x0a, false),
            cong_rec("10.0.0.2", 0x123, 0x0a, true),
            // QP 0x456 on 10.0.0.1: a CNP (opcode 0x81).
            cong_rec("10.0.0.1", 0x456, 0x81, false),
        ];
        let rep = analyze_cong(&recs);
        assert_eq!(rep.rows.len(), 2);
        assert_eq!(rep.total_packets, 3);
        assert_eq!(rep.total_ce, 1);
        assert_eq!(rep.total_cnps, 1);

        let q123 = rep.rows.iter().find(|r| r.qp == 0x123).unwrap();
        assert_eq!(q123.packets, 2);
        assert_eq!(q123.ce_marked, 1);
        assert_eq!(q123.cnps, 0);

        let q456 = rep.rows.iter().find(|r| r.qp == 0x456).unwrap();
        assert_eq!(q456.cnps, 1);
    }

    #[test]
    fn psn_analysis_ignores_cnp_but_congestion_counts_it() {
        // A CNP shares a QP with RC data; PSN analysis must skip it.
        let recs = vec![
            rec(1, "10.0.0.2", 0x123, 100),         // RC (opcode 0x0a via helper)
            cong_rec("10.0.0.2", 0x123, 0x81, false), // CNP, not RC
            rec(2, "10.0.0.2", 0x123, 101),
        ];
        let psn = analyze_psn(&recs);
        assert_eq!(psn.rows.len(), 1);
        assert_eq!(psn.rows[0].packets, 2); // CNP excluded
        assert_eq!(psn.rows[0].gap_events, 0);

        let cong = analyze_cong(&recs);
        assert_eq!(cong.total_packets, 3); // CNP included
        assert_eq!(cong.total_cnps, 1);
    }
}
