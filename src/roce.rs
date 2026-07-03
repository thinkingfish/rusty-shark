//! RoCEv2 (RDMA over Converged Ethernet, v2) dissection.
//!
//! RoCEv2 carries the InfiniBand transport directly over UDP/IP: the UDP
//! destination port is always 4791, and the UDP payload begins with the
//! InfiniBand Base Transport Header (BTH). This module decodes the BTH and,
//! driven by the BTH opcode, the most common extended transport headers
//! (RETH for RDMA operations, AETH for acknowledgements).
//!
//! This is the datacenter-networking vertical slice: it reuses the existing
//! Ethernet/IP/UDP path and hangs a new transport dissector off UDP/4791.
//! The `dqp` (destination queue pair) and `psn` (packet sequence number)
//! surfaced here are the two fields RoCE debugging revolves around, and they
//! are also the natural sharding key / ordering key for a future
//! QP-parallel, PSN-aware analysis pass.
//!
//! Not handled yet: the 4-byte ICRC trailer (present but neither stripped nor
//! validated), RoCEv1 (ethertype 0x8915), native InfiniBand (LRH/GRH), and
//! upper-layer protocols (NVMe-oF, iSER, SMB Direct, ...). See
//! docs/tshark-analysis/datacenter-roadmap.md.

use std::fmt::Write;

use crate::dissect::Summary;

/// The well-known UDP destination port for RoCEv2.
pub const ROCE_V2_UDP_PORT: u16 = 4791;

/// InfiniBand Base Transport Header length, in bytes.
const BTH_LEN: usize = 12;

/// Decode a RoCEv2 payload (the bytes following the UDP header). `s` has
/// already been populated with the IP src/dst; we overwrite the protocol
/// and info columns.
pub fn dissect(payload: &[u8], s: &mut Summary) {
    s.protocol = "RoCE";
    if payload.len() < BTH_LEN {
        s.info = "truncated BTH".into();
        return;
    }

    let opcode = payload[0];
    let se = payload[1] & 0x80 != 0;
    let migreq = payload[1] & 0x40 != 0;
    let pad_count = (payload[1] >> 4) & 0x03;
    let _tver = payload[1] & 0x0f;
    let _p_key = u16::from_be_bytes([payload[2], payload[3]]);
    let fecn = payload[4] & 0x80 != 0;
    let becn = payload[4] & 0x40 != 0;
    let dest_qp = u24_be(&payload[5..8]);
    let ack_req = payload[8] & 0x80 != 0;
    let psn = u24_be(&payload[9..12]);

    let name = opcode_name(opcode);

    let mut info = String::with_capacity(64);
    let _ = write!(&mut info, "{name} DQP=0x{dest_qp:06x} PSN={psn}");

    // Opcode-driven dispatch to the following extended transport header.
    // This is the core BTH pattern: the operation determines what comes next.
    let ext = &payload[BTH_LEN..];
    match ext_header_for(opcode) {
        ExtHeader::Reth => append_reth(ext, &mut info),
        ExtHeader::Aeth => append_aeth(ext, &mut info),
        ExtHeader::None => {}
    }

    // Trailing flags of interest for congestion / reliability debugging.
    let mut flags: Vec<&str> = Vec::new();
    if ack_req {
        flags.push("AckReq");
    }
    if se {
        flags.push("SE");
    }
    if fecn {
        flags.push("FECN");
    }
    if becn {
        flags.push("BECN");
    }
    if migreq {
        flags.push("MigReq");
    }
    if pad_count != 0 {
        // Not a flag, but worth noting when non-zero.
    }
    if !flags.is_empty() {
        let _ = write!(&mut info, " [{}]", flags.join(", "));
    }

    s.info = info;
}

/// Which extended header, if any, immediately follows the BTH for a given
/// opcode. Only the two most common are wired up for the MVP.
enum ExtHeader {
    Reth,
    Aeth,
    None,
}

fn ext_header_for(opcode: u8) -> ExtHeader {
    let op = opcode & 0x1f;
    let svc = opcode >> 5;
    // RC (0) and UC (1) and RD (2) share the base operation numbering for
    // the RDMA family; we only need the operation bits to pick the header.
    match svc {
        0..=2 => match op {
            // RDMA WRITE First / Only, RDMA WRITE Only w/ Imm, RDMA READ Request
            0x06 | 0x0a | 0x0b | 0x0c => ExtHeader::Reth,
            // Acknowledge, ATOMIC Acknowledge
            0x11 | 0x12 => ExtHeader::Aeth,
            _ => ExtHeader::None,
        },
        _ => ExtHeader::None,
    }
}

/// RDMA Extended Transport Header: virtual address, remote key, DMA length.
fn append_reth(ext: &[u8], info: &mut String) {
    if ext.len() < 16 {
        info.push_str(" RETH=<truncated>");
        return;
    }
    let va = u64::from_be_bytes(ext[0..8].try_into().unwrap());
    let r_key = u32::from_be_bytes([ext[8], ext[9], ext[10], ext[11]]);
    let dma_len = u32::from_be_bytes([ext[12], ext[13], ext[14], ext[15]]);
    let _ = write!(
        info,
        " VA=0x{va:016x} RKey=0x{r_key:08x} Len={dma_len}"
    );
}

/// ACK Extended Transport Header: syndrome + message sequence number.
fn append_aeth(ext: &[u8], info: &mut String) {
    if ext.len() < 4 {
        info.push_str(" AETH=<truncated>");
        return;
    }
    let syndrome = ext[0];
    let msn = u24_be(&ext[1..4]);
    let kind = match syndrome >> 5 {
        0b000 => "ACK",
        0b001 => "RNR-NAK",
        0b011 => "NAK",
        _ => "reserved",
    };
    let _ = write!(info, " {kind} Syndrome=0x{syndrome:02x} MSN={msn}");
}

/// Human-readable BTH opcode name. The high 3 bits select the transport
/// service (RC/UC/RD/UD/CNP/XRC); the low 5 bits select the operation.
fn opcode_name(opcode: u8) -> String {
    // RoCEv2 Congestion Notification Packet is a distinguished opcode.
    if opcode == 0x81 {
        return "CNP".into();
    }
    let svc = match opcode >> 5 {
        0b000 => "RC",
        0b001 => "UC",
        0b010 => "RD",
        0b011 => "UD",
        0b100 => "CNP",
        0b101 => "XRC",
        _ => "Vendor",
    };
    let op = match opcode & 0x1f {
        0x00 => "SEND First",
        0x01 => "SEND Middle",
        0x02 => "SEND Last",
        0x03 => "SEND Last w/ Imm",
        0x04 => "SEND Only",
        0x05 => "SEND Only w/ Imm",
        0x06 => "RDMA WRITE First",
        0x07 => "RDMA WRITE Middle",
        0x08 => "RDMA WRITE Last",
        0x09 => "RDMA WRITE Last w/ Imm",
        0x0a => "RDMA WRITE Only",
        0x0b => "RDMA WRITE Only w/ Imm",
        0x0c => "RDMA READ Request",
        0x0d => "RDMA READ Response First",
        0x0e => "RDMA READ Response Middle",
        0x0f => "RDMA READ Response Last",
        0x10 => "RDMA READ Response Only",
        0x11 => "Acknowledge",
        0x12 => "ATOMIC Acknowledge",
        0x13 => "CmpSwap",
        0x14 => "FetchAdd",
        0x16 => "SEND Last w/ Invalidate",
        0x17 => "SEND Only w/ Invalidate",
        other => return format!("{svc} opcode 0x{other:02x}"),
    };
    format!("{svc} {op}")
}

#[inline]
fn u24_be(b: &[u8]) -> u32 {
    ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary() -> Summary {
        // Length is irrelevant to these tests; build a bare Summary via the
        // public dissect entry using a crafted BTH.
        Summary {
            src: "10.0.0.1".into(),
            dst: "10.0.0.2".into(),
            protocol: "UDP",
            info: String::new(),
            length: 0,
        }
    }

    fn bth(opcode: u8, dest_qp: u32, psn: u32, byte1: u8, byte4: u8, byte8: u8) -> Vec<u8> {
        let mut v = vec![
            opcode,
            byte1,
            0xff,
            0xff, // p_key
            byte4,
            ((dest_qp >> 16) & 0xff) as u8,
            ((dest_qp >> 8) & 0xff) as u8,
            (dest_qp & 0xff) as u8,
            byte8,
            ((psn >> 16) & 0xff) as u8,
            ((psn >> 8) & 0xff) as u8,
            (psn & 0xff) as u8,
        ];
        assert_eq!(v.len(), BTH_LEN);
        v.reserve(16);
        v
    }

    #[test]
    fn send_only_rc() {
        // RC SEND Only (0x04), DQP 0xd2, PSN 1, AckReq set (byte8 0x80).
        let payload = bth(0x04, 0x0000d2, 1, 0x00, 0x00, 0x80);
        let mut s = summary();
        dissect(&payload, &mut s);
        assert_eq!(s.protocol, "RoCE");
        assert!(s.info.contains("RC SEND Only"), "{}", s.info);
        assert!(s.info.contains("DQP=0x0000d2"), "{}", s.info);
        assert!(s.info.contains("PSN=1"), "{}", s.info);
        assert!(s.info.contains("AckReq"), "{}", s.info);
    }

    #[test]
    fn rdma_write_only_carries_reth() {
        // RC RDMA WRITE Only (0x0a) + RETH (VA, RKey, Len).
        let mut payload = bth(0x0a, 0x123456, 42, 0x00, 0x00, 0x00);
        payload.extend_from_slice(&0x1122_3344_5566_7788u64.to_be_bytes()); // VA
        payload.extend_from_slice(&0xdead_beefu32.to_be_bytes()); // RKey
        payload.extend_from_slice(&4096u32.to_be_bytes()); // DMA length
        let mut s = summary();
        dissect(&payload, &mut s);
        assert!(s.info.contains("RDMA WRITE Only"), "{}", s.info);
        assert!(s.info.contains("VA=0x1122334455667788"), "{}", s.info);
        assert!(s.info.contains("RKey=0xdeadbeef"), "{}", s.info);
        assert!(s.info.contains("Len=4096"), "{}", s.info);
    }

    #[test]
    fn ack_carries_aeth() {
        // RC Acknowledge (0x11) + AETH (syndrome 0x00 = ACK, MSN 7).
        let mut payload = bth(0x11, 0x000001, 100, 0x00, 0x00, 0x00);
        payload.push(0x00); // syndrome: ACK
        payload.extend_from_slice(&[0x00, 0x00, 0x07]); // MSN = 7
        let mut s = summary();
        dissect(&payload, &mut s);
        assert!(s.info.contains("Acknowledge"), "{}", s.info);
        assert!(s.info.contains("ACK"), "{}", s.info);
        assert!(s.info.contains("MSN=7"), "{}", s.info);
    }

    #[test]
    fn cnp_congestion_packet() {
        let payload = bth(0x81, 0x000abc, 0, 0x00, 0x00, 0x00);
        let mut s = summary();
        dissect(&payload, &mut s);
        assert!(s.info.contains("CNP"), "{}", s.info);
    }

    #[test]
    fn congestion_flags_surfaced() {
        // FECN + BECN set in byte 4.
        let payload = bth(0x04, 0x000001, 5, 0x00, 0xc0, 0x00);
        let mut s = summary();
        dissect(&payload, &mut s);
        assert!(s.info.contains("FECN"), "{}", s.info);
        assert!(s.info.contains("BECN"), "{}", s.info);
    }

    #[test]
    fn truncated_bth() {
        let payload = vec![0u8; 8];
        let mut s = summary();
        dissect(&payload, &mut s);
        assert_eq!(s.protocol, "RoCE");
        assert!(s.info.contains("truncated"), "{}", s.info);
    }
}
