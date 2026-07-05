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
//! Upper-layer protocols: NVMe/RDMA capsules riding on SEND operations are
//! handed to `crate::nvme` (the ICRC trailer is stripped first). Not
//! handled yet: RoCEv1 (ethertype 0x8915), native InfiniBand (LRH/GRH),
//! ICRC validation, and other ULPs (iSER, SMB Direct, ...). See
//! docs/tshark-analysis/datacenter-roadmap.md.

use std::fmt::Write;

use crate::dissect::{Dissection, DissectConfig};
use crate::field::{Node, Value};

/// The well-known UDP destination port for RoCEv2.
pub const ROCE_V2_UDP_PORT: u16 = 4791;

/// InfiniBand Base Transport Header length, in bytes.
const BTH_LEN: usize = 12;

/// Decode a RoCEv2 payload (the bytes following the UDP header). The IP
/// src/dst columns are already populated; we overwrite the protocol and
/// info columns and append a BTH protocol node to the detail tree.
pub fn dissect(payload: &[u8], d: &mut Dissection, cfg: &DissectConfig) {
    d.summary.protocol = "RoCE";
    if payload.len() < BTH_LEN {
        d.summary.info = "truncated BTH".into();
        d.tree.push(Node::proto("InfiniBand Base Transport Header (truncated)"));
        return;
    }

    let opcode = payload[0];
    let se = payload[1] & 0x80 != 0;
    let migreq = payload[1] & 0x40 != 0;
    let pad_count = (payload[1] >> 4) & 0x03;
    let _tver = payload[1] & 0x0f;
    let p_key = u16::from_be_bytes([payload[2], payload[3]]);
    let fecn = payload[4] & 0x80 != 0;
    let becn = payload[4] & 0x40 != 0;
    let dest_qp = u24_be(&payload[5..8]);
    let ack_req = payload[8] & 0x80 != 0;
    let psn = u24_be(&payload[9..12]);

    let name = opcode_name(opcode);

    let mut info = String::with_capacity(64);
    let _ = write!(&mut info, "{name} DQP=0x{dest_qp:06x} PSN={psn}");

    let mut node = Node::proto(format!("InfiniBand BTH — {name}"));
    node.add(
        "infiniband.bth.opcode",
        Value::Uint(opcode as u64),
        format!("Opcode: {name} (0x{opcode:02x})"),
    );
    node.add(
        "infiniband.bth.pkey",
        Value::Uint(p_key as u64),
        format!("Partition Key: 0x{p_key:04x}"),
    );
    node.add(
        "infiniband.bth.destqp",
        Value::Uint(dest_qp as u64),
        format!("Destination Queue Pair: 0x{dest_qp:06x}"),
    );
    node.add(
        "infiniband.bth.psn",
        Value::Uint(psn as u64),
        format!("Packet Sequence Number: {psn}"),
    );
    node.add(
        "infiniband.bth.se",
        Value::Uint(se as u64),
        format!("Solicited Event: {}", se as u8),
    );
    node.add(
        "infiniband.bth.ackreq",
        Value::Uint(ack_req as u64),
        format!("Acknowledge Request: {}", ack_req as u8),
    );
    node.add(
        "infiniband.bth.fecn",
        Value::Uint(fecn as u64),
        format!("FECN: {}", fecn as u8),
    );
    node.add(
        "infiniband.bth.becn",
        Value::Uint(becn as u64),
        format!("BECN: {}", becn as u8),
    );

    // Opcode-driven dispatch to the following extended transport headers.
    // This is the core BTH pattern: the operation determines what comes
    // next, and some operations carry more than one (e.g. RDMA WRITE Only
    // with Immediate is RETH followed by ImmDt).
    let ext = &payload[BTH_LEN..];
    let ext_len = decode_ext_headers(opcode, ext, &mut info, &mut node);

    // Upper-layer protocol: NVMe/RDMA capsules ride on SEND operations.
    // The SEND payload is whatever follows the extended headers, minus the
    // trailing 4-byte ICRC. Fabrics capsules are auto-detected; full NVMe
    // decode requires --nvme (cfg.nvme_force).
    if is_send_opcode(opcode) {
        let after_ext = &ext[ext_len.min(ext.len())..];
        let capsule = strip_icrc(after_ext);
        if !capsule.is_empty() {
            if let Some(label) =
                crate::nvme::try_dissect(capsule, cfg.nvme_force, &mut info, &mut node)
            {
                d.summary.protocol = label;
            }
        }
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
    let _ = pad_count; // decoded for completeness; not surfaced in summary
    if !flags.is_empty() {
        let _ = write!(&mut info, " [{}]", flags.join(", "));
    }

    d.summary.info = info;
    d.tree.push(node);
}

/// Append every extended transport header carried by this opcode, in
/// order, advancing through `ext`. RC/UC/RD share the base RDMA-family
/// operation numbering, so the operation bits select the headers. Returns
/// the total number of bytes the extended headers consumed.
fn decode_ext_headers(opcode: u8, ext: &[u8], info: &mut String, node: &mut Node) -> usize {
    let op = opcode & 0x1f;
    let svc = opcode >> 5;
    if svc > 2 {
        return 0; // UD/CNP/XRC extended headers not decoded here
    }
    let mut off = 0usize;
    // RETH: RDMA WRITE First/Only, WRITE Only w/ Imm, READ Request.
    if matches!(op, 0x06 | 0x0a | 0x0b | 0x0c) {
        off += append_reth(&ext[off.min(ext.len())..], info, node);
    }
    // AETH: Acknowledge, ATOMIC Acknowledge.
    if matches!(op, 0x11 | 0x12) {
        off += append_aeth(&ext[off.min(ext.len())..], info, node);
    }
    // ImmDt: the "with Immediate" variants — SEND (0x03/0x05) and RDMA
    // WRITE (0x09/0x0b). For WRITE Only w/ Imm it follows the RETH above.
    if matches!(op, 0x03 | 0x05 | 0x09 | 0x0b) {
        off += append_immdt(&ext[off.min(ext.len())..], info, node);
    }
    off
}

/// True for the SEND family (First/Middle/Last/Only, plain and with
/// Immediate / Invalidate) on RC/UC service — the operations that carry
/// an upper-layer capsule payload.
fn is_send_opcode(opcode: u8) -> bool {
    let svc = opcode >> 5;
    let op = opcode & 0x1f;
    matches!(svc, 0 | 1) && matches!(op, 0x00..=0x05 | 0x16 | 0x17)
}

/// Drop the trailing 4-byte Invariant CRC that ends every IB/RoCE packet,
/// leaving just the upper-layer payload.
fn strip_icrc(bytes: &[u8]) -> &[u8] {
    if bytes.len() > 4 {
        &bytes[..bytes.len() - 4]
    } else {
        &[]
    }
}

/// RDMA Extended Transport Header: virtual address, remote key, DMA length.
/// Returns the number of bytes consumed.
fn append_reth(ext: &[u8], info: &mut String, node: &mut Node) -> usize {
    if ext.len() < 16 {
        info.push_str(" RETH=<truncated>");
        return ext.len();
    }
    let va = u64::from_be_bytes(ext[0..8].try_into().unwrap());
    let r_key = u32::from_be_bytes([ext[8], ext[9], ext[10], ext[11]]);
    let dma_len = u32::from_be_bytes([ext[12], ext[13], ext[14], ext[15]]);
    let _ = write!(
        info,
        " VA=0x{va:016x} RKey=0x{r_key:08x} Len={dma_len}"
    );
    node.add(
        "infiniband.reth.va",
        Value::Uint(va),
        format!("Virtual Address: 0x{va:016x}"),
    );
    node.add(
        "infiniband.reth.rkey",
        Value::Uint(r_key as u64),
        format!("Remote Key: 0x{r_key:08x}"),
    );
    node.add(
        "infiniband.reth.dmalen",
        Value::Uint(dma_len as u64),
        format!("DMA Length: {dma_len}"),
    );
    16
}

/// Immediate Data Extended Transport Header: 4 bytes of opaque immediate
/// data delivered to the receiver's completion queue.
fn append_immdt(ext: &[u8], info: &mut String, node: &mut Node) -> usize {
    if ext.len() < 4 {
        info.push_str(" ImmDt=<truncated>");
        return ext.len();
    }
    let imm = u32::from_be_bytes([ext[0], ext[1], ext[2], ext[3]]);
    let _ = write!(info, " ImmDt=0x{imm:08x}");
    node.add(
        "infiniband.immdt.immediatedata",
        Value::Uint(imm as u64),
        format!("Immediate Data: 0x{imm:08x}"),
    );
    4
}

/// ACK Extended Transport Header: syndrome + message sequence number.
/// Returns the number of bytes consumed.
fn append_aeth(ext: &[u8], info: &mut String, node: &mut Node) -> usize {
    if ext.len() < 4 {
        info.push_str(" AETH=<truncated>");
        return ext.len();
    }
    let syndrome = ext[0];
    let msn = u24_be(&ext[1..4]);
    let kind = match syndrome >> 5 {
        0b000 => "ACK",
        0b001 => "RNR-NAK",
        0b011 => "NAK",
        _ => "reserved",
    };
    node.add(
        "infiniband.aeth.syndrome",
        Value::Uint(syndrome as u64),
        format!("Syndrome: 0x{syndrome:02x} ({kind})"),
    );
    node.add(
        "infiniband.aeth.msn",
        Value::Uint(msn as u64),
        format!("Message Sequence Number: {msn}"),
    );
    let _ = write!(info, " {kind} Syndrome=0x{syndrome:02x} MSN={msn}");
    4
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
    use crate::dissect::Summary;
    use crate::field::extract;

    fn dis() -> Dissection {
        // Bare dissection with IP columns already filled, as the UDP
        // dissector would leave it before handing off to RoCE.
        Dissection {
            summary: Summary {
                src: "10.0.0.1".into(),
                dst: "10.0.0.2".into(),
                protocol: "UDP",
                info: String::new(),
                length: 0,
            },
            tree: Vec::new(),
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
        let mut d = dis();
        dissect(&payload, &mut d, &DissectConfig::default());
        let s = &d.summary;
        assert_eq!(s.protocol, "RoCE");
        assert!(s.info.contains("RC SEND Only"), "{}", s.info);
        assert!(s.info.contains("DQP=0x0000d2"), "{}", s.info);
        assert!(s.info.contains("PSN=1"), "{}", s.info);
        assert!(s.info.contains("AckReq"), "{}", s.info);
        // The same values are addressable as typed fields.
        assert_eq!(extract(&d.tree, "infiniband.bth.destqp"), Some(&Value::Uint(0xd2)));
        assert_eq!(extract(&d.tree, "infiniband.bth.psn"), Some(&Value::Uint(1)));
        assert_eq!(extract(&d.tree, "infiniband.bth.opcode"), Some(&Value::Uint(0x04)));
    }

    #[test]
    fn rdma_write_only_carries_reth() {
        // RC RDMA WRITE Only (0x0a) + RETH (VA, RKey, Len).
        let mut payload = bth(0x0a, 0x123456, 42, 0x00, 0x00, 0x00);
        payload.extend_from_slice(&0x1122_3344_5566_7788u64.to_be_bytes()); // VA
        payload.extend_from_slice(&0xdead_beefu32.to_be_bytes()); // RKey
        payload.extend_from_slice(&4096u32.to_be_bytes()); // DMA length
        let mut d = dis();
        dissect(&payload, &mut d, &DissectConfig::default());
        let s = &d.summary;
        assert!(s.info.contains("RDMA WRITE Only"), "{}", s.info);
        assert!(s.info.contains("VA=0x1122334455667788"), "{}", s.info);
        assert!(s.info.contains("RKey=0xdeadbeef"), "{}", s.info);
        assert!(s.info.contains("Len=4096"), "{}", s.info);
        assert_eq!(extract(&d.tree, "infiniband.reth.dmalen"), Some(&Value::Uint(4096)));
        assert_eq!(
            extract(&d.tree, "infiniband.reth.rkey"),
            Some(&Value::Uint(0xdead_beef))
        );
    }

    #[test]
    fn ack_carries_aeth() {
        // RC Acknowledge (0x11) + AETH (syndrome 0x00 = ACK, MSN 7).
        let mut payload = bth(0x11, 0x000001, 100, 0x00, 0x00, 0x00);
        payload.push(0x00); // syndrome: ACK
        payload.extend_from_slice(&[0x00, 0x00, 0x07]); // MSN = 7
        let mut d = dis();
        dissect(&payload, &mut d, &DissectConfig::default());
        let s = &d.summary;
        assert!(s.info.contains("Acknowledge"), "{}", s.info);
        assert!(s.info.contains("ACK"), "{}", s.info);
        assert!(s.info.contains("MSN=7"), "{}", s.info);
        assert_eq!(extract(&d.tree, "infiniband.aeth.msn"), Some(&Value::Uint(7)));
    }

    #[test]
    fn cnp_congestion_packet() {
        let payload = bth(0x81, 0x000abc, 0, 0x00, 0x00, 0x00);
        let mut d = dis();
        dissect(&payload, &mut d, &DissectConfig::default());
        assert!(d.summary.info.contains("CNP"), "{}", d.summary.info);
    }

    #[test]
    fn congestion_flags_surfaced() {
        // FECN + BECN set in byte 4.
        let payload = bth(0x04, 0x000001, 5, 0x00, 0xc0, 0x00);
        let mut d = dis();
        dissect(&payload, &mut d, &DissectConfig::default());
        assert!(d.summary.info.contains("FECN"), "{}", d.summary.info);
        assert!(d.summary.info.contains("BECN"), "{}", d.summary.info);
        assert_eq!(extract(&d.tree, "infiniband.bth.fecn"), Some(&Value::Uint(1)));
        assert_eq!(extract(&d.tree, "infiniband.bth.becn"), Some(&Value::Uint(1)));
    }

    #[test]
    fn truncated_bth() {
        let payload = vec![0u8; 8];
        let mut d = dis();
        dissect(&payload, &mut d, &DissectConfig::default());
        assert_eq!(d.summary.protocol, "RoCE");
        assert!(d.summary.info.contains("truncated"), "{}", d.summary.info);
    }
}
