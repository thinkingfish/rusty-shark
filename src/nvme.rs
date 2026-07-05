//! NVMe over Fabrics / RDMA capsule dissection (milestone M6).
//!
//! NVMe/RDMA carries NVMe **capsules** over RDMA SEND operations:
//!   - a **command capsule** = a 64-byte Submission Queue Entry (SQE),
//!     optionally followed by in-capsule data, host → controller;
//!   - a **response capsule** = a 16-byte Completion Queue Entry (CQE),
//!     controller → host.
//!
//! Bulk data moves separately via RDMA READ/WRITE and isn't in the SEND.
//!
//! Detection is the hard part: nothing in a lone RDMA SEND says "this QP
//! is NVMe" — that's established at connection time (the Fabrics Connect),
//! which needs cross-packet QP state we don't yet track. So this module is
//! deliberately conservative:
//!   - **auto**: only claim a capsule as NVMe when it is unmistakably an
//!     NVMe-oF *Fabrics* command (SQE opcode 0x7F) — a very distinctive
//!     value that other SEND-based ULPs (iSER, SMB Direct) don't use;
//!   - **forced** (`--nvme`): decode every RC/UC SEND capsule as NVMe,
//!     for captures the user knows are NVMe/RDMA — this unlocks the I/O
//!     command fields (opcode, SLBA, NLB) and CQE status.
//!
//! All NVMe data structures are little-endian.

use std::fmt::Write;

use crate::field::{Node, Value};

/// Attempt to decode `capsule` (the RDMA SEND payload, ICRC already
/// stripped) as an NVMe capsule. On success appends fields to `parent`,
/// writes a summary fragment to `info`, and returns the protocol label
/// ("NVMeF" or "NVMe"); returns `None` if it declines to claim the bytes.
pub fn try_dissect(
    capsule: &[u8],
    force: bool,
    info: &mut String,
    parent: &mut Node,
) -> Option<&'static str> {
    // Command capsule: SQE is 64 bytes.
    if capsule.len() >= 64 {
        let opcode = capsule[0];
        if opcode == FABRICS_OPCODE {
            decode_fabrics(capsule, info, parent);
            return Some("NVMeF");
        }
        if force {
            decode_io_command(capsule, info, parent);
            return Some("NVMe");
        }
        return None;
    }
    // Response capsule: CQE is 16 bytes. Only decoded when forced — we
    // can't structurally confirm a CQE without command context.
    if force && capsule.len() >= 16 {
        decode_response(capsule, info, parent);
        return Some("NVMe");
    }
    None
}

const FABRICS_OPCODE: u8 = 0x7f;

fn le16(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}
fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}
fn le64(b: &[u8]) -> u64 {
    u64::from_le_bytes(b[0..8].try_into().unwrap())
}

fn fabrics_type_name(fctype: u8) -> &'static str {
    match fctype {
        0x00 => "Property Set",
        0x01 => "Connect",
        0x04 => "Property Get",
        0x05 => "Authentication Send",
        0x06 => "Authentication Receive",
        0x08 => "Disconnect",
        _ => "Unknown",
    }
}

fn decode_fabrics(sqe: &[u8], info: &mut String, parent: &mut Node) {
    // SQE: [0]=opcode(0x7F) [1]=flags [2..4]=CID [4]=Fabrics Command Type.
    let cid = le16(&sqe[2..4]);
    let fctype = sqe[4];
    let name = fabrics_type_name(fctype);

    let mut node = Node::proto(format!("NVMe over Fabrics — {name} command"));
    node.add(
        "nvme.cmd.opcode",
        Value::Uint(FABRICS_OPCODE as u64),
        "Opcode: Fabrics (0x7f)",
    );
    node.add(
        "nvmeof.fctype",
        Value::Uint(fctype as u64),
        format!("Fabrics Command Type: {name} (0x{fctype:02x})"),
    );
    node.add(
        "nvme.cmd.cid",
        Value::Uint(cid as u64),
        format!("Command Identifier: {cid}"),
    );
    parent.children.push(node);

    let _ = write!(info, " | NVMe-oF {name} CID={cid}");
}

fn io_opcode_name(opcode: u8) -> &'static str {
    // NVM command set (I/O). Admin opcodes overlap numerically; without
    // queue context we assume the I/O set, which dominates NVMe/RDMA data
    // traffic.
    match opcode {
        0x00 => "Flush",
        0x01 => "Write",
        0x02 => "Read",
        0x04 => "Write Uncorrectable",
        0x05 => "Compare",
        0x08 => "Write Zeroes",
        0x09 => "Dataset Management",
        0x0d => "Reservation Register",
        0x0e => "Reservation Report",
        _ => "Unknown",
    }
}

fn decode_io_command(sqe: &[u8], info: &mut String, parent: &mut Node) {
    let opcode = sqe[0];
    let cid = le16(&sqe[2..4]);
    let nsid = le32(&sqe[4..8]);
    let name = io_opcode_name(opcode);

    let mut node = Node::proto(format!("NVMe command — {name}"));
    node.add(
        "nvme.cmd.opcode",
        Value::Uint(opcode as u64),
        format!("Opcode: {name} (0x{opcode:02x})"),
    );
    node.add(
        "nvme.cmd.cid",
        Value::Uint(cid as u64),
        format!("Command Identifier: {cid}"),
    );
    node.add(
        "nvme.cmd.nsid",
        Value::Uint(nsid as u64),
        format!("Namespace Identifier: {nsid}"),
    );

    let _ = write!(info, " | NVMe {name} nsid={nsid} CID={cid}");

    // Read/Write carry the Starting LBA (CDW10-11) and Number of Logical
    // Blocks (CDW12 low 16 bits, 0-based) — the fields storage debugging
    // actually wants.
    if matches!(opcode, 0x01 | 0x02 | 0x04 | 0x05 | 0x08) && sqe.len() >= 52 {
        let slba = le64(&sqe[40..48]);
        let nlb = le16(&sqe[48..50]) as u32 + 1; // 0-based count
        node.add(
            "nvme.cmd.slba",
            Value::Uint(slba),
            format!("Starting LBA: {slba}"),
        );
        node.add(
            "nvme.cmd.nlb",
            Value::Uint(nlb as u64),
            format!("Number of Logical Blocks: {nlb}"),
        );
        let _ = write!(info, " SLBA={slba} NLB={nlb}");
    }

    parent.children.push(node);
}

fn decode_response(cqe: &[u8], info: &mut String, parent: &mut Node) {
    // CQE: [8..10]=SQ head [10..12]=SQID [12..14]=CID [14..16]=Status.
    let cid = le16(&cqe[12..14]);
    let status = le16(&cqe[14..16]);
    let phase = status & 0x1;
    let sc = (status >> 1) & 0xff; // Status Code
    let sct = (status >> 9) & 0x7; // Status Code Type
    let ok = sc == 0 && sct == 0;

    let mut node = Node::proto("NVMe response (CQE)");
    node.add(
        "nvme.cqe.cid",
        Value::Uint(cid as u64),
        format!("Command Identifier: {cid}"),
    );
    node.add(
        "nvme.cqe.status",
        Value::Uint(status as u64),
        format!("Status: 0x{status:04x} (SCT={sct} SC=0x{sc:02x}, phase={phase})"),
    );
    parent.children.push(node);

    let _ = write!(
        info,
        " | NVMe response CID={cid} status={}",
        if ok { "Success".to_string() } else { format!("SCT={sct} SC=0x{sc:02x}") }
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::extract;

    fn parent() -> Node {
        Node::proto("InfiniBand BTH")
    }

    fn fabrics_connect() -> Vec<u8> {
        let mut c = vec![0u8; 64];
        c[0] = 0x7f; // Fabrics opcode
        c[2] = 0x2a; // CID low = 42
        c[3] = 0x00;
        c[4] = 0x01; // fctype = Connect
        c
    }

    #[test]
    fn auto_detects_fabrics_connect() {
        let cap = fabrics_connect();
        let mut info = String::new();
        let mut node = parent();
        let label = try_dissect(&cap, false, &mut info, &mut node);
        assert_eq!(label, Some("NVMeF"));
        assert!(info.contains("Connect"), "{info}");
        assert!(info.contains("CID=42"), "{info}");
        assert_eq!(
            extract(std::slice::from_ref(&node), "nvmeof.fctype"),
            Some(&Value::Uint(0x01))
        );
    }

    #[test]
    fn auto_declines_plain_io_command() {
        // A Write command should NOT be auto-claimed (could be another ULP).
        let mut cap = vec![0u8; 64];
        cap[0] = 0x01; // Write
        let mut info = String::new();
        let mut node = parent();
        assert_eq!(try_dissect(&cap, false, &mut info, &mut node), None);
        assert!(info.is_empty());
    }

    #[test]
    fn forced_decodes_write_with_lba() {
        let mut cap = vec![0u8; 64];
        cap[0] = 0x01; // Write
        cap[2] = 0x07; // CID = 7
        cap[4] = 0x01; // NSID = 1
        cap[40..48].copy_from_slice(&0x1000u64.to_le_bytes()); // SLBA
        cap[48..50].copy_from_slice(&7u16.to_le_bytes()); // NLB = 7 (0-based) → 8
        let mut info = String::new();
        let mut node = parent();
        let label = try_dissect(&cap, true, &mut info, &mut node);
        assert_eq!(label, Some("NVMe"));
        assert!(info.contains("NVMe Write"), "{info}");
        assert_eq!(
            extract(std::slice::from_ref(&node), "nvme.cmd.slba"),
            Some(&Value::Uint(0x1000))
        );
        assert_eq!(
            extract(std::slice::from_ref(&node), "nvme.cmd.nlb"),
            Some(&Value::Uint(8))
        );
    }

    #[test]
    fn forced_decodes_response_cqe() {
        let mut cap = vec![0u8; 16];
        cap[12] = 0x07; // CID = 7
        cap[14] = 0x00; // status low
        cap[15] = 0x00; // status high → success, phase 0
        let mut info = String::new();
        let mut node = parent();
        let label = try_dissect(&cap, true, &mut info, &mut node);
        assert_eq!(label, Some("NVMe"));
        assert!(info.contains("NVMe response"), "{info}");
        assert!(info.contains("Success"), "{info}");
    }

    #[test]
    fn short_capsule_declined() {
        let cap = vec![0u8; 8];
        let mut info = String::new();
        let mut node = parent();
        assert_eq!(try_dissect(&cap, true, &mut info, &mut node), None);
    }
}
