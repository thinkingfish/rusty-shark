//! Stateless per-packet dissection. Each `dissect()` call is independent of
//! every other, which is what makes parallel dissection safe. Reassembly,
//! conversation tracking, and TCP stream following are deliberately out of
//! scope — they'd need ordered, stateful processing.
//!
//! Each dissector produces two things in a single pass:
//!   - the summary columns (`Summary`) shown in the default one-line output;
//!   - a protocol detail tree (`Vec<Node>`) shown by `-V` and queried by `-e`.
//!
//! The summary columns match tshark's default:
//!   No. | Time | Source | Destination | Protocol | Length | Info

use std::fmt::Write;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::field::{Node, Value};
use crate::pcap::{LinkType, RawPacket};

#[derive(Debug, Clone)]
pub struct Summary {
    pub src: String,
    pub dst: String,
    pub protocol: &'static str,
    pub info: String,
    pub length: u32,
}

impl Summary {
    fn new(length: u32) -> Self {
        Self {
            src: String::new(),
            dst: String::new(),
            protocol: "UNKNOWN",
            info: String::new(),
            length,
        }
    }
}

/// Per-run dissection options that individual dissectors consult.
#[derive(Debug, Clone, Copy, Default)]
pub struct DissectConfig {
    /// Force NVMe/RDMA decode of every RC/UC SEND capsule (`--nvme`).
    /// NVMe-oF Fabrics capsules are auto-detected regardless.
    pub nvme_force: bool,
}

/// The full result of dissecting one packet: summary columns plus the
/// protocol detail tree (a flat list of protocol-layer nodes, each with
/// field children — matching tshark's `-V` layout where protocol layers
/// are siblings at the left margin).
pub struct Dissection {
    pub summary: Summary,
    pub tree: Vec<Node>,
}

impl Dissection {
    fn new(length: u32) -> Self {
        Self {
            summary: Summary::new(length),
            tree: Vec::new(),
        }
    }
}

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_FLOW_CONTROL: u16 = 0x8808; // IEEE 802.3x PAUSE / 802.1Qbb PFC
const ETHERTYPE_ROCE: u16 = 0x8915; // RoCEv1: GRH + BTH directly over Ethernet

const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMPV6: u8 = 58;

pub fn dissect(pkt: &RawPacket, cfg: &DissectConfig) -> Dissection {
    let mut d = Dissection::new(pkt.orig_len);
    let data = &pkt.data[..];
    match pkt.link_type {
        LinkType::Ethernet => dissect_ethernet(data, &mut d, cfg),
        LinkType::RawIp => dissect_ip_auto(data, &mut d, cfg),
        LinkType::Null => dissect_null(data, &mut d, cfg),
        LinkType::LinuxSll => dissect_linux_sll(data, &mut d, cfg),
        LinkType::Infiniband => crate::roce::dissect_lrh(data, &mut d, cfg),
        LinkType::Other(n) => {
            d.summary.protocol = "LINK";
            d.summary.info = format!("unsupported DLT {n}, {} bytes", data.len());
        }
    }
    d
}

fn ethertype_name(etype: u16) -> &'static str {
    match etype {
        ETHERTYPE_IPV4 => "IPv4",
        ETHERTYPE_IPV6 => "IPv6",
        ETHERTYPE_ARP => "ARP",
        ETHERTYPE_VLAN => "802.1Q Virtual LAN",
        ETHERTYPE_FLOW_CONTROL => "MAC Control",
        ETHERTYPE_ROCE => "RoCE",
        _ => "Unknown",
    }
}

/// Human name for an ECN codepoint (the low 2 bits of the IP DS field).
/// Central to RoCE congestion control (DCQCN): CE marking drives CNPs.
fn ecn_name(ecn: u8) -> &'static str {
    match ecn & 0x03 {
        0 => "Not-ECT",
        1 => "ECT(1)",
        2 => "ECT(0)",
        3 => "CE",
        _ => unreachable!(),
    }
}

fn dissect_ethernet(data: &[u8], d: &mut Dissection, cfg: &DissectConfig) {
    if data.len() < 14 {
        d.summary.protocol = "ETH";
        d.summary.info = "truncated ethernet header".into();
        return;
    }
    let dst = fmt_mac(&data[0..6]);
    let src = fmt_mac(&data[6..12]);
    let mut etype = u16::from_be_bytes([data[12], data[13]]);
    let mut off = 14usize;

    // One level of VLAN is enough for now; nested VLANs fall through.
    if etype == ETHERTYPE_VLAN && data.len() >= off + 4 {
        etype = u16::from_be_bytes([data[off + 2], data[off + 3]]);
        off += 4;
    }

    d.summary.protocol = "ETH";
    d.summary.src = src.clone();
    d.summary.dst = dst.clone();

    let mut node = Node::proto(format!("Ethernet II, Src: {src}, Dst: {dst}"));
    node.add("eth.dst", Value::Str(dst.clone()), format!("Destination: {dst}"));
    node.add("eth.src", Value::Str(src.clone()), format!("Source: {src}"));
    node.add(
        "eth.type",
        Value::Uint(etype as u64),
        format!("Type: {} (0x{etype:04x})", ethertype_name(etype)),
    );
    d.tree.push(node);

    let payload = &data[off.min(data.len())..];
    match etype {
        ETHERTYPE_IPV4 => dissect_ipv4(payload, d, cfg),
        ETHERTYPE_IPV6 => dissect_ipv6(payload, d, cfg),
        ETHERTYPE_ARP => dissect_arp(payload, d),
        ETHERTYPE_FLOW_CONTROL => dissect_flow_control(payload, d),
        // RoCEv1: the InfiniBand GRH + BTH ride directly on Ethernet.
        ETHERTYPE_ROCE => crate::roce::dissect_grh(payload, d, cfg, "RoCE"),
        other => {
            d.summary.protocol = "ETH";
            if d.summary.info.is_empty() {
                d.summary.info = format!("ethertype 0x{other:04x}");
            }
        }
    }
}

/// MAC Control frames (ethertype 0x8808): IEEE 802.3x PAUSE and the
/// per-priority variant 802.1Qbb PFC. On a lossless RoCE fabric these are
/// how a congested port tells its upstream neighbour to hold off, so
/// making them visible is central to diagnosing RoCE stalls.
fn dissect_flow_control(data: &[u8], d: &mut Dissection) {
    if data.len() < 2 {
        d.summary.protocol = "MAC CTRL";
        d.summary.info = "truncated MAC Control frame".into();
        return;
    }
    let opcode = u16::from_be_bytes([data[0], data[1]]);
    match opcode {
        0x0001 => dissect_pause(data, d),
        0x0101 => dissect_pfc(data, d),
        other => {
            d.summary.protocol = "MAC CTRL";
            d.summary.info = format!("opcode 0x{other:04x}");
            let mut node = Node::proto("MAC Control");
            node.add(
                "mac.control.opcode",
                Value::Uint(other as u64),
                format!("Opcode: 0x{other:04x}"),
            );
            d.tree.push(node);
        }
    }
}

/// IEEE 802.3x global PAUSE: a single pause time in quanta (512 bit-times).
fn dissect_pause(data: &[u8], d: &mut Dissection) {
    d.summary.protocol = "PAUSE";
    let quanta = if data.len() >= 4 {
        u16::from_be_bytes([data[2], data[3]])
    } else {
        0
    };
    d.summary.info = format!("MAC PAUSE: quanta={quanta}");

    let mut node = Node::proto("MAC Control: Pause");
    node.add(
        "mac.control.opcode",
        Value::Uint(0x0001),
        "Opcode: Pause (0x0001)",
    );
    node.add(
        "mac.control.pause.time",
        Value::Uint(quanta as u64),
        format!("Pause Time: {quanta} quanta"),
    );
    d.tree.push(node);
}

/// IEEE 802.1Qbb Priority Flow Control: a class-enable vector selects which
/// of the 8 priority classes are paused, each with its own time in quanta.
fn dissect_pfc(data: &[u8], d: &mut Dissection) {
    d.summary.protocol = "PFC";
    if data.len() < 4 {
        d.summary.info = "truncated PFC frame".into();
        return;
    }
    // data[2] is reserved (MS byte of the enable field); data[3] carries
    // the class-enable vector, one bit per priority 0..7. Eight 2-byte
    // time values follow at data[4..].
    let enable = data[3];

    let mut node = Node::proto("MAC Control: Priority Flow Control (PFC)");
    node.add("mac.control.opcode", Value::Uint(0x0101), "Opcode: PFC (0x0101)");
    node.add(
        "pfc.enable",
        Value::Uint(enable as u64),
        format!("Class Enable Vector: 0x{enable:02x}"),
    );

    // Static abbreviations, one per priority class (no per-packet alloc).
    const PFC_TIME_ABBREV: [&str; 8] = [
        "pfc.time.prio0",
        "pfc.time.prio1",
        "pfc.time.prio2",
        "pfc.time.prio3",
        "pfc.time.prio4",
        "pfc.time.prio5",
        "pfc.time.prio6",
        "pfc.time.prio7",
    ];
    let mut paused: Vec<String> = Vec::new();
    for class in 0..8u8 {
        let time = if data.len() >= 4 + 2 * (class as usize + 1) {
            let o = 4 + 2 * class as usize;
            u16::from_be_bytes([data[o], data[o + 1]])
        } else {
            0
        };
        let enabled = enable & (1 << class) != 0;
        node.add(
            PFC_TIME_ABBREV[class as usize],
            Value::Uint(time as u64),
            format!(
                "Priority {class}: {} time={time}",
                if enabled { "enabled" } else { "disabled" }
            ),
        );
        if enabled {
            paused.push(format!("P{class}={time}"));
        }
    }

    d.summary.info = if paused.is_empty() {
        "PFC: no classes paused".to_string()
    } else {
        format!("PFC pause: {}", paused.join(" "))
    };
    d.tree.push(node);
}

fn dissect_null(data: &[u8], d: &mut Dissection, cfg: &DissectConfig) {
    // BSD loopback: 4-byte protocol family, host byte order. 2 = IPv4,
    // 24/28/30 = IPv6 depending on platform. Accept common values.
    if data.len() < 4 {
        d.summary.protocol = "NULL";
        return;
    }
    let fam_le = u32::from_le_bytes(data[0..4].try_into().unwrap());
    let fam_be = u32::from_be_bytes(data[0..4].try_into().unwrap());
    let payload = &data[4..];
    match (fam_le, fam_be) {
        (2, _) | (_, 2) => dissect_ipv4(payload, d, cfg),
        (24, _) | (_, 24) | (28, _) | (_, 28) | (30, _) | (_, 30) => dissect_ipv6(payload, d, cfg),
        _ => {
            d.summary.protocol = "NULL";
            d.summary.info = format!("family 0x{fam_le:08x}");
        }
    }
}

fn dissect_linux_sll(data: &[u8], d: &mut Dissection, cfg: &DissectConfig) {
    if data.len() < 16 {
        d.summary.protocol = "SLL";
        return;
    }
    let etype = u16::from_be_bytes([data[14], data[15]]);
    let payload = &data[16..];
    match etype {
        ETHERTYPE_IPV4 => dissect_ipv4(payload, d, cfg),
        ETHERTYPE_IPV6 => dissect_ipv6(payload, d, cfg),
        ETHERTYPE_ARP => dissect_arp(payload, d),
        other => {
            d.summary.protocol = "SLL";
            d.summary.info = format!("ethertype 0x{other:04x}");
        }
    }
}

fn dissect_ip_auto(data: &[u8], d: &mut Dissection, cfg: &DissectConfig) {
    if data.is_empty() {
        return;
    }
    match data[0] >> 4 {
        4 => dissect_ipv4(data, d, cfg),
        6 => dissect_ipv6(data, d, cfg),
        _ => {
            d.summary.protocol = "IP";
            d.summary.info = format!("unknown IP version {}", data[0] >> 4);
        }
    }
}

fn ip_proto_name(proto: u8) -> &'static str {
    match proto {
        IPPROTO_ICMP => "ICMP",
        IPPROTO_TCP => "TCP",
        IPPROTO_UDP => "UDP",
        IPPROTO_ICMPV6 => "IPv6-ICMP",
        _ => "Unknown",
    }
}

fn dissect_ipv4(data: &[u8], d: &mut Dissection, cfg: &DissectConfig) {
    if data.len() < 20 {
        d.summary.protocol = "IPv4";
        d.summary.info = "truncated IPv4 header".into();
        return;
    }
    let ihl = (data[0] & 0x0f) as usize * 4;
    if ihl < 20 || data.len() < ihl {
        d.summary.protocol = "IPv4";
        d.summary.info = "bad IPv4 header length".into();
        return;
    }
    let total_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    let ttl = data[8];
    let proto = data[9];
    let ecn = data[1] & 0x03;
    let src = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
    d.summary.src = src.to_string();
    d.summary.dst = dst.to_string();
    d.summary.protocol = "IPv4";

    let mut node = Node::proto(format!(
        "Internet Protocol Version 4, Src: {src}, Dst: {dst}"
    ));
    node.add("ip.version", Value::Uint(4), "Version: 4");
    node.add(
        "ip.hdr_len",
        Value::Uint(ihl as u64),
        format!("Header Length: {ihl} bytes ({})", ihl / 4),
    );
    node.add(
        "ip.dsfield.ecn",
        Value::Uint(ecn as u64),
        format!("ECN: 0x{ecn:02x} ({})", ecn_name(ecn)),
    );
    node.add(
        "ip.len",
        Value::Uint(total_len as u64),
        format!("Total Length: {total_len}"),
    );
    node.add("ip.ttl", Value::Uint(ttl as u64), format!("Time to Live: {ttl}"));
    node.add(
        "ip.proto",
        Value::Uint(proto as u64),
        format!("Protocol: {} ({proto})", ip_proto_name(proto)),
    );
    node.add(
        "ip.src",
        Value::Str(src.to_string()),
        format!("Source Address: {src}"),
    );
    node.add(
        "ip.dst",
        Value::Str(dst.to_string()),
        format!("Destination Address: {dst}"),
    );
    d.tree.push(node);

    // Reject payload beyond total length (but don't fail if total_len is
    // zero, which happens with TCP segmentation offload captures).
    let end = if total_len == 0 {
        data.len()
    } else {
        total_len.min(data.len())
    };
    let payload = &data[ihl..end.max(ihl)];

    match proto {
        IPPROTO_ICMP => dissect_icmp(payload, d),
        IPPROTO_TCP => dissect_tcp(payload, d),
        IPPROTO_UDP => dissect_udp(payload, d, false, cfg),
        other => {
            d.summary.info = format!("proto {other}");
        }
    }
}

fn dissect_ipv6(data: &[u8], d: &mut Dissection, cfg: &DissectConfig) {
    if data.len() < 40 {
        d.summary.protocol = "IPv6";
        d.summary.info = "truncated IPv6 header".into();
        return;
    }
    let next_header = data[6];
    let hop_limit = data[7];
    let payload_len = u16::from_be_bytes([data[4], data[5]]) as usize;
    // Traffic class spans the low nibble of byte 0 and high nibble of byte
    // 1; the ECN codepoint is its low 2 bits.
    let traffic_class = ((data[0] & 0x0f) << 4) | (data[1] >> 4);
    let ecn = traffic_class & 0x03;
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&data[8..24]).unwrap());
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&data[24..40]).unwrap());
    d.summary.src = src.to_string();
    d.summary.dst = dst.to_string();
    d.summary.protocol = "IPv6";

    let mut node = Node::proto(format!(
        "Internet Protocol Version 6, Src: {src}, Dst: {dst}"
    ));
    node.add("ipv6.version", Value::Uint(6), "Version: 6");
    node.add(
        "ipv6.dsfield.ecn",
        Value::Uint(ecn as u64),
        format!("ECN: 0x{ecn:02x} ({})", ecn_name(ecn)),
    );
    node.add(
        "ipv6.plen",
        Value::Uint(payload_len as u64),
        format!("Payload Length: {payload_len}"),
    );
    node.add(
        "ipv6.nxt",
        Value::Uint(next_header as u64),
        format!("Next Header: {} ({next_header})", ip_proto_name(next_header)),
    );
    node.add(
        "ipv6.hlim",
        Value::Uint(hop_limit as u64),
        format!("Hop Limit: {hop_limit}"),
    );
    node.add(
        "ipv6.src",
        Value::Str(src.to_string()),
        format!("Source Address: {src}"),
    );
    node.add(
        "ipv6.dst",
        Value::Str(dst.to_string()),
        format!("Destination Address: {dst}"),
    );
    d.tree.push(node);

    let end = (40 + payload_len).min(data.len());
    let payload = &data[40..end];
    match next_header {
        IPPROTO_TCP => dissect_tcp(payload, d),
        IPPROTO_UDP => dissect_udp(payload, d, true, cfg),
        IPPROTO_ICMPV6 => dissect_icmpv6(payload, d),
        other => {
            d.summary.info = format!("next header {other}");
        }
    }
}

fn dissect_arp(data: &[u8], d: &mut Dissection) {
    d.summary.protocol = "ARP";
    if data.len() < 28 {
        d.summary.info = "truncated ARP packet".into();
        return;
    }
    let op = u16::from_be_bytes([data[6], data[7]]);
    let sha = fmt_mac(&data[8..14]);
    let spa = Ipv4Addr::new(data[14], data[15], data[16], data[17]);
    let tha = fmt_mac(&data[18..24]);
    let tpa = Ipv4Addr::new(data[24], data[25], data[26], data[27]);
    d.summary.src = spa.to_string();
    d.summary.dst = tpa.to_string();
    d.summary.info = match op {
        1 => format!("Who has {tpa}? Tell {spa}"),
        2 => format!("{spa} is at {sha}"),
        3 => format!("Reverse request for {tha}"),
        4 => format!("Reverse reply: {tpa} is at {tha}"),
        other => format!("opcode {other}"),
    };

    let mut node = Node::proto("Address Resolution Protocol");
    node.add("arp.opcode", Value::Uint(op as u64), format!("Opcode: {op}"));
    node.add(
        "arp.src.hw_mac",
        Value::Str(sha.clone()),
        format!("Sender MAC address: {sha}"),
    );
    node.add(
        "arp.src.proto_ipv4",
        Value::Str(spa.to_string()),
        format!("Sender IP address: {spa}"),
    );
    node.add(
        "arp.dst.hw_mac",
        Value::Str(tha.clone()),
        format!("Target MAC address: {tha}"),
    );
    node.add(
        "arp.dst.proto_ipv4",
        Value::Str(tpa.to_string()),
        format!("Target IP address: {tpa}"),
    );
    d.tree.push(node);
}

fn dissect_tcp(data: &[u8], d: &mut Dissection) {
    if data.len() < 20 {
        d.summary.protocol = "TCP";
        d.summary.info = "truncated TCP header".into();
        return;
    }
    let sport = u16::from_be_bytes([data[0], data[1]]);
    let dport = u16::from_be_bytes([data[2], data[3]]);
    let seq = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ack = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let data_off = ((data[12] >> 4) as usize) * 4;
    let flags = data[13];
    let window = u16::from_be_bytes([data[14], data[15]]);
    let payload_len = data.len().saturating_sub(data_off);

    d.summary.protocol = "TCP";
    let mut flag_names = String::new();
    let mut info = String::with_capacity(48);
    let _ = write!(&mut info, "{sport} \u{2192} {dport} ");
    info.push('[');
    let mut first = true;
    for (bit, name) in [
        (0x01u8, "FIN"),
        (0x02, "SYN"),
        (0x04, "RST"),
        (0x08, "PSH"),
        (0x10, "ACK"),
        (0x20, "URG"),
        (0x40, "ECE"),
        (0x80, "CWR"),
    ] {
        if flags & bit != 0 {
            if !first {
                info.push_str(", ");
                flag_names.push_str(", ");
            }
            info.push_str(name);
            flag_names.push_str(name);
            first = false;
        }
    }
    info.push(']');
    let _ = write!(
        &mut info,
        " Seq={seq} Ack={ack} Win={window} Len={payload_len}"
    );
    d.summary.info = info;

    let mut node = Node::proto(format!(
        "Transmission Control Protocol, Src Port: {sport}, Dst Port: {dport}, Seq: {seq}, Len: {payload_len}"
    ));
    node.add(
        "tcp.srcport",
        Value::Uint(sport as u64),
        format!("Source Port: {sport}"),
    );
    node.add(
        "tcp.dstport",
        Value::Uint(dport as u64),
        format!("Destination Port: {dport}"),
    );
    node.add("tcp.seq", Value::Uint(seq as u64), format!("Sequence Number: {seq}"));
    node.add(
        "tcp.ack",
        Value::Uint(ack as u64),
        format!("Acknowledgment Number: {ack}"),
    );
    node.add(
        "tcp.flags",
        Value::Uint(flags as u64),
        format!("Flags: 0x{flags:03x} [{flag_names}]"),
    );
    node.add(
        "tcp.window_size",
        Value::Uint(window as u64),
        format!("Window: {window}"),
    );
    node.add(
        "tcp.len",
        Value::Uint(payload_len as u64),
        format!("TCP payload Length: {payload_len}"),
    );
    d.tree.push(node);
}

fn dissect_udp(data: &[u8], d: &mut Dissection, _is_ipv6: bool, cfg: &DissectConfig) {
    if data.len() < 8 {
        d.summary.protocol = "UDP";
        d.summary.info = "truncated UDP header".into();
        return;
    }
    let sport = u16::from_be_bytes([data[0], data[1]]);
    let dport = u16::from_be_bytes([data[2], data[3]]);
    let length = u16::from_be_bytes([data[4], data[5]]);
    d.summary.protocol = "UDP";
    d.summary.info = format!("{sport} \u{2192} {dport}  Len={}", length.saturating_sub(8));

    let mut node = Node::proto(format!(
        "User Datagram Protocol, Src Port: {sport}, Dst Port: {dport}"
    ));
    node.add(
        "udp.srcport",
        Value::Uint(sport as u64),
        format!("Source Port: {sport}"),
    );
    node.add(
        "udp.dstport",
        Value::Uint(dport as u64),
        format!("Destination Port: {dport}"),
    );
    node.add(
        "udp.length",
        Value::Uint(length as u64),
        format!("Length: {length}"),
    );
    d.tree.push(node);

    // A couple of well-known upper-layer labels so output is slightly less
    // opaque. We don't attempt to decode payloads.
    let payload = &data[8..];
    if dport == crate::roce::ROCE_V2_UDP_PORT || sport == crate::roce::ROCE_V2_UDP_PORT {
        // RoCEv2: InfiniBand transport over UDP/4791. The destination port
        // is the reliable indicator; the source port is flow entropy.
        crate::roce::dissect(payload, d, cfg);
    } else if sport == 53 || dport == 53 {
        dissect_dns(payload, d);
    } else if sport == 67 || sport == 68 || dport == 67 || dport == 68 {
        d.summary.protocol = "DHCP";
    } else if sport == 123 || dport == 123 {
        d.summary.protocol = "NTP";
    } else if sport == 5353 || dport == 5353 {
        d.summary.protocol = "MDNS";
    }
}

fn dissect_icmp(data: &[u8], d: &mut Dissection) {
    d.summary.protocol = "ICMP";
    if data.len() < 4 {
        d.summary.info = "truncated".into();
        return;
    }
    let ty = data[0];
    let code = data[1];
    d.summary.info = match (ty, code) {
        (0, _) => "Echo (ping) reply".into(),
        (3, _) => format!("Destination unreachable (code {code})"),
        (8, _) => "Echo (ping) request".into(),
        (11, _) => format!("Time-to-live exceeded (code {code})"),
        _ => format!("type {ty} code {code}"),
    };

    let mut node = Node::proto("Internet Control Message Protocol");
    node.add("icmp.type", Value::Uint(ty as u64), format!("Type: {ty}"));
    node.add("icmp.code", Value::Uint(code as u64), format!("Code: {code}"));
    d.tree.push(node);
}

fn dissect_icmpv6(data: &[u8], d: &mut Dissection) {
    d.summary.protocol = "ICMPv6";
    if data.len() < 4 {
        d.summary.info = "truncated".into();
        return;
    }
    let ty = data[0];
    d.summary.info = match ty {
        128 => "Echo Request".into(),
        129 => "Echo Reply".into(),
        133 => "Router Solicitation".into(),
        134 => "Router Advertisement".into(),
        135 => "Neighbor Solicitation".into(),
        136 => "Neighbor Advertisement".into(),
        137 => "Redirect".into(),
        _ => format!("type {ty}"),
    };

    let mut node = Node::proto("Internet Control Message Protocol v6");
    node.add("icmpv6.type", Value::Uint(ty as u64), format!("Type: {ty}"));
    d.tree.push(node);
}

fn dissect_dns(data: &[u8], d: &mut Dissection) {
    d.summary.protocol = "DNS";
    if data.len() < 12 {
        d.summary.info = "truncated".into();
        return;
    }
    let txid = u16::from_be_bytes([data[0], data[1]]);
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let qd = u16::from_be_bytes([data[4], data[5]]);
    let an = u16::from_be_bytes([data[6], data[7]]);
    let qr = flags >> 15;
    let op = (flags >> 11) & 0x0f;
    let rcode = flags & 0x0f;
    let kind = if qr == 0 { "query" } else { "response" };
    let opname = match op {
        0 => "standard",
        1 => "inverse",
        2 => "status",
        4 => "notify",
        5 => "update",
        _ => "other",
    };
    let qname = parse_first_qname(data).unwrap_or_default();
    let mut info = format!("0x{txid:04x} {opname} {kind} qd={qd} an={an} rcode={rcode}");
    if !qname.is_empty() {
        let _ = write!(&mut info, " {qname}");
    }
    d.summary.info = info;

    let mut node = Node::proto("Domain Name System");
    node.add(
        "dns.id",
        Value::Uint(txid as u64),
        format!("Transaction ID: 0x{txid:04x}"),
    );
    node.add(
        "dns.flags.response",
        Value::Uint(qr as u64),
        format!("Response: {}", if qr == 0 { "Message is a query" } else { "Message is a response" }),
    );
    if !qname.is_empty() {
        node.add(
            "dns.qry.name",
            Value::Str(qname.clone()),
            format!("Name: {qname}"),
        );
    }
    d.tree.push(node);
}

fn parse_first_qname(dns: &[u8]) -> Option<String> {
    if dns.len() < 12 {
        return None;
    }
    let mut i = 12usize;
    let mut out = String::new();
    // No compression in the question section per RFC 1035, so we just
    // walk labels until we hit a zero length octet.
    while i < dns.len() {
        let n = dns[i] as usize;
        if n == 0 {
            return if out.is_empty() { None } else { Some(out) };
        }
        // Refuse compression pointers here (question section shouldn't have
        // them, but stay defensive).
        if n & 0xc0 != 0 {
            return None;
        }
        i += 1;
        if i + n > dns.len() {
            return None;
        }
        if !out.is_empty() {
            out.push('.');
        }
        for &b in &dns[i..i + n] {
            if b.is_ascii_graphic() {
                out.push(b as char);
            } else {
                out.push('?');
            }
        }
        i += n;
    }
    None
}

fn fmt_mac(b: &[u8]) -> String {
    debug_assert_eq!(b.len(), 6);
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::extract;

    fn raw(data: Vec<u8>) -> RawPacket {
        let len = data.len() as u32;
        RawPacket {
            ts_sec: 0,
            ts_nsec: 0,
            orig_len: len,
            link_type: LinkType::Ethernet,
            data,
        }
    }

    /// Build an Ethernet + IPv4 + TCP SYN frame from 192.168.0.1:55555 to
    /// 192.168.0.2:443, seq=1.
    fn tcp_syn_frame() -> Vec<u8> {
        let mut eth = vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // dst mac
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // src mac
            0x08, 0x00, // IPv4 ethertype
        ];
        let ipv4 = [
            0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00,
            192, 168, 0, 1,
            192, 168, 0, 2,
        ];
        let tcp = [
            0xd9, 0x03, 0x01, 0xbb, // sport 55555 dport 443
            0x00, 0x00, 0x00, 0x01, // seq 1
            0x00, 0x00, 0x00, 0x00, // ack 0
            0x50, 0x02,              // data-off 5 * 4, flags SYN
            0xfa, 0xf0,              // window 64240
            0x00, 0x00, 0x00, 0x00,  // checksum + urg
        ];
        eth.extend_from_slice(&ipv4);
        eth.extend_from_slice(&tcp);
        eth
    }

    #[test]
    fn dissect_tcp_syn_ipv4_over_ethernet() {
        let pkt = raw(tcp_syn_frame());
        let d = dissect(&pkt, &DissectConfig::default());
        let s = &d.summary;
        assert_eq!(s.protocol, "TCP");
        assert_eq!(s.src, "192.168.0.1");
        assert_eq!(s.dst, "192.168.0.2");
        assert!(s.info.contains("55555"));
        assert!(s.info.contains("443"));
        assert!(s.info.contains("[SYN]"));
    }

    #[test]
    fn tree_has_named_fields() {
        let pkt = raw(tcp_syn_frame());
        let d = dissect(&pkt, &DissectConfig::default());
        // Protocol layers are siblings at the top level.
        assert_eq!(d.tree.len(), 3); // Ethernet, IPv4, TCP
        assert_eq!(
            extract(&d.tree, "ip.src"),
            Some(&Value::Str("192.168.0.1".into()))
        );
        assert_eq!(extract(&d.tree, "tcp.dstport"), Some(&Value::Uint(443)));
        assert_eq!(extract(&d.tree, "tcp.srcport"), Some(&Value::Uint(55555)));
        assert_eq!(extract(&d.tree, "eth.type"), Some(&Value::Uint(0x0800)));
    }

    #[test]
    fn dissect_arp_who_has() {
        let mut eth = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
            0x08, 0x06,
        ];
        let arp = [
            0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, // hw/proto types, opcode=request
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05,             // sha
            10, 0, 0, 1,                                     // spa
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,             // tha
            10, 0, 0, 2,                                     // tpa
        ];
        eth.extend_from_slice(&arp);
        let pkt = raw(eth);
        let d = dissect(&pkt, &DissectConfig::default());
        assert_eq!(d.summary.protocol, "ARP");
        assert_eq!(d.summary.src, "10.0.0.1");
        assert_eq!(d.summary.dst, "10.0.0.2");
        assert!(d.summary.info.contains("Who has 10.0.0.2"));
        assert_eq!(
            extract(&d.tree, "arp.src.proto_ipv4"),
            Some(&Value::Str("10.0.0.1".into()))
        );
    }

    #[test]
    fn dns_qname_decoded() {
        let mut dns = vec![
            0x12, 0x34, 0x01, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in ["www", "example", "com"] {
            dns.push(label.len() as u8);
            dns.extend_from_slice(label.as_bytes());
        }
        dns.push(0);
        dns.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE=A QCLASS=IN

        let name = parse_first_qname(&dns).unwrap();
        assert_eq!(name, "www.example.com");
    }

    #[test]
    fn truncated_tcp_header_handled() {
        // Ethernet + IPv4 header valid, TCP header only 8 bytes long.
        let mut frame = vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            0x08, 0x00,
        ];
        let ipv4 = [
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00,
            10, 0, 0, 1,
            10, 0, 0, 2,
        ];
        frame.extend_from_slice(&ipv4);
        frame.extend_from_slice(&[0; 8]); // too-short TCP
        let pkt = raw(frame);
        let d = dissect(&pkt, &DissectConfig::default());
        assert_eq!(d.summary.protocol, "TCP");
        assert!(d.summary.info.contains("truncated"));
    }
}
