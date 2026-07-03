//! Stateless per-packet dissection. Each `dissect()` call is independent of
//! every other, which is what makes parallel dissection safe. Reassembly,
//! conversation tracking, and TCP stream following are deliberately out of
//! scope for this MVP — they'd need ordered, stateful processing.
//!
//! The output is a `Summary` matching tshark's default columns:
//!   No. | Time | Source | Destination | Protocol | Length | Info

use std::fmt::Write;
use std::net::{Ipv4Addr, Ipv6Addr};

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

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const ETHERTYPE_VLAN: u16 = 0x8100;

const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMPV6: u8 = 58;

pub fn dissect(pkt: &RawPacket) -> Summary {
    let mut s = Summary::new(pkt.orig_len);
    let data = &pkt.data[..];
    match pkt.link_type {
        LinkType::Ethernet => dissect_ethernet(data, &mut s),
        LinkType::RawIp => dissect_ip_auto(data, &mut s),
        LinkType::Null => dissect_null(data, &mut s),
        LinkType::LinuxSll => dissect_linux_sll(data, &mut s),
        LinkType::Other(n) => {
            s.protocol = "LINK";
            s.info = format!("unsupported DLT {n}, {} bytes", data.len());
        }
    }
    s
}

fn dissect_ethernet(data: &[u8], s: &mut Summary) {
    if data.len() < 14 {
        s.protocol = "ETH";
        s.info = "truncated ethernet header".into();
        return;
    }
    let dst = fmt_mac(&data[0..6]);
    let src = fmt_mac(&data[6..12]);
    let mut etype = u16::from_be_bytes([data[12], data[13]]);
    let mut off = 14usize;

    // One level of VLAN is enough for the MVP; nested VLANs fall through.
    if etype == ETHERTYPE_VLAN && data.len() >= off + 4 {
        etype = u16::from_be_bytes([data[off + 2], data[off + 3]]);
        off += 4;
    }

    s.protocol = "ETH";
    s.src = src;
    s.dst = dst;

    let payload = &data[off.min(data.len())..];
    match etype {
        ETHERTYPE_IPV4 => dissect_ipv4(payload, s),
        ETHERTYPE_IPV6 => dissect_ipv6(payload, s),
        ETHERTYPE_ARP => dissect_arp(payload, s),
        other => {
            s.protocol = "ETH";
            if s.info.is_empty() {
                s.info = format!("ethertype 0x{other:04x}");
            }
        }
    }
}

fn dissect_null(data: &[u8], s: &mut Summary) {
    // BSD loopback: 4-byte protocol family, host byte order. 2 = IPv4,
    // 24/28/30 = IPv6 depending on platform. Accept common values.
    if data.len() < 4 {
        s.protocol = "NULL";
        return;
    }
    let fam_le = u32::from_le_bytes(data[0..4].try_into().unwrap());
    let fam_be = u32::from_be_bytes(data[0..4].try_into().unwrap());
    let payload = &data[4..];
    match (fam_le, fam_be) {
        (2, _) | (_, 2) => dissect_ipv4(payload, s),
        (24, _) | (_, 24) | (28, _) | (_, 28) | (30, _) | (_, 30) => dissect_ipv6(payload, s),
        _ => {
            s.protocol = "NULL";
            s.info = format!("family 0x{fam_le:08x}");
        }
    }
}

fn dissect_linux_sll(data: &[u8], s: &mut Summary) {
    if data.len() < 16 {
        s.protocol = "SLL";
        return;
    }
    let etype = u16::from_be_bytes([data[14], data[15]]);
    let payload = &data[16..];
    match etype {
        ETHERTYPE_IPV4 => dissect_ipv4(payload, s),
        ETHERTYPE_IPV6 => dissect_ipv6(payload, s),
        ETHERTYPE_ARP => dissect_arp(payload, s),
        other => {
            s.protocol = "SLL";
            s.info = format!("ethertype 0x{other:04x}");
        }
    }
}

fn dissect_ip_auto(data: &[u8], s: &mut Summary) {
    if data.is_empty() {
        return;
    }
    match data[0] >> 4 {
        4 => dissect_ipv4(data, s),
        6 => dissect_ipv6(data, s),
        _ => {
            s.protocol = "IP";
            s.info = format!("unknown IP version {}", data[0] >> 4);
        }
    }
}

fn dissect_ipv4(data: &[u8], s: &mut Summary) {
    if data.len() < 20 {
        s.protocol = "IPv4";
        s.info = "truncated IPv4 header".into();
        return;
    }
    let ihl = (data[0] & 0x0f) as usize * 4;
    if ihl < 20 || data.len() < ihl {
        s.protocol = "IPv4";
        s.info = "bad IPv4 header length".into();
        return;
    }
    let total_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    let proto = data[9];
    let src = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
    s.src = src.to_string();
    s.dst = dst.to_string();
    s.protocol = "IPv4";

    // Reject payload beyond total length (but don't fail if total_len is
    // zero, which happens with TCP segmentation offload captures).
    let end = if total_len == 0 {
        data.len()
    } else {
        total_len.min(data.len())
    };
    let payload = &data[ihl..end.max(ihl)];

    match proto {
        IPPROTO_ICMP => dissect_icmp(payload, s),
        IPPROTO_TCP => dissect_tcp(payload, s),
        IPPROTO_UDP => dissect_udp(payload, s, false),
        other => {
            s.info = format!("proto {other}");
        }
    }
}

fn dissect_ipv6(data: &[u8], s: &mut Summary) {
    if data.len() < 40 {
        s.protocol = "IPv6";
        s.info = "truncated IPv6 header".into();
        return;
    }
    let next_header = data[6];
    let payload_len = u16::from_be_bytes([data[4], data[5]]) as usize;
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&data[8..24]).unwrap());
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&data[24..40]).unwrap());
    s.src = src.to_string();
    s.dst = dst.to_string();
    s.protocol = "IPv6";
    let end = (40 + payload_len).min(data.len());
    let payload = &data[40..end];
    match next_header {
        IPPROTO_TCP => dissect_tcp(payload, s),
        IPPROTO_UDP => dissect_udp(payload, s, true),
        IPPROTO_ICMPV6 => dissect_icmpv6(payload, s),
        other => {
            s.info = format!("next header {other}");
        }
    }
}

fn dissect_arp(data: &[u8], s: &mut Summary) {
    s.protocol = "ARP";
    if data.len() < 28 {
        s.info = "truncated ARP packet".into();
        return;
    }
    let op = u16::from_be_bytes([data[6], data[7]]);
    let sha = fmt_mac(&data[8..14]);
    let spa = Ipv4Addr::new(data[14], data[15], data[16], data[17]);
    let tha = fmt_mac(&data[18..24]);
    let tpa = Ipv4Addr::new(data[24], data[25], data[26], data[27]);
    s.src = spa.to_string();
    s.dst = tpa.to_string();
    s.info = match op {
        1 => format!("Who has {tpa}? Tell {spa}"),
        2 => format!("{spa} is at {sha}"),
        3 => format!("Reverse request for {tha}"),
        4 => format!("Reverse reply: {tpa} is at {tha}"),
        other => format!("opcode {other}"),
    };
}

fn dissect_tcp(data: &[u8], s: &mut Summary) {
    if data.len() < 20 {
        s.protocol = "TCP";
        s.info = "truncated TCP header".into();
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

    s.protocol = "TCP";
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
            }
            info.push_str(name);
            first = false;
        }
    }
    info.push(']');
    let _ = write!(
        &mut info,
        " Seq={seq} Ack={ack} Win={window} Len={payload_len}"
    );
    s.info = info;
}

fn dissect_udp(data: &[u8], s: &mut Summary, _is_ipv6: bool) {
    if data.len() < 8 {
        s.protocol = "UDP";
        s.info = "truncated UDP header".into();
        return;
    }
    let sport = u16::from_be_bytes([data[0], data[1]]);
    let dport = u16::from_be_bytes([data[2], data[3]]);
    let length = u16::from_be_bytes([data[4], data[5]]);
    s.protocol = "UDP";
    s.info = format!("{sport} \u{2192} {dport}  Len={}", length.saturating_sub(8));

    // A couple of well-known upper-layer labels so output is slightly less
    // opaque. We don't attempt to decode payloads.
    let payload = &data[8..];
    if sport == 53 || dport == 53 {
        dissect_dns(payload, s);
    } else if sport == 67 || sport == 68 || dport == 67 || dport == 68 {
        s.protocol = "DHCP";
    } else if sport == 123 || dport == 123 {
        s.protocol = "NTP";
    } else if sport == 5353 || dport == 5353 {
        s.protocol = "MDNS";
    }
}

fn dissect_icmp(data: &[u8], s: &mut Summary) {
    s.protocol = "ICMP";
    if data.len() < 4 {
        s.info = "truncated".into();
        return;
    }
    let ty = data[0];
    let code = data[1];
    s.info = match (ty, code) {
        (0, _) => "Echo (ping) reply".into(),
        (3, _) => format!("Destination unreachable (code {code})"),
        (8, _) => "Echo (ping) request".into(),
        (11, _) => format!("Time-to-live exceeded (code {code})"),
        _ => format!("type {ty} code {code}"),
    };
}

fn dissect_icmpv6(data: &[u8], s: &mut Summary) {
    s.protocol = "ICMPv6";
    if data.len() < 4 {
        s.info = "truncated".into();
        return;
    }
    let ty = data[0];
    s.info = match ty {
        128 => "Echo Request".into(),
        129 => "Echo Reply".into(),
        133 => "Router Solicitation".into(),
        134 => "Router Advertisement".into(),
        135 => "Neighbor Solicitation".into(),
        136 => "Neighbor Advertisement".into(),
        137 => "Redirect".into(),
        _ => format!("type {ty}"),
    };
}

fn dissect_dns(data: &[u8], s: &mut Summary) {
    s.protocol = "DNS";
    if data.len() < 12 {
        s.info = "truncated".into();
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
    let mut info = format!(
        "0x{txid:04x} {opname} {kind} qd={qd} an={an} rcode={rcode}"
    );
    if !qname.is_empty() {
        let _ = write!(&mut info, " {qname}");
    }
    s.info = info;
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
        let s = dissect(&pkt);
        assert_eq!(s.protocol, "TCP");
        assert_eq!(s.src, "192.168.0.1");
        assert_eq!(s.dst, "192.168.0.2");
        assert!(s.info.contains("55555"));
        assert!(s.info.contains("443"));
        assert!(s.info.contains("[SYN]"));
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
        let s = dissect(&pkt);
        assert_eq!(s.protocol, "ARP");
        assert_eq!(s.src, "10.0.0.1");
        assert_eq!(s.dst, "10.0.0.2");
        assert!(s.info.contains("Who has 10.0.0.2"));
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
        let s = dissect(&pkt);
        assert_eq!(s.protocol, "TCP");
        assert!(s.info.contains("truncated"));
    }
}
