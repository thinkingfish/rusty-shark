use std::fs::File;
use std::io::{self, BufReader, Read};

use anyhow::{Context, Result, anyhow, bail};

const PCAP_MAGIC_US: u32 = 0xa1b2_c3d4;
const PCAP_MAGIC_US_SWAP: u32 = 0xd4c3_b2a1;
const PCAP_MAGIC_NS: u32 = 0xa1b2_3c4d;
const PCAP_MAGIC_NS_SWAP: u32 = 0x4d3c_b2a1;

/// Well-known pcap link-layer types (subset).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    Ethernet,     // 1  (DLT_EN10MB)
    RawIp,        // 101 (DLT_RAW)
    LinuxSll,     // 113 (DLT_LINUX_SLL)
    Null,         // 0   (DLT_NULL)
    Other(u32),
}

impl LinkType {
    fn from_u32(v: u32) -> Self {
        match v {
            0 => LinkType::Null,
            1 => LinkType::Ethernet,
            101 => LinkType::RawIp,
            113 => LinkType::LinuxSll,
            x => LinkType::Other(x),
        }
    }
}

/// A raw packet record pulled from the capture file. The caller owns the
/// bytes; dissection happens later, possibly on another thread.
#[derive(Debug, Clone)]
pub struct RawPacket {
    /// Timestamp seconds (since Unix epoch).
    pub ts_sec: u32,
    /// Sub-second component in nanoseconds.
    pub ts_nsec: u32,
    /// Original (on-wire) length.
    pub orig_len: u32,
    /// Captured bytes (may be truncated to snaplen).
    pub data: Vec<u8>,
}

/// Classic pcap file reader. Streams records one at a time from any
/// `Read` source.
pub struct PcapReader<R: Read> {
    inner: R,
    swap: bool,
    ns_precision: bool,
    link_type: LinkType,
}

impl PcapReader<BufReader<File>> {
    pub fn open(path: &str) -> Result<Self> {
        let file = File::open(path).with_context(|| format!("opening {path}"))?;
        Self::new(BufReader::with_capacity(1 << 20, file))
    }
}

impl<R: Read> PcapReader<R> {
    pub fn new(mut inner: R) -> Result<Self> {
        let mut hdr = [0u8; 24];
        inner
            .read_exact(&mut hdr)
            .context("reading pcap global header")?;

        let raw_magic = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
        let (swap, ns_precision) = match raw_magic {
            PCAP_MAGIC_US => (false, false),
            PCAP_MAGIC_NS => (false, true),
            PCAP_MAGIC_US_SWAP => (true, false),
            PCAP_MAGIC_NS_SWAP => (true, true),
            other => bail!("not a classic pcap file (magic = 0x{other:08x}); pcapng is not yet supported"),
        };

        // Fields at 4..8 version, 8..16 zone+sigfigs, 16..20 snaplen, 20..24 network.
        let link_raw = read_u32(&hdr[20..24], swap);
        Ok(Self {
            inner,
            swap,
            ns_precision,
            link_type: LinkType::from_u32(link_raw),
        })
    }

    pub fn link_type(&self) -> LinkType {
        self.link_type
    }

    /// Read the next record, or `Ok(None)` at EOF.
    pub fn next_packet(&mut self) -> Result<Option<RawPacket>> {
        let mut rec = [0u8; 16];
        match self.inner.read_exact(&mut rec) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e).context("reading pcap record header"),
        }
        let ts_sec = read_u32(&rec[0..4], self.swap);
        let ts_sub = read_u32(&rec[4..8], self.swap);
        let incl_len = read_u32(&rec[8..12], self.swap);
        let orig_len = read_u32(&rec[12..16], self.swap);

        // Guard against pathological incl_len values.
        if incl_len > 256 * 1024 * 1024 {
            return Err(anyhow!("implausible pcap record length: {incl_len}"));
        }

        let mut data = vec![0u8; incl_len as usize];
        self.inner
            .read_exact(&mut data)
            .context("reading pcap record payload")?;

        let ts_nsec = if self.ns_precision {
            ts_sub
        } else {
            // microseconds -> nanoseconds
            ts_sub.saturating_mul(1000)
        };

        Ok(Some(RawPacket {
            ts_sec,
            ts_nsec,
            orig_len,
            data,
        }))
    }
}

#[inline]
fn read_u32(b: &[u8], swap: bool) -> u32 {
    let v = u32::from_le_bytes(b.try_into().unwrap());
    if swap { v.swap_bytes() } else { v }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn build_pcap(magic: u32, records: &[(u32, u32, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&magic.to_le_bytes());
        buf.extend_from_slice(&2u16.to_le_bytes()); // major
        buf.extend_from_slice(&4u16.to_le_bytes()); // minor
        buf.extend_from_slice(&0u32.to_le_bytes()); // zone
        buf.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
        buf.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
        buf.extend_from_slice(&1u32.to_le_bytes()); // DLT = EN10MB
        for (ts_sec, ts_sub, data) in records {
            buf.extend_from_slice(&ts_sec.to_le_bytes());
            buf.extend_from_slice(&ts_sub.to_le_bytes());
            buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
            buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
            buf.extend_from_slice(data);
        }
        buf
    }

    #[test]
    fn round_trip_microsecond_pcap() {
        let payload = &[0xde, 0xad, 0xbe, 0xef];
        let buf = build_pcap(PCAP_MAGIC_US, &[(42, 500_000, payload)]);
        let mut r = PcapReader::new(Cursor::new(buf)).unwrap();
        assert_eq!(r.link_type(), LinkType::Ethernet);
        let pkt = r.next_packet().unwrap().unwrap();
        assert_eq!(pkt.ts_sec, 42);
        // 500_000 us -> 500_000_000 ns
        assert_eq!(pkt.ts_nsec, 500_000_000);
        assert_eq!(pkt.orig_len, 4);
        assert_eq!(pkt.data, payload);
        assert!(r.next_packet().unwrap().is_none());
    }

    #[test]
    fn round_trip_nanosecond_pcap() {
        let buf = build_pcap(PCAP_MAGIC_NS, &[(7, 123_456_789, b"x")]);
        let mut r = PcapReader::new(Cursor::new(buf)).unwrap();
        let pkt = r.next_packet().unwrap().unwrap();
        assert_eq!(pkt.ts_sec, 7);
        assert_eq!(pkt.ts_nsec, 123_456_789);
    }

    #[test]
    fn rejects_non_pcap() {
        let buf = b"not-a-pcap-file-header-xxxxxxxx".to_vec();
        let err = match PcapReader::new(Cursor::new(buf)) {
            Ok(_) => panic!("expected error"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("not a classic pcap"));
    }
}
