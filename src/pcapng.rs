//! Minimal pcapng reader — enough to iterate Enhanced and Simple Packet
//! Blocks from files produced by tshark/dumpcap/tcpdump. Unhandled block
//! types are skipped by length.
//!
//! References: draft-tuexen-opsawg-pcapng.

use std::io::{self, Read};

use anyhow::{Context, Result, bail};

use crate::pcap::{LinkType, RawPacket, read_u16, read_u32};

const BT_SHB: u32 = 0x0a0d_0d0a;
const BT_IDB: u32 = 0x0000_0001;
const BT_SPB: u32 = 0x0000_0003;
const BT_EPB: u32 = 0x0000_0006;

const SHB_BOM: u32 = 0x1a2b_3c4d;

/// One interface described by an IDB. pcapng multiplexes packets from
/// multiple interfaces, each with its own link layer and timestamp
/// resolution; we index into this table by the EPB's `interface_id`.
#[derive(Debug, Clone, Copy)]
struct Interface {
    link_type: LinkType,
    /// Ticks per second the interface uses for its timestamps.
    ticks_per_sec: u64,
}

impl Interface {
    fn default_ethernet() -> Self {
        Self {
            link_type: LinkType::Ethernet,
            ticks_per_sec: 1_000_000, // pcapng default: microseconds
        }
    }
}

/// Streaming pcapng reader. Owns byte-order and per-interface state that
/// change across Section Header Blocks.
pub struct PcapNgReader<R: Read> {
    inner: R,
    swap: bool,
    interfaces: Vec<Interface>,
}

impl<R: Read> PcapNgReader<R> {
    #[allow(dead_code)] // stand-alone constructor kept for library use and tests
    pub fn new(mut inner: R) -> Result<Self> {
        let mut magic = [0u8; 4];
        inner.read_exact(&mut magic).context("reading pcapng magic")?;
        let m = u32::from_le_bytes(magic);
        if m != BT_SHB {
            bail!("not a pcapng file (magic = 0x{m:08x})");
        }
        Self::from_magic(inner)
    }

    /// Continue reading a pcapng SHB whose 4-byte magic has already been
    /// consumed and identified as `0x0a0d0d0a`.
    pub(crate) fn from_magic(mut inner: R) -> Result<Self> {
        // The rest of the SHB: total_length (4), byte_order_magic (4),
        // major (2), minor (2), section_length (8), options (variable),
        // trailer_total_length (4).
        //
        // Byte order is fixed by the BOM at offset 8 from the block
        // start, i.e. 4 bytes past the magic we already consumed.
        let mut prefix = [0u8; 8];
        inner
            .read_exact(&mut prefix)
            .context("reading pcapng SHB prefix")?;
        // Try both orderings for the BOM. block_total_length depends on
        // byte order too, so we read the BOM first.
        let bom_le = u32::from_le_bytes(prefix[4..8].try_into().unwrap());
        let bom_be = u32::from_be_bytes(prefix[4..8].try_into().unwrap());
        let swap = if bom_le == SHB_BOM {
            false
        } else if bom_be == SHB_BOM {
            true
        } else {
            bail!("pcapng SHB byte-order magic invalid (got 0x{bom_le:08x})");
        };
        let total_len = read_u32(&prefix[0..4], swap) as usize;
        if !(12..=(16 * 1024 * 1024)).contains(&total_len) {
            bail!("implausible pcapng SHB total length: {total_len}");
        }
        // Consume the rest of the SHB (major/minor/section_length/options/trailer).
        // We've already read 12 bytes (4 magic + 4 total_len + 4 BOM).
        let mut rest = vec![0u8; total_len - 12];
        inner
            .read_exact(&mut rest)
            .context("reading pcapng SHB body")?;
        // trailer at the end must match total_len.
        let trailer = read_u32(&rest[rest.len() - 4..], swap) as usize;
        if trailer != total_len {
            bail!("pcapng SHB trailer length mismatch: {trailer} vs {total_len}");
        }

        Ok(Self {
            inner,
            swap,
            interfaces: Vec::new(),
        })
    }

    /// Read the next Enhanced or Simple Packet Block, skipping other
    /// block types (interface descriptions, statistics, section headers,
    /// name resolution, custom, ...). Returns `Ok(None)` at EOF.
    pub fn next_packet(&mut self) -> Result<Option<RawPacket>> {
        loop {
            let mut hdr = [0u8; 8];
            match self.inner.read_exact(&mut hdr) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
                Err(e) => return Err(e).context("reading pcapng block header"),
            }
            let block_type = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
            let block_type = if self.swap {
                block_type.swap_bytes()
            } else {
                block_type
            };
            let total_len = read_u32(&hdr[4..8], self.swap) as usize;
            if !(12..=(256 * 1024 * 1024)).contains(&total_len) {
                bail!("implausible pcapng block length: {total_len}");
            }
            let body_len = total_len - 12;
            let mut body = vec![0u8; body_len];
            self.inner
                .read_exact(&mut body)
                .context("reading pcapng block body")?;
            let mut trailer = [0u8; 4];
            self.inner
                .read_exact(&mut trailer)
                .context("reading pcapng block trailer")?;
            let trailer_len = read_u32(&trailer, self.swap) as usize;
            if trailer_len != total_len {
                bail!(
                    "pcapng block trailer length mismatch: {trailer_len} vs {total_len}"
                );
            }

            match block_type {
                BT_SHB => {
                    // A new section resets endianness and interface
                    // table. Rare, but the spec allows it. For simplicity
                    // we only accept sections whose byte order matches
                    // the first one we saw.
                    self.interfaces.clear();
                    let bom = read_u32(&body[0..4], self.swap);
                    if bom != SHB_BOM {
                        bail!(
                            "pcapng section header block with foreign byte order not supported"
                        );
                    }
                }
                BT_IDB => {
                    let iface = self.parse_idb(&body)?;
                    self.interfaces.push(iface);
                }
                BT_EPB => {
                    return self.parse_epb(&body).map(Some);
                }
                BT_SPB => {
                    return self.parse_spb(&body).map(Some);
                }
                _ => {
                    // Skip: ISB, NRB, DSB, CB, etc.
                }
            }
        }
    }

    fn parse_idb(&self, body: &[u8]) -> Result<Interface> {
        if body.len() < 8 {
            bail!("truncated pcapng IDB body");
        }
        let link_type_raw = read_u16(&body[0..2], self.swap) as u32;
        // body[2..4] reserved; body[4..8] SnapLen. Options follow.
        let ticks_per_sec = self.parse_tsresol_option(&body[8..]).unwrap_or(1_000_000);
        Ok(Interface {
            link_type: LinkType::from_u32(link_type_raw),
            ticks_per_sec,
        })
    }

    fn parse_tsresol_option(&self, options: &[u8]) -> Option<u64> {
        // Options are TLV: option_code (2), option_length (2), value,
        // padded to 32-bit. Terminator is opt_endofopt (code 0).
        let mut i = 0;
        while i + 4 <= options.len() {
            let code = read_u16(&options[i..i + 2], self.swap);
            let len = read_u16(&options[i + 2..i + 4], self.swap) as usize;
            i += 4;
            if code == 0 {
                break; // opt_endofopt
            }
            if i + len > options.len() {
                break;
            }
            if code == 9 && len >= 1 {
                // if_tsresol
                let v = options[i];
                let ticks_per_sec = if v & 0x80 == 0 {
                    // base-10 resolution: 10^v ticks per second
                    let exp = (v & 0x7f) as u32;
                    10u64.checked_pow(exp)?
                } else {
                    // base-2 resolution: 2^v ticks per second
                    let exp = (v & 0x7f) as u32;
                    if exp >= 63 {
                        return None;
                    }
                    1u64 << exp
                };
                return Some(ticks_per_sec);
            }
            i += pad4(len);
        }
        None
    }

    fn parse_epb(&self, body: &[u8]) -> Result<RawPacket> {
        if body.len() < 20 {
            bail!("truncated pcapng EPB body");
        }
        let interface_id = read_u32(&body[0..4], self.swap) as usize;
        let ts_high = read_u32(&body[4..8], self.swap) as u64;
        let ts_low = read_u32(&body[8..12], self.swap) as u64;
        let captured_len = read_u32(&body[12..16], self.swap) as usize;
        let orig_len = read_u32(&body[16..20], self.swap);
        if body.len() < 20 + captured_len {
            bail!(
                "pcapng EPB captured length {captured_len} exceeds body ({} bytes)",
                body.len() - 20
            );
        }
        let data = body[20..20 + captured_len].to_vec();
        let iface = self.interface(interface_id);
        let (ts_sec, ts_nsec) = split_ticks((ts_high << 32) | ts_low, iface.ticks_per_sec);
        Ok(RawPacket {
            ts_sec,
            ts_nsec,
            orig_len,
            link_type: iface.link_type,
            data,
        })
    }

    fn parse_spb(&self, body: &[u8]) -> Result<RawPacket> {
        if body.len() < 4 {
            bail!("truncated pcapng SPB body");
        }
        let orig_len = read_u32(&body[0..4], self.swap);
        // SPB has no captured-length field: everything after the header
        // (minus 4-byte padding at the end) is packet data. We don't
        // know how much padding there is without recomputing from the
        // block length, but our caller already stripped the trailer, so
        // `body[4..]` less its 32-bit padding is the packet.
        let mut data = body[4..].to_vec();
        // Trim trailing zeros used as padding, up to 3 bytes.
        let pad = pad4(orig_len as usize).min(data.len());
        data.truncate(data.len().saturating_sub(pad));
        let iface = self.interface(0);
        // SPB has no timestamp.
        Ok(RawPacket {
            ts_sec: 0,
            ts_nsec: 0,
            orig_len,
            link_type: iface.link_type,
            data,
        })
    }

    fn interface(&self, id: usize) -> Interface {
        self.interfaces
            .get(id)
            .copied()
            .unwrap_or_else(Interface::default_ethernet)
    }
}

#[inline]
fn pad4(n: usize) -> usize {
    (4 - (n % 4)) % 4
}

#[inline]
fn split_ticks(ticks: u64, ticks_per_sec: u64) -> (u32, u32) {
    if ticks_per_sec == 0 {
        return (0, 0);
    }
    let sec = ticks / ticks_per_sec;
    let sub = ticks % ticks_per_sec;
    // Rescale the sub-second remainder to nanoseconds. Use u128 to avoid
    // overflow when ticks_per_sec is large (e.g. base-2 with exp near 40).
    let nsec = if ticks_per_sec == 1_000_000_000 {
        sub as u32
    } else {
        (sub as u128 * 1_000_000_000u128 / ticks_per_sec as u128) as u32
    };
    (sec.min(u32::MAX as u64) as u32, nsec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn write_option(out: &mut Vec<u8>, code: u16, value: &[u8]) {
        out.extend_from_slice(&code.to_le_bytes());
        out.extend_from_slice(&(value.len() as u16).to_le_bytes());
        out.extend_from_slice(value);
        // Pad to 32-bit.
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
    }

    fn write_block(out: &mut Vec<u8>, block_type: u32, body: &[u8]) {
        let mut padded = body.to_vec();
        while !padded.len().is_multiple_of(4) {
            padded.push(0);
        }
        let total = (12 + padded.len()) as u32;
        out.extend_from_slice(&block_type.to_le_bytes());
        out.extend_from_slice(&total.to_le_bytes());
        out.extend_from_slice(&padded);
        out.extend_from_slice(&total.to_le_bytes());
    }

    fn build_shb() -> Vec<u8> {
        // body: BOM(4) major(2) minor(2) section_length(8) opt_endofopt
        let mut body = Vec::new();
        body.extend_from_slice(&SHB_BOM.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes()); // major
        body.extend_from_slice(&0u16.to_le_bytes()); // minor
        body.extend_from_slice(&u64::MAX.to_le_bytes()); // section_length: unspecified
        // opt_endofopt
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body
    }

    fn build_idb(link_type: u16, tsresol: Option<u8>) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&link_type.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes()); // reserved
        body.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
        if let Some(v) = tsresol {
            write_option(&mut body, 9, &[v]);
            write_option(&mut body, 0, &[]);
        }
        body
    }

    fn build_epb(interface_id: u32, ts: u64, data: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&interface_id.to_le_bytes());
        body.extend_from_slice(&((ts >> 32) as u32).to_le_bytes());
        body.extend_from_slice(&(ts as u32).to_le_bytes());
        body.extend_from_slice(&(data.len() as u32).to_le_bytes());
        body.extend_from_slice(&(data.len() as u32).to_le_bytes());
        body.extend_from_slice(data);
        // pad packet data to 4 bytes
        while !body.len().is_multiple_of(4) {
            body.push(0);
        }
        // opt_endofopt
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body
    }

    fn build_capture(idb_link: u16, tsresol: Option<u8>, packets: &[(u64, Vec<u8>)]) -> Vec<u8> {
        let mut buf = Vec::new();
        write_block(&mut buf, BT_SHB, &build_shb());
        write_block(&mut buf, BT_IDB, &build_idb(idb_link, tsresol));
        for (ts, data) in packets {
            write_block(&mut buf, BT_EPB, &build_epb(0, *ts, data));
        }
        buf
    }

    #[test]
    fn reads_epb_us_resolution() {
        // Default tsresol is microseconds.
        let payload = [0xde, 0xad, 0xbe, 0xef];
        let ts = 1_700_000_000u64 * 1_000_000 + 500_000; // 500 ms after
        let buf = build_capture(1, None, &[(ts, payload.to_vec())]);
        let mut r = PcapNgReader::new(Cursor::new(buf)).unwrap();
        let pkt = r.next_packet().unwrap().unwrap();
        assert_eq!(pkt.link_type, LinkType::Ethernet);
        assert_eq!(pkt.ts_sec, 1_700_000_000);
        assert_eq!(pkt.ts_nsec, 500_000_000);
        assert_eq!(pkt.data, payload);
        assert!(r.next_packet().unwrap().is_none());
    }

    #[test]
    fn reads_epb_nanosecond_resolution() {
        let payload = [1, 2, 3, 4, 5];
        // tsresol = 9 (base-10 exp): nanoseconds
        let ts = 1_700_000_000u64 * 1_000_000_000 + 123_456_789;
        let buf = build_capture(1, Some(9), &[(ts, payload.to_vec())]);
        let mut r = PcapNgReader::new(Cursor::new(buf)).unwrap();
        let pkt = r.next_packet().unwrap().unwrap();
        assert_eq!(pkt.ts_sec, 1_700_000_000);
        assert_eq!(pkt.ts_nsec, 123_456_789);
    }

    #[test]
    fn skips_unknown_block_types() {
        // Standard SHB + IDB + one unknown block + one EPB.
        let mut buf = Vec::new();
        write_block(&mut buf, BT_SHB, &build_shb());
        write_block(&mut buf, BT_IDB, &build_idb(1, None));
        write_block(&mut buf, 0xdead_beef, &[0, 1, 2, 3, 4, 5, 6, 7]); // gibberish
        write_block(&mut buf, BT_EPB, &build_epb(0, 42, &[0xaa; 8]));

        let mut r = PcapNgReader::new(Cursor::new(buf)).unwrap();
        let pkt = r.next_packet().unwrap().unwrap();
        assert_eq!(pkt.data, [0xaa; 8]);
    }

    #[test]
    fn rejects_bad_magic() {
        let buf = vec![0; 32];
        let err = match PcapNgReader::new(Cursor::new(buf)) {
            Ok(_) => panic!("expected error"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("not a pcapng file"));
    }
}
