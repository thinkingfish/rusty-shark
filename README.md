# rusty-shark

A parallel, Rust port of the packet-summary path of
[tshark](https://www.wireshark.org/). The goal is speed through
per-packet parallelism on file-based captures.

This is a **small subset** of tshark — enough to read a classic pcap file
and print the default text summary columns:

    No. | Time | Source | Destination | Protocol | Length | Info

Dissection runs on a rayon worker pool, one packet per job, while the
reader thread pulls records sequentially. Output order matches the input
capture order.

## What works today

- Classic `pcap` file input (little- and big-endian, µs and ns
  timestamps).
- `pcapng` file input: Section Header Block, Interface Description
  Block (with `if_tsresol` for timestamp resolution), Enhanced Packet
  Block, Simple Packet Block. Multi-interface files with mixed link
  types are handled. Non-packet block types (name resolution,
  interface statistics, decryption secrets, custom) are skipped.
- Automatic format detection at open time (`CaptureReader`).
- Link layer: Ethernet (incl. one level of VLAN), Linux SLL, BSD Null
  loopback, DLT_RAW.
- Network layer: IPv4, IPv6, ARP.
- Transport: TCP (flags, seq/ack/win), UDP, ICMP, ICMPv6.
- Well-known UDP upper-layer labels: DNS (with qname), DHCP, NTP, mDNS.
- Parallel dissection (`rayon`), reader-batched for bounded memory.
- `-c N`, `-q`, `-j N`, `--no-parallel`, `--batch N` CLI flags.

## Not implemented

- Live capture (no libpcap / dumpcap equivalent yet).
- Display / read filters (`-Y`, `-R`).
- Two-pass analysis (`-2`).
- Verbose protocol tree (`-V`), hex dump (`-x`), PDML / PSML / JSON / EK
  output.
- Stateful protocols that need reassembly, defragmentation, or conversation
  tracking (TLS, HTTP/2, stream-following, ...).
- Name resolution, color output, taps, statistics, PDU export.

## Build & run

    cargo build --release
    ./target/release/rshark -r capture.pcap
    ./target/release/rshark -r capture.pcap -c 100           # first 100 packets
    ./target/release/rshark -r capture.pcap -j 8             # 8 worker threads
    ./target/release/rshark -r capture.pcap -q --no-parallel # sequential, silent

## Layout

    src/main.rs       — CLI entry
    src/cli.rs        — argument definitions
    src/pcap.rs       — classic pcap reader + CaptureReader dispatch
    src/pcapng.rs     — pcapng reader (SHB / IDB / EPB / SPB)
    src/dissect.rs    — per-packet stateless dissectors
    src/print.rs      — column-summary formatting
    src/pipeline.rs   — reader → parallel dissect → ordered print

## License

GPL-2.0-or-later, matching upstream Wireshark/tshark.
