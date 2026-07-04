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
- **RDMA / datacenter:** RoCEv2 (InfiniBand BTH over UDP/4791) — opcode,
  Dest QP, PSN, RETH/AETH extended headers, CNP, and ECN/FECN/BECN
  congestion flags. See `docs/tshark-analysis/datacenter-roadmap.md`.
- Parallel dissection (`rayon`), reader-batched for bounded memory.
- **Protocol detail tree** with typed, named fields behind every
  dissector: `-V` prints the full tree (tshark-style), `-e <field>`
  extracts named field values (tab-separated, repeatable) — e.g.
  `-e infiniband.bth.psn -e infiniband.bth.destqp` to pipe RDMA
  sequence numbers into analysis.
- **Display filters** (`-Y`): comparisons (`==`, `!=`, `<`, `<=`, `>`,
  `>=` and eq/ne/lt/le/gt/ge aliases), boolean `&&`/`||`/`!`
  (and/or/not), parentheses, and bare field/protocol existence tests.
  Numeric literals accept decimal or `0x` hex. Examples:
  `-Y 'infiniband.bth.destqp == 0x123'`,
  `-Y 'ip.dsfield.ecn == 3'` (ECN-marked),
  `-Y 'infiniband.bth.opcode == 0x11 || infiniband.bth.opcode == 0x81'`.
- **RoCE PSN analysis** (`-z roce,psn`): per-queue-pair sequence
  tracking that reports dropped packets, reordering/duplicates, and
  retransmits, with the frame where each QP's first anomaly appears.
  Keyed by (destination IP, destination QP); 24-bit PSN wrap handled;
  covers all packets read, independent of any `-Y` filter. This is the
  QP-shardable analysis the parallel design was built for.
- `-c N`, `-q`, `-j N`, `-V`, `-e`, `-Y`, `-z`, `--no-parallel`,
  `--batch N`.

## Not implemented

- Live capture (no libpcap / dumpcap equivalent yet).
- Read filters (`-R`) and two-pass analysis (`-2`). (Single-pass
  display filtering with `-Y` is supported.)
- Hex dump (`-x`), PDML / PSML / JSON / EK output.
- Stateful protocols that need reassembly, defragmentation, or conversation
  tracking (TLS, HTTP/2, stream-following, ...). (RoCE PSN analysis via
  `-z roce,psn` is the one stateful analysis implemented so far.)
- Name resolution, color output, general tap framework, PDU export.

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
    src/roce.rs       — RoCEv2 / InfiniBand BTH dissection
    src/field.rs      — typed field tree (-V / -e), the filter foundation
    src/dfilter.rs    — display-filter lexer / parser / evaluator (-Y)
    src/analysis.rs   — per-QP RoCE PSN analysis (-z roce,psn)
    src/print.rs      — summary, verbose, and field-extraction formatting
    src/pipeline.rs   — reader → parallel dissect → filter → ordered print

## License

GPL-2.0-or-later, matching upstream Wireshark/tshark.
