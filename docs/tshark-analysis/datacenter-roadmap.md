# Datacenter / RDMA roadmap

This document scopes rusty-shark toward **datacenter networking** —
Ethernet fabrics carrying RDMA (RoCE, and eventually native InfiniBand)
— rather than chasing general tshark parity across ~3000 dissectors.

The bet: datacenter RDMA is one coherent protocol stack, maybe 20–30
dissectors deep, and it is exactly the workload where this project's
parallelism thesis pays off. Line-rate 100/200/400G captures are huge,
and they shard cleanly by queue pair (QP), so a QP-parallel, PSN-aware
analyzer is both useful and a natural fit for the reader → parallel
dissect → ordered emit pipeline already in place.

## Target stack

Convergent entry paths into one transport core (the InfiniBand Base
Transport Header, BTH):

```
  RoCEv2:   Ethernet → IPv4/6 → UDP(dport 4791) → BTH → [ext hdrs] → payload → ICRC
  RoCEv1:   Ethernet(0x8915) → GRH → BTH → [ext hdrs] → payload → ICRC
  Native IB: LRH → GRH → BTH → [ext hdrs] → payload → ICRC   (pcap DLT 247)
```

RoCEv2 is the pragmatic primary target: it captures with ordinary NIC
port mirroring, whereas native InfiniBand needs tap hardware.

### Tiers

**1. Framing / link**
- Ethernet (done), IPv4/IPv6 (done), UDP (done).
- 802.1Q VLAN with PCP/DEI extraction; QinQ. (PCP → traffic class is
  central to RoCE lossless-fabric design.)
- `LINKTYPE_INFINIBAND` (DLT 247) for native captures.
- Account for the 4-byte **ICRC** trailer.

**2. Fabric / congestion (DCB)**
- **PFC** (802.1Qbb) pause frames — MAC Control, ethertype 0x8808.
- **ECN** bits in the IP header, surfaced as fields (drives DCQCN).
- **CNP** — Congestion Notification Packet (a BTH opcode).
- **LLDP + DCBX** TLVs; **PTP/1588** clock sync.

**3. RDMA transport (the core)**
- **BTH**: opcode, SE, MigReq, PadCount, TVer, P_Key, FECN/BECN,
  Dest QP, AckReq, PSN.
- **Opcode dispatch** to extended headers: RETH, AETH, DETH, RDETH,
  AtomicETH, ImmDt, XRCETH.

**4. RDMA upper-layer protocols**
- Storage: NVMe-oF/RDMA, iSER, SRP, NFS/RDMA.
- Enterprise: SMB Direct.
- General: IPoIB, RDS.
- Caveat: raw RDMA WRITE/READ payloads are opaque remote memory; we
  dissect headers and known ULPs, not arbitrary payload.

**5. Stateful analysis (the differentiator)**
- **QP / connection tracking** — conversation keyed by Dest QP. *(Done,
  M5: keyed by (dst IP, dst QP).)*
- **PSN sequence analysis** — drops, reorder, retransmit. The single
  most valuable RoCE diagnostic. *(Done, M5: `-z roce,psn`,
  `src/analysis.rs`.)*
- **Multi-packet message reassembly** (First/Middle/Last/Only).
- **Congestion correlation** — ECN-marked → CNP → rate reaction. *(M4.)*

## Parallelism fit

The per-flow-shard design sketched in `README.md` (this directory) maps
almost perfectly onto RDMA: **shard by Dest QP**, and each shard owns
its own PSN state and reassembly buffers with no cross-shard locking.
Datacenter captures are both the largest and the most cleanly shardable
workload we could target — the state that blocks naive parallelism in
general tshark becomes embarrassingly parallel here.

## Foundational prerequisites (shared with general roadmap)

Two pieces from the general roadmap still gate the interesting work,
but scoped to this domain:

1. **Field-tree dissection model.** *(Done, M2.)* BTH alone has ~10
   named fields; extended headers add more. Typed, named fields are
   what make `bth.opcode == RDMA_WRITE_ONLY`, `bth.dqp == 0x123`, and
   PSN analysis possible. Every dissector now builds a `Vec<Node>` of
   typed fields alongside the summary columns (`src/field.rs`),
   consumed by `-V` and `-e`.
2. **Display filters (`-Y`).** *(Done, M3.)* Enormously valuable here
   (`infiniband.bth.psn`, `infiniband.bth.destqp`, `ip.dsfield.ecn`).
   A lexer / recursive-descent parser / evaluator (`src/dfilter.rs`)
   runs expressions against the field tree's node abbreviations and
   typed values; filtered output keeps original frame numbers.

## Milestones

| ID | Milestone | Delivers |
|----|-----------|----------|
| **M1** | RoCEv2 BTH summary slice (MVP — DONE) | Detect UDP/4791, decode BTH opcode + Dest QP + PSN, dispatch to RETH/AETH, surface CNP and ECN/FECN/BECN flags, in the existing summary line |
| **M2** | Field-tree model + `-V` + `-e` (DONE) | Typed named fields (`infiniband.bth.*`, `ip.*`, `tcp.*`, ...) on every dissector; `-V` verbose tree; `-e <field>` extraction |
| **M3** | Display filters over the field tree (DONE) | `-Y 'infiniband.bth.destqp == 0x123 && infiniband.bth.opcode == 0x0a'`; comparisons, booleans, parens, existence tests |
| **M5** | **QP-sharded, PSN-aware analysis pass (DONE in this PR)** | `-z roce,psn`: per-QP drop / reorder / retransmit detection keyed by (dst IP, dst QP), 24-bit PSN wrap handled, first-anomaly frame reported |
| M4 | Congestion + fabric tier | ECN surfacing, CNP correlation, PFC pause frames, remaining ext headers |
| M6 | RDMA ULPs | NVMe-oF/RDMA first, then iSER / SMB Direct / IPoIB |
| M7 | Native InfiniBand + RoCEv1 | LRH/GRH, DLT 247, ethertype 0x8915 |

M5 landed ahead of M4 as the higher-value RDMA diagnostic and the
payoff for the QP-shardable parallel design.

## MVP (M1) — the smallest vertical slice

Built first, in this PR. Deliberately reuses the entire existing
Ethernet/IP/UDP path and hangs one new transport dissector off UDP/4791
(`src/roce.rs`).

Scope:
- RoCEv2 detection (UDP destination or source port 4791).
- BTH decode: opcode (named, service-type + operation), Dest QP, PSN.
- Opcode-driven dispatch to the two most common extended headers:
  RETH (VA / R_Key / DMA length) and AETH (syndrome / MSN). This
  establishes the BTH dispatch pattern the rest of the stack extends.
- CNP recognition; SE / AckReq / FECN / BECN / MigReq flags surfaced.

Example output:

```
1  0.000000 10.0.0.1 → 10.0.0.2 RoCE 74 RC RDMA WRITE Only DQP=0x000123 PSN=100 VA=0x1122334455667788 RKey=0xdeadbeef Len=4096
2  1.001000 10.0.0.2 → 10.0.0.1 RoCE 62 RC Acknowledge DQP=0x000456 PSN=100 ACK Syndrome=0x00 MSN=7
4  3.003000 10.0.0.2 → 10.0.0.1 RoCE 58 CNP DQP=0x000123 PSN=0
5  4.004000 10.0.0.1 → 10.0.0.2 RoCE 58 RC SEND Only DQP=0x000123 PSN=102 [AckReq, BECN]
```

Explicitly out of scope for M1 (tracked above):
- ICRC trailer stripping/validation.
- RoCEv1, native InfiniBand.
- Field tree / display filters / PSN analysis.
- Upper-layer protocols.

## Open decisions

1. **Native InfiniBand** — in scope (M7) or RoCEv2-only indefinitely?
   Native IB needs tap hardware to capture, so its practical value
   depends on your environment.
2. **ULP priority (M6)** — storage stack (NVMe-oF / iSER / SRP) vs
   SMB Direct vs IPoIB first?
3. **ICRC** — validate (catch fabric corruption) or just skip the
   trailing 4 bytes for length accounting?
