# tshark: code overview

A working reference for people porting tshark to another language or
reasoning about how it could be parallelized. The notes below are based
on reading `tshark.c` and on the surrounding libraries it links against
(libwireshark, libwiretap, libwsutil, dumpcap).

Line references in this document are to upstream `tshark.c` at the
revision used to seed this project. Names of functions and globals are
reproduced verbatim.

## Contents

1. [What tshark is](#what-tshark-is)
2. [Feature surface](#feature-surface)
3. [Component architecture](#component-architecture)
4. [Source layout](#source-layout)
5. [Execution modes](#execution-modes)
6. [Per-packet dissection flow](#per-packet-dissection-flow)
7. [Dissection engine](#dissection-engine)
8. [Output formats](#output-formats)
9. [Threading model](#threading-model)
10. [Memory management](#memory-management)
11. [Error handling and signals](#error-handling-and-signals)
12. [Implications for a parallel Rust port](#implications-for-a-parallel-rust-port)

## What tshark is

tshark is the command-line sibling of the Wireshark GUI. It shares
essentially the entire dissection engine (`libwireshark` / `epan`), the
file I/O layer (`libwiretap`), and the capture plumbing (`dumpcap` plus
`libpcap`) with Wireshark. What it adds on top is a text-oriented UI:
argument parsing, column rendering, alternate output formats (PDML,
PSML, JSON, EK, fields), taps/statistics, and packet-count reporting.

Functionally tshark overlaps with `tcpdump`, but it dissects with the
full Wireshark protocol suite — thousands of dissectors spanning
link-layer protocols through application payloads — and can emit
structured output suitable for downstream tooling.

tshark is not itself a capture engine. Live capture is performed by a
separate privileged child process, `dumpcap`, which writes packets to a
file or pipe that tshark then reads. See
[Execution modes](#execution-modes).

## Feature surface

Grouped roughly the way the `--help` text groups them.

### Capture (requires `HAVE_LIBPCAP`)

- `-i <iface>` — interface to capture on (or multiple).
- `-f <bpf>` — capture filter in libpcap syntax, compiled by libpcap
  and applied in-kernel before packets reach userspace.
- `-s <snaplen>` — per-packet truncation length.
- `-p` / `-I` — promiscuous / monitor mode.
- `-B <size>` — kernel capture buffer size.
- `-y <dlt>` / `--time-stamp-type` — link-layer and timestamp
  negotiation.
- `-c N`, `-a <cond>` — stop conditions (packets, duration, file size,
  file count).
- `-b <cond>` — ring-buffer output (rotate files by time, size, count,
  or wall-clock interval).
- `-D`, `-L`, `--list-time-stamp-types` — list interfaces / DLTs /
  timestamp methods and exit.
- `extcap` integration — external tools (USB, Bluetooth, vendor
  captures) that present themselves as capture interfaces.

### Input from files

- `-r <file|->` — read a saved capture (any format libwiretap
  supports: pcap, pcapng, and many proprietary variants). `-` reads
  from stdin.
- `-X read_format:<name>` — override format auto-detection.

### Processing controls

- `-2` — two-pass analysis. Needed for display filters that reference
  fields only known after later frames are seen (e.g. response-to-frame
  numbers). See [Execution modes](#execution-modes).
- `-M <N>` — periodic session reset to bound memory in long runs.
- `-R <filter>` — read filter (pass 1). Requires `-2`.
- `-Y <filter>` — display filter (pass 2 or single-pass).
- `-n` / `-N mtndsNvg` — disable or tune name resolution
  (MAC-manufacturer / transport / network-DNS / SS7 / NetBIOS / VLAN /
  geoip).
- `-d <layer.field==val,dissector>` — "decode as" overrides.
- `--enable-protocol` / `--disable-protocol` / `--only-protocols` /
  `--disable-all-protocols` — selectively enable/disable dissectors.
- `--enable-heuristic` / `--disable-heuristic` — ditto for heuristic
  dissectors.
- `-H <hosts>` — preload host name resolutions.
- `-C <profile>` / `--global-profile` — configuration profile.
- `-o <pref>:<value>` — override individual preferences.
- `-K <keytab>` — Kerberos decryption.

### Output

- `-w <file|->` — write packets to a pcapng file (or pcap with `-F`).
- `-F <type>` — output capture format.
- `-V` — verbose packet details (the protocol tree).
- `-O <protos>` — restrict `-V` to named protocols.
- `-P` — print summaries even when `-w` is given.
- `-S <sep>` — inter-packet line separator.
- `-x` / `--hexdump <opts>` — hex+ASCII dump of frame bytes.
- `-T text|tabs|ps|pdml|psml|json|jsonraw|ek|fields` — output format.
- `-e <field>` / `-E <opt>=<val>` — field list and formatting for
  `-Tfields`.
- `-j <filter>` / `-J <top-filter>` — protocol filters for structured
  formats.
- `-t <format>` / `-u s|hms` — time column format.
- `-l` — line-buffer stdout.
- `-q` / `-Q` — progressively quieter stdout / stderr.
- `--color` — 24-bit color using Wireshark coloring rules.
- `--capture-comment`, `--export-objects`, `--export-tls-session-keys`,
  `-U <tap>` — metadata and export features.
- `-z <statistic>` — various statistics ("taps").
- `-G <report>` — dump glossary/preferences and exit. One of:
  `column-formats`, `decodes`, `dissector-tables`, `dissectors`,
  `elastic-mapping`, `enterprises`, `fieldcount`, `fields`, `ftypes`,
  `heuristic-decodes`, `manuf`, `plugins`, `protocols`, `services`,
  `values`, `currentprefs`, `defaultprefs`, `folders`.
- `--print-timers` — emit per-pass timing as JSON to stderr.

### Miscellaneous

- `-h`, `-v` — help / version.
- `-W n` — save extra information (e.g. name-resolution block) to the
  output file.
- `--temp-dir`, `--compress` — staging and output compression.

## Component architecture

tshark is a thin orchestrator on top of several libraries that do the
real work.

```
                         +-------------------+
                         |     tshark.c      |
                         |  (main, printing) |
                         +---------+---------+
                                   |
     +-------------+   +-----------+-----------+   +---------------+
     |  libwsutil  |   |     libwireshark      |   |   libwiretap  |
     |  (helpers)  |   |        (epan)         |   | (file format) |
     +-------------+   +-----------+-----------+   +-------+-------+
                                   |                       |
                +------------------+---------+             |
                |         dissectors         |             |
                |     (~3000 protocols)      |             |
                +----------------------------+             |
                                                           |
                       +---------------+                   |
                       |    libpcap    |<----- capture ----+
                       +-------+-------+          |
                               |                  |
                       +-------+-------+  +-------+--------+
                       |    kernel     |  |    dumpcap     |
                       |  (BPF / PF)   |  | (child process)|
                       +---------------+  +----------------+
```

- **`tshark.c`** — argument parsing, dispatching between live-capture
  and file-read modes, the single- and two-pass loops, column
  rendering, and preamble/finale handling for output formats.
- **`libwireshark` (`epan/`)** — dissection engine. Owns the protocol
  registration database, the dissector-table dispatch, the `proto_tree`
  representation, display-filter compilation (`dfilter_compile_full`),
  column filling, and the tap/listener bus. All the per-protocol
  dissectors live here (`epan/dissectors/`).
- **`libwiretap` (`wiretap/`)** — file-format abstraction. Opens,
  reads, seeks, and writes capture files. Supports pcap, pcapng, and
  many proprietary formats; exposes a uniform `wtap_rec` per record.
- **`libwsutil` (`wsutil/`)** — shared helpers: logging, filesystem,
  string utilities, compression, JSON dumper, clock/locale,
  command-line helpers.
- **`dumpcap`** — a separate, minimally-privileged binary that does
  the actual packet capture. tshark talks to it via a "sync pipe" and
  reads the file/pipe it writes to. Isolating capture in its own
  process lets Wireshark and tshark run unprivileged.
- **`extcap`** — plugin mechanism for external capture tools (USB,
  Wi-Fi monitors, Bluetooth, vendor interfaces). Presented to the rest
  of tshark as additional interfaces.
- **`libpcap` / WinPcap / Npcap** — kernel-side capture primitive.
  Used by dumpcap, not by tshark directly.
- **GLib** — pervasive. `GString`, `GHashTable`, `GPtrArray`,
  `GMainContext` (the live-capture event loop), and `TRY`/`CATCH`
  (set-jmp-based exceptions) are all GLib.
- **Optional** — Lua (`wslua`) for scripting, libsmi for MIBs,
  MaxMindDB for geo lookup, Kerberos for decryption.

## Source layout

Top-level directories inside the Wireshark source tree that matter for
tshark:

| Path | Purpose |
|------|---------|
| `tshark.c` | CLI entry point, main loop, print routines |
| `cli_main.c` | Shared CLI bootstrap (signals, logging, locale) |
| `capture_opts.c`, `capture/` | Capture-session configuration and plumbing |
| `epan/` | Dissection engine library |
| `epan/dissectors/` | Per-protocol dissectors (~3000 files) |
| `epan/dfilter/` | Display-filter language implementation |
| `wiretap/` | Capture-file readers and writers |
| `wsutil/` | Utility library |
| `ui/cli/` | Tap-style statistics commands (`-z` handlers) |
| `ui/` | UI-shared code (failure messages, filter files, taps) |
| `extcap/` | External capture tool glue |
| `dumpcap.c` | The privileged capture child |

## Execution modes

tshark's `main()` parses arguments, initializes epan and wiretap, and
then dispatches to one of two top-level paths:

1. **File read** — if `-r <file>` was given. Calls `cf_open()` to open
   the capture with `wtap_open_offline()`, then `process_cap_file()`.
2. **Live capture** — otherwise. Calls `capture()`, which forks
   dumpcap via `sync_pipe_start()` and drives a GLib main loop
   (`g_main_context_iteration`) while dumpcap pushes packets back.

Most of the interesting flow is in the file-read path. Live capture
ultimately ends up in a similar per-packet loop in
`capture_input_new_packets`.

### Single-pass file processing

`process_cap_file_single_pass()` is the common case.

```
    while (wtap_read(wth, &rec, &err, &data_offset)) {
        process_packet_single_pass(cf, edt, data_offset, &rec, tap_flags);
        wtap_rec_reset(&rec);
        ... stop conditions ...
    }
```

For each record it:

1. Counts the frame and initializes a `frame_data` for it.
2. Runs the dissector via `epan_dissect_run_with_taps()`.
3. Applies the display filter (`cf->dfcode`) if one was provided.
4. If the packet passed and we're printing: calls `print_packet()`,
   which emits columns (`print_columns`) or a protocol tree depending
   on flags.
5. If we're writing (`pdh != NULL`): `wtap_dump()` the record.

### Two-pass file processing

`-2` triggers `process_cap_file_first_pass()` followed by
`process_cap_file_second_pass()`.

The first pass:

- Allocates a `frame_data_sequence`.
- Streams records via `wtap_read()`.
- Dissects each one only enough to evaluate the read filter (`-R`)
  and to populate `frame_data` fields needed for later display-filter
  evaluation (e.g. dependent-frame resolution).
- Appends passing frames to `cf->provider.frames` via
  `frame_data_sequence_add`.
- Calls `wtap_sequential_close()` and `postseq_cleanup_all_protocols()`
  once done, freeing per-pass memory.

The second pass:

- Iterates `framenum` from 1 to `cf->count`.
- For each frame, `wtap_seek_read()` random-accesses the record at
  its stored offset.
- Dissects with `epan_dissect_run_with_taps()`, re-applying the
  display filter, then prints and/or writes.

Two-pass is required for display filters that reference fields such as
response times or dependent frame numbers — information that only
exists after the whole capture has been seen once.

### Live capture

`capture()` (only built when `HAVE_LIBPCAP` is set):

- Installs signal handlers (`capture_cleanup`).
- Calls `sync_pipe_start()` to fork dumpcap.
- Runs `g_main_context_iteration()` in a loop until `loop_running`
  becomes false.
- dumpcap writes captured records to a file (or pipe); when it signals
  "new packets available", `capture_input_new_packets()` is invoked on
  the main thread to dissect and print them. The per-packet path is
  essentially the same as the single-pass file read path.

All dissection still happens in the tshark process. dumpcap only
captures and writes.

## Per-packet dissection flow

In all three code paths — single-pass file, second-pass file, live — a
record ends up flowing through roughly the same steps:

1. **Read** — `wtap_read()` or `wtap_seek_read()` fills a
   `wtap_rec` with the packet metadata (timestamp, lengths, block
   type) and its payload bytes. Returns the absolute file offset.
2. **Frame-data init** — `frame_data_init()` wraps the record with
   bookkeeping: frame number, cumulative bytes, per-frame flags.
3. **Priming** — if a filter or tap has declared interest in specific
   fields, `epan_dissect_prime_with_dfilter()` /
   `epan_dissect_prime_with_hfid()` mark those fields so the engine
   bothers to extract them during dissection.
4. **Before-dissect setup** — `frame_data_set_before_dissect()`
   captures timestamp references (for relative time columns) and
   updates the "previous captured"/"previous displayed" frame pointers.
5. **Dissect** — `epan_dissect_run_with_taps()` walks the dissector
   chain starting from the link-layer dissector for `cf->cd_t`. Each
   dissector inspects its layer, consumes bytes, possibly builds a
   `proto_tree` node, and hands off to a sub-dissector via a
   dissector table.
6. **Filter** — if `cf->dfcode` is set, `dfilter_apply_edt()`
   evaluates the compiled display filter over the dissection tree.
7. **After-dissect** — `frame_data_set_after_dissect()` updates
   cumulative stats.
8. **Emit** — `print_packet()` prints columns, tree, hex dump, or
   structured output, and/or `wtap_dump()` writes the record to the
   output file.
9. **Reset** — `epan_dissect_reset()` clears per-packet scoped memory
   (`pinfo_pool`). Optionally `reset_epan_mem()` tears the whole epan
   session down and rebuilds it when `-M` is in effect.

## Dissection engine

The engine lives under `epan/`. Key abstractions:

- **`epan_t`** — a dissection session. Wraps the registered dissector
  database plus per-session caches (conversations, fragment tables,
  reassembly state). `tshark_epan_new()` creates one per capture file;
  `reset_epan_mem()` can tear it down mid-run to bound memory.
- **`epan_dissect_t`** — a per-dissection instance, reused across
  packets. Holds the current `proto_tree`, `packet_info` (`pinfo`),
  and a `tvbuff_t` view over the packet bytes. Created with
  `epan_dissect_new()` once per loop.
- **Dissector tables** — string-keyed or integer-keyed dispatch
  tables. Every protocol registers handlers it wants sub-dissectors
  for (e.g. `tcp.port` dispatches to the dissector for port 443).
  Created during `register_all_protocol_handoffs()` on startup.
- **Heuristic dissectors** — additional dissectors that opt in to
  inspect a payload even without a matching registration, by pattern
  matching (e.g. HTTP-over-arbitrary-port).
- **`proto_tree`** — the structured tree of decoded fields. Built
  eagerly only when something downstream needs it: `-V`, a display
  filter, a tap that declared `TL_REQUIRES_PROTO_TREE`, a postdissector
  needing fields, or custom columns.
- **`column_info`** — the precomputed column strings. Populated by
  `epan_dissect_fill_in_columns()` when summary output is wanted.
- **Display filters** — compiled to a bytecode via
  `dfilter_compile_full()`; evaluated per-frame by `dfilter_apply_edt()`.
  Expansion (macros) is done once at startup in `_compile_dfilter()`.
- **Taps / listeners** — callbacks registered via `register_tap_listener`.
  Dissectors emit "tap data" during dissection (e.g. one record per
  HTTP request); statistics (`-z`) are implemented as taps.
- **Postdissectors** — dissectors that run after the normal stack, so
  they can see fields extracted by any earlier dissector. Used by MATE
  and similar cross-layer analyses.

State that lives longer than a single packet and is therefore why
parallelism is hard:

- **Conversations** — hash-keyed by addresses/ports, used to thread
  related packets (e.g. every TCP segment in the same flow).
- **Reassembly tables** — per-protocol (TCP, IP, SMB) tables holding
  pending fragments until the final segment arrives.
- **Stream-tracking** — TCP-stream follow, TLS session resumption.
- **Name resolution caches** — hash tables keyed by IP/MAC/port.
- **Secrets** — TLS session keys loaded from pcapng DSBs or files.

## Output formats

The output pipeline is keyed off `output_action` (set by `-T`):

| `-T` | `output_action` | Behavior |
|------|-----------------|----------|
| `text` (default) | `WRITE_TEXT` | Columns, or tree under `-V`, via `print_stream` |
| `tabs` | `WRITE_TEXT` | Same, with tab as column delimiter |
| `ps` | `WRITE_TEXT` | PostScript variant of text |
| `pdml` | `WRITE_XML` | Full protocol details as XML |
| `psml` | `WRITE_XML` | Summary columns as XML |
| `fields` | `WRITE_FIELDS` | Named fields from `-e`, in order |
| `json` | `WRITE_JSON` | Nested JSON with field display values |
| `jsonraw` | `WRITE_JSON_RAW` | Same shape, raw hex-encoded values only |
| `ek` | `WRITE_EK` | Elasticsearch bulk-insert lines |

For each, tshark calls:

- `write_preamble()` once at the start (PDML header, JSON `[`, text
  banner).
- `print_packet()` per frame. It dispatches on `output_action` to the
  appropriate formatter: `print_columns`, `proto_tree_print`,
  `write_pdml_proto_tree`, `write_json_proto_tree`,
  `write_fields_proto_tree`, `write_ek_proto_tree`.
- `write_finale()` at the end (closing XML, JSON `]`, totals).

`print_columns()` is worth noting: it renders the configured column
set with minimum-width padding and inserts UTF-8 arrow glyphs between
source and destination columns of the same address family — this is
the signature "src → dst" look of tshark output.

Hex dumps (`-x`, `--hexdump`) and per-packet separators are layered on
top regardless of `output_action`, subject to compatibility checks.

## Threading model

tshark itself is **effectively single-threaded**. All significant work
— file reading, dissection, filter evaluation, tap processing, column
rendering, printing, writing — runs on the main thread.

Where concurrency does appear:

- **dumpcap is a separate process.** Live capture reads from a file
  or pipe written by dumpcap. The sync pipe is checked on the main
  tshark GLib loop; dumpcap runs independently and is driven by the
  kernel's capture APIs. This separates capture from dissection, but
  they still happen on at most two cores in practice (dumpcap +
  tshark).
- **Async name resolution.** Under a specific preference, C-ares is
  used for DNS lookups. Results are drained on the main thread via
  `host_name_lookup_process()`. When async lookups are disabled
  (`set_resolution_synchrony(true)`) — which is the case for both
  live capture and single-pass file read — even this goes synchronous.
- **MaxMindDB lookups** run in a helper process invoked via pipe, not
  threads. tshark serializes reads from it.
- **GLib main context.** Only used for the live-capture event loop.
  It does not dispatch work to worker threads.

There is no worker-thread pool for dissection, no per-flow affinity,
no ordered-output collector. Every packet is dissected serially in
the order it arrives.

### Why the engine is single-threaded

Several sources of shared mutable state make parallel dissection
unsafe in the general case:

1. **The conversation table** — a hash table keyed by addresses/ports
   that many dissectors (TCP, UDP, SCTP, HTTP, TLS, RTP, RTCP, SIP,
   DNS, etc.) read and mutate to correlate related packets. Not
   locked; assumes single-threaded mutation.
2. **Reassembly state** — IP fragments, TCP-segment reassembly, SMB
   multiplexing, MSRP, and many others keep per-flow buffers that are
   appended to as new fragments arrive. Ordering matters.
3. **Stream trackers** — TCP-stream numbering, TLS session resumption
   tracking, HTTP/2 stream state, QUIC connection state.
4. **Per-session caches** — decrypted-TLS caches, Kerberos replay
   detection, IKE SA state.
5. **Name resolution caches** — shared across packets.
6. **`wmem` allocator scopes** — the `packet` scope is logically
   reset between packets; concurrent mutations would race.

The dissector registry itself (`protocol_t`, `dissector_table`,
`header_field_info`) is effectively immutable after
`epan_init()`/`register_all_protocol_handoffs()` returns. That part is
fine to read from multiple threads. It's the per-session state above
that is not.

### Two-pass, and why it matters

Two-pass analysis (`-2`) is not parallelism. It's a sequential
two-phase algorithm: phase 1 dissects each packet to compute
`frame_data` fields referenced by the display filter, then phase 2
re-dissects and emits. The motivation is correctness (filters can
reference fields populated only after the whole capture is seen, like
response-times), not throughput — two-pass is slower than single-pass.

## Memory management

tshark relies on two overlapping schemes:

- **`wmem` (epan's memory manager)** — scoped allocators. Scopes
  include `epan_scope` (process lifetime), `file_scope` (per capture
  file), and `packet_scope` (per-packet, released at
  `epan_dissect_reset`). Dissectors allocate almost all their
  short-lived data in `packet_scope`, which is freed wholesale between
  packets with no per-object destructor calls.
- **GLib** — `g_malloc`/`g_free`, `GString`, `GHashTable`,
  `GPtrArray` for longer-lived structures and anywhere the API
  predates wmem.

`-M <N>` / `epan_auto_reset` exists because long captures accumulate
conversation and reassembly state in `file_scope` that cannot be
freed piecemeal. Periodically dropping and rebuilding the entire epan
session is the blunt tool that keeps memory bounded.

Out-of-memory is handled via GLib `TRY`/`CATCH` (set-jmp-based
exceptions) around the per-file loop. An OOM aborts the current file
cleanly rather than the whole process.

## Error handling and signals

- **`SIGINT` / `SIGTERM` / `SIGHUP`** set `read_interrupted` (file
  mode) or trigger `sync_pipe_stop()` (capture mode). The current loop
  iteration completes and the process shuts down cleanly.
- **`SIGINFO`** (BSD/macOS) prints the current packet count without
  interrupting processing.
- **Windows** has an analogous `SetConsoleCtrlHandler` path.
- **EPIPE on stdout** is treated as "downstream pipe consumer
  exited" and exits silently with no error. Handy for
  `tshark ... | head`.
- **Write errors** to the output capture file propagate as
  `PROCESS_FILE_WRITE_ERROR` and set a non-zero exit status while
  still draining any tap results.

## Implications for a parallel Rust port

The single-threaded engine is a real bottleneck on multi-core
hardware, especially for `-r` workloads where capture is bounded by
how fast one CPU can dissect. A few observations worth keeping in mind
as the port evolves:

### What is safe to parallelize today

- **Stateless per-packet dissection.** Protocols with no cross-packet
  state — Ethernet, IPv4/IPv6 header parsing, ARP, ICMP, DNS request
  decoding for a single datagram, stateless UDP payloads — can be
  dissected in parallel trivially. This is what the current Rust
  MVP exploits.
- **Summary-column rendering.** Once dissection produces a flat
  `Summary`, formatting it into a line is pure.
- **File I/O vs dissection.** Reading is I/O bound; dissection is
  CPU bound. Overlapping them via a reader thread and a rayon dissect
  pool (as this port does) recovers most of the single-core case's
  ceiling before any harder work.

### What a full port has to solve

- **Conversation affinity.** TCP, HTTP, TLS, QUIC, RTP all require a
  single packet's dissection to read and mutate per-flow state built
  from earlier packets. A correct parallel design needs per-flow
  serialization. The usual pattern:
  1. Compute a 5-tuple (plus VLAN, IPv6 flow label) hash on the
     reader thread.
  2. Route each packet to a worker indexed by that hash.
  3. Each worker dissects in arrival order within its shard.
  4. A reorder/emit stage tags each dissected summary with the
     original frame number and emits in order.
- **Reassembly.** IP fragments and TCP segments straddle multiple
  packets and are defragmented/reassembled before upper-layer
  dissection. Flow-affinity handles the common case; cross-flow
  reassembly (rare) requires coarser locking.
- **Two-pass.** Natural to keep serial, but the first pass can
  parallelize for filters that only reference stateless fields. A
  static analysis of the compiled filter would tell you which.
- **Output ordering.** Default text and pcap(ng) output must preserve
  input order. A simple bounded-slot reorder buffer indexed by frame
  number handles this with minimal head-of-line blocking.
- **Display-filter compilation.** Filter bytecode is compiled once
  and evaluated per-frame. The bytecode is read-only at eval time, so
  evaluation parallelizes; mapping it to an allocation-free Rust
  representation is a project in itself.

### Design sketch for a future phase

```
   +----------+   ring   +-------------+   shards   +----------+
   |  reader  |--------->|  demux by   |----------->| worker 0 |--+
   |  thread  |  frames  | 5-tuple /   |----------->| worker 1 |  |
   +----------+          |   hash      |----------->| worker N |  |
                         +-------------+            +----------+  |
                                                                  v
                                                         +-----------------+
                                                         | reorder + emit  |
                                                         +-----------------+
```

- The reader is one thread; packets are cheap to parse at the
  framing level (pcap record header + payload).
- The demux computes a tuple hash and forwards each packet to a
  bounded MPMC ring for its assigned worker.
- Workers own their shards' conversation/reassembly tables with
  no locking.
- The reorder stage holds a window of recent frames, emitting them in
  sequence as they complete. This bounds latency and memory.

The current Rust MVP in this repository is the degenerate one-shard
version of this design with "the shard is everything, and its state
is empty". Growing it into the full picture above is the natural
path once stateful dissectors are in scope.

### Non-goals worth being explicit about

- **Bit-exact reproduction of tshark output.** Some text quirks
  (locale-dependent time formatting, hand-tuned column widths,
  specific dissector wording) are not worth matching. The Rust port
  should aim for semantically equivalent output suitable for
  scripting, not a character-for-character clone.
- **Dissecting everything tshark dissects.** The long tail of
  industrial/vendor protocols (Profinet, DNP3, FOUNDATION Fieldbus,
  every mobile-core protocol) is probably not worth reimplementing.
  A Rust port that handles common IP/transport plus a few application
  protocols (DNS, HTTP/1, TLS metadata, QUIC headers) covers the vast
  majority of real-world captures.
- **Live capture parity.** Replacing dumpcap is a separate project.
  The Rust port can start as read-from-file-only and keep dumpcap as
  the capture front-end if needed.

## References

- `tshark.c` — main source, driver for everything above.
- `epan/epan.h`, `epan/packet.h` — dissection engine API.
- `epan/proto.h` — protocol-tree and field-info APIs.
- `epan/dfilter/dfilter.h` — display-filter compiler.
- `wiretap/wtap.h` — capture-file I/O.
- Wireshark developer's guide: <https://www.wireshark.org/docs/wsdg_html_chunked/>.
