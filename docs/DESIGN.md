# Design notes

Decisions made while building `pktproc`, the tradeoffs considered, and what
production hardening would change.

---

## Capture path — why `AF_PACKET` + `recv()`

`AF_PACKET` + `SOCK_RAW` gives full L2 frames (including the Ethernet header)
from a single socket bound to one interface. That's the right starting point:
it's the same API `tcpdump`/`libpcap` use in their default configuration, and
every parsing concern (ethertype, VLAN tags, IPv6) can be exercised without
touching the kernel.

The capture loop uses a plain blocking `recv()` with `SO_RCVTIMEO = 1s`. The
timeout is intentional — it lets the main loop observe the `g_running` flag
shortly after `SIGINT`, without the complexity of `poll()` or a self-pipe. For
a capture tool that can tolerate ~1s shutdown latency this is the right
tradeoff.

### What would change for production throughput

`recv()` on `AF_PACKET` incurs one syscall per packet. At line-rate 10Gbps
with 64-byte frames (~14.88 Mpps), that's 14.88M syscalls/sec — not feasible.
Production capture tools use:

1. **`PACKET_MMAP` (TPACKET_V3)** — kernel maps a ring buffer into the user
   address space; userspace reads packet descriptors directly without a
   syscall per packet. Typically 5–10× faster than `recv()`.
2. **`AF_XDP`** — even closer to the NIC, with zero-copy RX into user-owned
   UMEM. The modern replacement.
3. **Kernel bypass (DPDK, Snabb, VPP)** — skip the kernel entirely.

The parser, filter, and flow table in this project are self-contained and
could be re-pointed at any of those backends. The `capture_next()` abstraction
is intentionally thin.

---

## Parser — why manual byte extraction for TCP flags

glibc exposes TCP flags as bitfields (`tcp->syn`, `tcp->fin`, …), but the
bitfield layout depends on:

- Host endianness (flipped in `<netinet/tcp.h>` via `__BYTE_ORDER`)
- Whether `__FAVOR_BSD` / `_DEFAULT_SOURCE` is set
- Compiler-specific bitfield packing

Getting any of those wrong silently produces swapped flags — a category of
bug that won't show up until you're debugging a SYN flood in production.
`src/parser.c` reads the TCP flag byte at its fixed offset (13, per RFC 793)
and decodes the six interesting bits by hand. The Ethernet and IPv4 header
structs (`struct ether_header`, `struct iphdr`) are used because their field
offsets are stable on every Linux ABI, but everything beyond that is raw-byte
arithmetic.

### Bounds checking

Every access is length-gated. The parser returns `-1` as soon as a stated
header length would read past `len`. Specifically:

- Ethernet: require ≥ 14 bytes
- IPv4: require ≥ 20 bytes + declared `IHL*4` bytes (validated `20 ≤ IHL*4 ≤ 60`)
- IPv4 version must be 4 (otherwise immediate `-1`)
- TCP: require ≥ 20 bytes past the IP header
- UDP: require ≥ 8 bytes past the IP header
- ICMP: require ≥ 8 bytes past the IP header
- IPv4 fragments with non-zero fragment offset: return success but leave
  `has_transport = 0` (can't decode a transport header that isn't there)

Malformed or adversarial frames produce a clean error, never an OOB read.

### Why not IPv6 / VLAN / QinQ

Scope. Adding IPv6 means parsing the full extension-header chain (Hop-by-Hop,
Routing, Fragment, AH, ESP…) and is a separate project in its own right.
802.1Q/802.1ad VLAN tags would be a ~20-line addition but aren't on the
critical path for a demo. Both are listed as extensions in the PRD.

---

## Flow table — open addressing with linear probing

The flow table is a single `calloc(capacity, sizeof(flow_entry_t))` with
`capacity` required to be a power of two. The hash is FNV-1a over the packed
`flow_key_t` (13 bytes). Insertion linearly probes up to `MAX_PROBE_DIST = 64`
slots; if no match or empty slot is found within that window, the packet's
flow is dropped and the `drops` counter incremented.

### Why open addressing rather than chaining

- **Cache locality**. Each slot is ~48 bytes, so on a 64-byte cache line a
  probe fetches the next bucket for free. Chained buckets, by contrast, chase
  an allocator-owned pointer per collision, which is an L3 miss most of the
  time.
- **Allocation behavior**. Chaining requires a per-flow `malloc()` on insert —
  or a separate arena. Open addressing is entirely static.
- **Pattern matches DPDK**. DPDK's `rte_hash` uses open addressing + cuckoo
  for exactly these reasons. Familiar shape for readers coming from that world.

### Why bound the probe distance

Unbounded linear probing on a near-full table degrades to O(n) per insert,
which would stall the capture loop and cause kernel ring-buffer overruns. A
fixed probe cap turns the worst case into "drop the flow, increment a
counter, keep capturing". Visibility is preserved through the `drops` metric
printed on exit.

### What production would add

- **Eviction policy**: right now `drops++` on full. LRU eviction based on
  `last_seen` would let long-running captures recover from table saturation.
- **Cuckoo hashing**: gives worst-case O(1) lookup at the cost of a second
  hash. A natural next step once LRU is in place.
- **Lock-free / sharded**: for multi-threaded capture (one thread per RSS
  queue), shard by `hash % num_threads` so each thread owns its partition
  and no atomic is needed on the hot path.

### Why flows are directional

A flow `(src_ip, dst_ip, sport, dport, proto)` is distinct from the reverse.
This matches how NetFlow/IPFIX models flows and keeps the key comparison a
single `memcmp`. Bidirectional flow aggregation is an analysis-layer concern:
walk the table once, merge `(A, B)` with `(B, A)` on output. Doing it at
insert time would require canonicalizing the key on every packet, which is
measurable overhead when you don't always want it.

---

## Filter engine

The filter language is intentionally trivial — `field=value[/prefix]`,
AND'd. A proper BPF compiler is a 10× larger project and contributes nothing
to the protocol-parsing story the project is meant to illustrate.

CIDR prefix matching is stored as a host-order `(value, mask)` pair, with
the value canonicalized to `value & mask` at parse time. Hot-path match is
a single `(pkt->field & rule->mask) == rule->value` — one AND, one compare,
branch-predictable.

---

## PCAP output

Writes libpcap format (magic `0xa1b2c3d4`, microsecond timestamps,
LINKTYPE_ETHERNET). Records are appended in capture order with
`incl_len = orig_len = min(len, snaplen)` — no truncation beyond snaplen.

Not implemented:
- PCAPng (the newer block-oriented format). Wireshark reads both; the older
  format is one 24-byte global header + one 16-byte record header per packet,
  which is easy enough to inline without a dependency.
- Rotation by size or time. One more flag, but scope-creep for a demo.

---

## What's explicitly out of scope

- **IPv6**. Header + extension-chain parsing.
- **VLAN (802.1Q)**. One extra ethertype branch, ~20 LOC.
- **`PACKET_MMAP` zero-copy**. Would materially change the capture API.
- **Full BPF VM**. Linux already has it. `cBPF` / `eBPF` are a separate project.
- **Windows / macOS backends**. `AF_PACKET` is Linux-specific. On other
  platforms the equivalents are `pcap_open_live()` (libpcap), `WinPcap`/
  `Npcap`, or `BPF` devices.
