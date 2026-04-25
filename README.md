# pktproc — Userspace Packet Processor

A lightweight, zero-dependency packet capture and flow-tracking engine in C11.
Uses Linux `AF_PACKET` raw sockets to ingest L2 frames, parses Ethernet / IPv4 /
TCP / UDP / ICMP headers with strict bounds checking, applies BPF-style filter
rules (including CIDR prefix matching), and maintains a 5-tuple flow table with
per-flow byte, packet, and duration statistics. Matched packets can optionally
be written out in libpcap format for inspection in Wireshark.

Built to demonstrate the kernel-adjacent systems programming used at networking
infrastructure companies (Arista, Cloudflare, Cisco, Juniper, AWS) — raw socket
I/O, byte-level protocol parsing, endianness discipline, hash-based flow
tracking, and cache-conscious C.

---

## Features

- **L2 raw capture** via `AF_PACKET` + `SOCK_RAW`, with configurable promiscuous mode
- **Zero-alloc hot path** — one stack buffer, parser writes into a stack struct
- **Strict parsing** — every header boundary bounds-checked; malformed frames drop, never segfault
- **Protocols**: Ethernet II, IPv4 (variable IHL, fragment-aware), TCP (with flag extraction), UDP, ICMP
- **Filter engine**: `src_ip`, `dst_ip` (with CIDR), `src_port`, `dst_port`, `protocol` (numeric or name). Multiple rules AND together
- **Flow table**: open-addressing hash table, FNV-1a on packed 5-tuple, linear probing with bounded worst case
- **Outputs**: aligned ASCII table (default), machine-readable JSON (`-j`), libpcap file (`-w`)
- **Clean shutdown**: `SIGINT` flushes stats; `SIGUSR1` dumps without exiting
- **Zero external dependencies** — just libc + Linux headers. Compiles with
  `-Wall -Wextra -Werror -Wshadow -Wstrict-prototypes`.

---

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                               main.c                            │
│                                                                 │
│  ┌──────────┐   ┌──────────┐   ┌─────────────┐                 │
│  │  Socket  │──▶│  Capture │──▶│   Parser    │                 │
│  │  setup   │   │   loop   │   │  (Eth→IP→L4)│                 │
│  │AF_PACKET │   │  recv()  │   │ bounds-chk  │                 │
│  └──────────┘   └──────────┘   └──────┬──────┘                 │
│                                       │                        │
│                                       ▼                        │
│                               ┌──────────────┐                 │
│                               │    Filter    │                 │
│                               │  (AND rules, │                 │
│                               │  CIDR match) │                 │
│                               └──────┬───────┘                 │
│                                      │                         │
│                      ┌───────────────┴─────────────┐           │
│                      ▼                             ▼           │
│             ┌─────────────────┐           ┌──────────────┐    │
│             │   Flow table    │           │  PCAP writer │    │
│             │   (FNV-1a +     │           │   (libpcap   │    │
│             │   linear probe) │           │    format)   │    │
│             └────────┬────────┘           └──────────────┘    │
│                      │                                         │
│                      ▼                                         │
│             ┌─────────────────┐                                │
│             │  Stats output   │                                │
│             │ (ASCII / JSON)  │                                │
│             └─────────────────┘                                │
└────────────────────────────────────────────────────────────────┘
```

See [`docs/DESIGN.md`](docs/DESIGN.md) for protocol-level and data-structure
decisions.

---

## Build

Requires a Linux toolchain with glibc — no third-party libraries.

```bash
make                # optimized build (-O2)
make debug          # -O0 -g -DDEBUG
make test           # build and run unit tests
make cap            # grant CAP_NET_RAW so you can run without sudo
make clean
```

The Makefile compiles with:

```
-std=c11 -Wall -Wextra -Werror -Wshadow -Wpointer-arith
-Wstrict-prototypes -Wmissing-prototypes -Wunused
```

Zero warnings is enforced by `-Werror`.

---

## Run

```bash
# Raw sockets need CAP_NET_RAW — either sudo, or grant once with `make cap`
sudo ./pktproc -i eth0

# Filter: all outbound TCP handshakes to port 443
sudo ./pktproc -i eth0 -f proto=tcp -f dst_port=443

# CIDR filter, capture to pcap, JSON stats on exit
sudo ./pktproc -i wlan0 -f src_ip=192.168.0.0/16 -w lan.pcap -j

# Stop after 10,000 matched packets
sudo ./pktproc -i eth0 -f proto=udp -c 10000

# Periodic stats every 5s + promiscuous mode
sudo ./pktproc -i eth0 -p -t 5
```

All flags:

| Flag           | Meaning                                                   |
|----------------|-----------------------------------------------------------|
| `-i <iface>`   | Interface to bind to (required)                           |
| `-f <rule>`    | Filter rule (repeatable, AND semantics)                   |
| `-w <file>`    | Append matched packets to a libpcap file                  |
| `-j`           | Emit final stats as JSON instead of ASCII table           |
| `-p`           | Enable promiscuous mode on the interface                  |
| `-t <sec>`     | Periodic stats interval (seconds)                         |
| `-c <n>`       | Exit after `n` matched packets                            |
| `-h`           | Usage                                                     |

Signals:

- `SIGINT` (Ctrl-C) / `SIGTERM` — flush stats and exit cleanly
- `SIGUSR1` — dump current flow table without exiting (`kill -USR1 <pid>`)

---

## Sample output

```
pktproc: capturing on eth0 (2 filters, pcap=https.pcap)
  filter[0]: proto=6
  filter[1]: dst_port=443
Ctrl+C to stop.

^C
--- Capture Statistics ---
Total packets:    142837
Matched packets:  9421
Active flows:     37
Flow drops:       0 (table full)
Avg probe dist:   0.08
Elapsed:          14.22s
Throughput:       10043 pps

  SRC IP          SPORT      DST IP          DPORT  PROTO     PACKETS           BYTES   DURATION
  ------------------------------------------------------------------------------------------------
  192.168.1.42    52104  ->  140.82.114.3      443  TCP           487          312840      12.04s
  192.168.1.42    52108  ->  151.101.1.140     443  TCP           219          187204      11.87s
  192.168.1.42    52111  ->   34.117.18.222    443  TCP           102           68391      10.44s
  ...

Wrote 13481920 bytes to https.pcap
```

Verify the captured pcap file in Wireshark:

```bash
wireshark https.pcap
# or
tshark -r https.pcap -q -z conv,tcp
```

---

## Testing

```bash
$ make test
== build/test_parser ==
== test_parser ==
  [PASS] parse_tcp_happy_path
  [PASS] parse_udp_happy_path
  [PASS] truncated_ethernet
  [PASS] truncated_ip_header
  [PASS] truncated_tcp
  [PASS] non_ipv4_ethertype_is_soft
  [PASS] bad_ip_version_is_rejected
  [PASS] fragment_does_not_parse_transport

Result: 8/8 passed
...
Test summary: 3 passed, 0 failed
```

Tests live in `tests/`, use a 60-line single-header framework (no Unity / no
CMocka), and hand-build Ethernet / IPv4 / TCP / UDP frames in memory to
exercise the parser, filter, and flow table directly.

For leak checking:

```bash
make debug
sudo valgrind --leak-check=full --error-exitcode=1 ./pktproc -i lo -c 100
```

---

## Project layout

```
packet-processor/
├── Makefile                 # -Wall -Wextra -Werror + test target
├── README.md
├── include/
│   ├── common.h             # 5-tuple, parsed_packet_t, filter_rule_t
│   ├── capture.h            # AF_PACKET socket API
│   ├── parser.h             # Eth/IPv4/TCP/UDP/ICMP decoder
│   ├── filter.h             # BPF-style rule parsing + matching
│   ├── flow_table.h         # Open-addressing hash table
│   ├── stats.h              # ASCII / JSON output
│   └── pcap_writer.h        # libpcap file format writer
├── src/
│   ├── main.c               # args, signals, capture loop
│   ├── capture.c            # socket setup, recv, promiscuous mode
│   ├── parser.c             # bounds-checked header decoding
│   ├── filter.c             # CIDR, port, proto parsing + matching
│   ├── flow_table.c         # FNV-1a, linear probing, bounded worst case
│   ├── stats.c              # table / JSON formatters
│   └── pcap_writer.c        # libpcap global + record headers
├── tests/
│   ├── test_framework.h     # 60-line micro test runner
│   ├── test_parser.c
│   ├── test_filter.c
│   └── test_flow_table.c
└── docs/
    └── DESIGN.md            # data-structure and protocol decisions
```

---

## Requirements & constraints

- **Platform**: Linux only (`AF_PACKET`, `linux/if_packet.h`)
- **Privilege**: `CAP_NET_RAW` (sudo or `setcap`) — required to bind a raw socket
- **Throughput**: benchmarked ~250 kpps on an idle Ubuntu 22.04 VM with a
  single captured ring buffer entry; the bottleneck is `recv()` syscall rate,
  not parsing. Adding `PACKET_MMAP` would raise this by roughly an order of
  magnitude — see DESIGN.md.
- **Memory**: bounded. Flow table is a single `calloc(65536, sizeof(flow_entry_t))`
  at startup — ~2 MB. When full, new flows are dropped (counter exposed) rather
  than letting the table grow unbounded.
- **Correctness**: compiles clean with `-Wall -Wextra -Werror -Wshadow
  -Wstrict-prototypes`. Parser truncation cases all have unit tests.

---

## What this project demonstrates

- Direct `AF_PACKET` / raw socket programming — foundational for any
  kernel-bypass or network-data-plane role
- Byte-level protocol decoding with explicit endianness handling (`ntohs`,
  `ntohl`, `memcpy` for unaligned loads)
- Defensive parsing: every length field is validated before use; crafted
  packets cannot cause OOB reads
- Open-addressing hash table with linear probing, FNV-1a hashing, bounded
  worst-case probe distance — no standard-library containers used
- Clean C11 ABI: packed structs for hashable keys, opaque handles, module
  boundaries enforced by separate headers
- Zero external dependencies — everything builds from a single Makefile
