# 12.14 — Data-centre fabric & RPC: RoCEv2, SunRPC, PROXY protocol, GRETAP

> Task: [12 Contrib library](README.md) · Depends on: 02–06 · Cross-refs: 06.5 (`gre`),
> 11.9 (`nfs` — its D15 portmapper note is this file's `sunrpc` entry seen from the other
> side) · PRD: FR-32 · D7, D14, D15, D16

## Goal
The east-west traffic of a modern data centre that the stdlib's overlay/messaging coverage
doesn't touch: kernel-bypass storage/compute fabrics (RoCEv2 — what NVMe-oF, GPUDirect and
distributed training actually ride on), the RPC layer under the NFS ecosystem, the
load-balancer prefix every proxied connection in a k8s/HAProxy shop carries, and the
plain-Ethernet-over-GRE encapsulation (NVGRE's substrate) that completes 06.5/11.5's
overlay family.

## Specification

**rocev2** (RoCEv2 — InfiniBand Architecture Specification (IBTA), Annex A17; the IB Base
Transport Header it carries is IBTA vol. 1).

| Item | Spec |
|---|---|
| Claims | `UdpPort(4791)` (IANA-assigned RoCEv2 entropy port) |
| Fields | `Keys`: `dest_qp` (24-bit destination queue pair) · `Structural`: `opcode` (BTH opcode byte, decoded to transport class + operation: RC/UC/RD/UD × SEND/RDMA WRITE/RDMA READ REQUEST/RDMA READ RESPONSE/ACK/ATOMIC/...), `se` (solicited event), `migreq`, `pad_count`, `pkey`, `psn` (24-bit) · `Full`: RETH (when the opcode carries it) → `rdma_length` (the advertised transfer size — counted, never captured: D7 for zero-copy traffic) |
| Hint | `Terminal` — payload is application/storage data; the trailing ICRC is recognized by length, not verified |
| Identity | key `[{dest_qp, None}]` — queue pairs are unidirectional like ESP SPIs (11.5): each direction of a connection targets a different QP, so one RC connection appears as two sibling `rocev2` streams under the parent UDP stream. Correct fabric semantics, documented exactly as `esp` documents it, not a modeling gap |
| Rollups | `Accumulate` on `opcode`; `Sample` on `pkey` |

**sunrpc** (ONC RPC v2, RFC 5531; portmapper/rpcbind, RFC 1833).

| Item | Spec |
|---|---|
| Claims | `TcpPort(111)`, `UdpPort(111)` — rpcbind/portmapper itself. 11.9's `nfs` parses its own RPC envelope on 2049 and deliberately does not claim 111 (its D15 note); this entry is that note's other half: the *negotiation* traffic becomes visible, the negotiated-port continuation stays architecturally invisible (D15, stated there once) |
| Fields | `Keys`: `app` (shared, constant `Str("sunrpc")`) · `Structural`: `xid`, `msg_type` (0 CALL/1 REPLY), TCP framing → `record_len` (the record-marking fragment header) · `Full` (CALL): `program` (U64 plus Str-decoded well-known names — 100000 portmap/100003 nfs/100005 mountd/100021 nlm/100024 status), `version`, `procedure` (for portmap: NULL/SET/UNSET/GETPORT/DUMP), `auth_flavor` (AUTH_NONE/AUTH_SYS/RPCSEC_GSS); (REPLY): `accept_state`; a GETPORT reply's returned port is extracted as `granted_port` — visible as a field, never registered as a route (D15) |
| Hint | `Terminal` |
| Identity | key `[{app, None}]`, one child per transport stream |
| Rollups | `Accumulate` on `program`; `Accumulate` on `procedure` |

**proxy_protocol** (HAProxy PROXY protocol v1/v2 — the HAProxy project's
`proxy-protocol.txt`; *no standards body*, but the de facto standard for AWS
NLB/ELB, HAProxy, nginx, and most cloud load-balancer passthrough).

| Item | Spec |
|---|---|
| Claims | **none** — the header prefixes arbitrary TCP services on whatever port the backend uses; a static claim is impossible by design. Probe-only admission |
| Probe | v2: the 12-byte signature `\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A` → maximal (a 12-byte magic). v1: leading `PROXY ` + a family token (`TCP4`/`TCP6`/`UNKNOWN`) → high |
| Fields | `Structural`: `pp_version` (1/2), `command` (v2: LOCAL/PROXY), `family` (TCP4/TCP6/UNIX/UNKNOWN) · `Full`: `orig_src_addr`, `orig_dst_addr`, `orig_src_port`, `orig_dst_port` (the *real* client endpoints the balancer is relaying — the entire analytic value: the capture's IP layer shows the balancer, these fields show the truth), v2 → `tlv_count` (TLVs counted, not decoded) |
| Hint | `Terminal` — the proxied protocol follows immediately in the same connection, but its identity is keyed to `orig_dst_port`, not this connection's port, so re-entering port-based routing would be dishonest; D15's shape one layer up. The extracted endpoint fields are the deliverable |
| Identity | none — a one-shot prefix on a connection's first segment; contributes fields to the packet view and stats to the parent TCP session |
| Rollups | n/a (identity-less) |

**gretap** (Transparent Ethernet Bridging over GRE — EtherType 0x6558 per the GRE
conventions of RFC 1701/2784; NVGRE, RFC 7637, uses this identical encapsulation with the
GRE key carrying the VSID).

| Item | Spec |
|---|---|
| Claims | `EtherType(0x6558)` — reachable through the **unmodified** 06.5 `gre` exactly like `erspan` (12.2): the stdlib has been emitting this route unclaimed since task 06; contrib supplies the claim side |
| Fields | `Structural`: `encap` (shared, constant `Str("gretap")`) — the header is zero-length; this plugin is a pure dispatch shim, and says so rather than inventing fields |
| Hint | `ByProtocol("ethernet")` — a complete inner L2 frame (vxlan's pattern, 06.5) |
| Identity | none of its own — tunnel identity is already the `gre` key stream above it (06.5), which for NVGRE *is* the VSID (upper 24 bits of the key; a rendering refinement of `gre`'s existing field, noted for the Tier-2 row, not new parsing here) |
| Rollups | n/a |

### Planned (Tier 2 — not yet specified)
| Protocol | Standard | Note |
|---|---|---|
| Apache Thrift (framed binary) | *Project doc* — Apache Thrift protocol spec | No fixed port (D15-adjacent); framed-transport length + version word `0x8001` is a workable probe |
| OVSDB | RFC 7047 | `TcpPort(6640)`; JSON-RPC — method-name extraction, `mongodb`'s bounded-first-key stance |
| Elasticsearch transport | *Project doc* (Elastic) | `TcpPort(9300)`; `ES` magic header |
| Serf / memberlist gossip | *Project doc* (HashiCorp) | `UdpPort(8301)` region; Consul's cluster chatter, msgpack-framed |
| Aeron | *Project doc* (real-logic) | UDP unicast/multicast, no fixed port; frame-header version/type |
| iWARP MPA | RFC 5044 | RDMA over plain TCP — the RoCE alternative; MPA request frame carries a 16-byte key string |
| FCIP | RFC 3821 | `TcpPort(3225)`; FC frame encapsulation over WAN |
| NVGRE VSID rendering | RFC 7637 | A `gre`-field rendering refinement (see `gretap` above), not a plugin |
| gRPC / etcd / gNMI / OTLP-gRPC | — | All ride HTTP/2 (11.8's `http2`, and gRPC is already 11.8's Tier 2) — cross-referenced so this file's taxonomy shows the DC control plane was placed, not missed |

## Acceptance criteria
- [ ] `rocev2` fixture: an RC SEND + RDMA WRITE + ACK exchange parses opcode/QP/PSN
      exactly; the two directions of one connection form two sibling `dest_qp` streams
      (the ESP-shape criterion, ported); RDMA payload bytes appear in no field.
- [ ] `sunrpc` fixture: a portmap GETPORT call/reply pair for NFS (program 100003) parses
      program/procedure/`granted_port` exactly, and no stream or route exists on the
      granted port afterwards (the D15 criterion, tested the way 11.9 tests PASV); a
      TCP-framed call exercises the record-marking header.
- [ ] `proxy_protocol` fixtures: v2 signature and v1 text header both admitted via the
      fallback pool on two different backend ports (proving port-independence); original
      endpoint fields extracted exactly; a near-miss (`PROXY` without valid family)
      declines.
- [ ] `gretap` fixture: `gre ▸ gretap ▸ ethernet ▸ ipv4 ▸ ...` nests a full inner stack
      with zero stdlib edits (the 12.2 `erspan` criterion shape); an NVGRE-style keyed
      fixture shows the key stream from `gre` untouched above the shim.
