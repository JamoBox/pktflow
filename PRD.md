# Product Requirements Document — Network Traffic Stream-Understanding Engine

*Working title: **pktman** (rebuild). Derived from an analysis of the existing codebase's
fundamental concepts, then re-centered on the bigger picture: understanding **streams and
conversations** within captured traffic, not just individual packets. Implementation details
are deliberately excluded so we are free to re-decide them together during the build.*

---

## 1. Summary

We are building an engine that turns captured network traffic into an understanding of the
**streams of data flowing through it**. Individual packets are the raw input, but they are
not the unit we care about. What we care about is the **conversations** and **sessions** that
packets belong to — a TCP 5-tuple session, a UDP 5-tuple stream, a MAC-to-MAC conversation,
an IP-to-IP conversation — and the **protocol metadata that accumulates across each stream**.

To get there we still need to dissect each packet into an ordered stack of **protocol
layers** carrying **structured field metadata**. That dissection is done by **independent,
self-describing plugins**, one per protocol — the engine holds no protocol knowledge itself.
But dissection is the *substrate*. On top of it sits the real product: a **flow-aggregation
layer** that groups packets into streams at every protocol level, rolls their metadata up
over time, and lets a caller reason about the traffic as a set of ongoing conversations.

The product exists so that (a) adding support for a new protocol is one self-contained plugin,
and (b) that plugin's data automatically becomes part of the stream-level picture — its
endpoints define conversations, and its fields become part of the metadata stream.

---

## 2. Problem & motivation

A packet in isolation tells you almost nothing useful. "One TCP segment from A:443 to B:52341
with the ACK flag set" is noise. The signal is: *A and B have an established session, it's
carried inside their IP conversation, which rides on a MAC conversation, and over its
lifetime it has exchanged N segments, this much data, this metadata.* Understanding traffic
means understanding **streams**, not packets.

Traditional per-packet parsers stop at dissection and leave stream reconstruction to the
caller. And they hard-code a monolithic decode tree, which is:

- **Closed to extension.** Adding a protocol means editing central dispatch logic.
- **Tightly coupled.** Protocols know about each other; a change ripples.
- **All-or-nothing work.** They extract every field of every layer even when the caller only
  wanted enough to identify the conversation.
- **Brittle on the unknown.** Encrypted/proprietary payloads get force-fit into whatever the
  decode tree guesses next.
- **Stream-blind.** They have no concept of a conversation, so the higher-order picture —
  who is talking to whom, in what protocol, carrying what — has to be rebuilt from scratch
  downstream, differently for every protocol.

We want a design where protocol logic is **modular** and **self-registering**, dissection is
**lazy** and **safe on the unknown**, and — the new center of gravity — packets are
**automatically aggregated into the streams they belong to**, with metadata rolled up per
stream, at every layer of the stack.

---

## 3. Goals and non-goals

### Goals
- **Stream/conversation as the primary output.** Group packets into conversations and
  sessions at every protocol layer (MAC, IP, TCP, UDP, and any protocol a plugin describes),
  keyed by that layer's notion of identity.
- **Protocol metadata streams.** For each stream, accumulate and summarize the metadata its
  packets carry over time (counts, byte totals, per-direction stats, first/last seen, and a
  time-ordered series of per-packet field values where it matters).
- **Layered flow hierarchy.** Represent how streams nest — a MAC conversation contains IP
  conversations, which contain transport sessions — so traffic can be explored top-down.
- **Bidirectional, canonicalized identity.** A→B and B→A fold into one conversation while
  still tracking each direction separately.
- **Protocol-defined stream identity.** Each plugin declares what makes a stream for its
  protocol (its endpoint/identity fields and how to canonicalize direction), so new protocols
  gain stream semantics without engine changes.
- **A plugin contract** for per-packet dissection: one interface every protocol satisfies.
- **A routing engine** dispatching between layers using explicit signals first, heuristics
  only as fallback, and **safe termination on the unknown**.
- **Lazy, layer-at-a-time** dissection feeding the aggregator.
- **Caller-controlled extraction depth** — how much metadata is worth computing per packet.
- **Cross-layer context** — a plugin can read fields already extracted by outer layers.
- **Encapsulation/tunneling** as a first-class case (inner stream nested under the tunnel).
- A **reference plugin set** and a **CLI** for live capture and offline replay that reports
  at the stream level, not just packet by packet.

### Non-goals (for the first build)
- Full application-layer **content reconstruction** (reassembling and parsing TCP payload
  bodies, TLS decryption, file carving). We track stream *metadata*, not reassembled content.
- Packet *rewriting*, injection, or crafting. Read/dissect/aggregate only.
- Deep protocol *analytics* beyond metadata aggregation (e.g. anomaly detection, alerting) —
  the engine should make these buildable on top, but they are out of scope for v1.
- A GUI. The deliverable UI is a CLI; a library API is the primary surface.

> Note: earlier framing treated flow/stream tracking as a non-goal. That is now the core of
> the product. Per-packet dissection is retained as the necessary substrate beneath it.

---

## 4. Core concepts (the fundamental model)

Two layers of concepts: the **dissection substrate** (how bytes become layers) and the
**stream model** (how layers become conversations). The stream model is the point; the
substrate exists to feed it.

### 4.A Stream model (the primary layer)

| Concept | Definition |
|---|---|
| **Flow Key** | The set of fields that identify a stream at a given protocol layer — e.g. TCP's 5-tuple, IP's address pair, Ethernet's MAC pair. |
| **Conversation** | A bidirectional aggregate of all packets sharing one canonicalized flow key at one layer. A→B and B→A belong to the same conversation. |
| **Stream / Session** | A conversation with protocol-specific character: a UDP 5-tuple stream, or a TCP session that additionally has a lifecycle (setup, established, teardown). "Stream" is the general term; "conversation" and "session" are its layer-specific flavors. |
| **Flow Hierarchy** | The nesting of streams across layers: a MAC conversation contains IP conversations, which contain transport sessions, which may contain tunneled inner streams. |
| **Metadata Stream** | The metadata rolled up under a stream: aggregate stats (packet/byte counts, per-direction totals, first/last seen, duration) plus, where relevant, a time-ordered series of per-packet field values. |
| **Direction Canonicalization** | The rule that maps both directions of a stream to a single identity while preserving per-direction accounting. |

Key ideas:

- **Every layer can define a stream.** Identity is not a TCP-only concept. Ethernet defines
  MAC conversations, IP defines IP conversations, transport defines sessions/streams, and any
  future protocol defines whatever "a stream of this protocol" means for it.
- **Streams are protocol-defined, engine-aggregated.** A plugin says *what identifies a stream
  of my protocol* and *how to canonicalize its direction*. The engine does the actual grouping,
  indexing, hierarchy-building, and rollup — uniformly, for every protocol.
- **Streams nest.** A packet contributes to one stream per layer it has, and those streams
  are linked parent→child by the layer order in that packet. This yields a browsable tree:
  from a MAC conversation down to the individual sessions inside it.
- **Metadata accumulates.** As packets arrive, each stream's rolled-up metadata updates:
  counters, per-direction byte/packet totals, timing, and protocol-specific summaries (e.g.
  the set of TCP flags seen, the DNS query names observed in a UDP stream, the observed
  session state).
- **Stateful over the capture, not just the packet.** The aggregator is long-lived: it holds
  the evolving set of streams across the whole capture (or live session), whereas a single
  dissection is momentary.

### 4.B Dissection substrate (feeds the stream model)

| Concept | Definition |
|---|---|
| **Layer** | One parsed protocol header in a packet: its name, offset, and header length. |
| **Layer Plugin** | A self-contained unit that parses exactly one protocol *and* describes that protocol's stream identity. |
| **Metadata** | The structured field values a plugin extracts from its header, as a small named map of typed values. |
| **Parse Context** | What a plugin is handed each call: metadata of all outer layers already parsed, plus requested extraction depth. |
| **Next-Layer Hint** | What a plugin returns to say what comes next, so the router doesn't guess. |
| **Router** | Turns a hint into "which plugin parses the next layer." |
| **Lazy Parser** | An iterator yielding one parsed layer per step until something says stop. |
| **Extraction Depth** | Caller-set level controlling how much metadata plugins extract. |

#### 4.B.1 Plugins are self-describing (dissection *and* stream identity)
A plugin declares its **name** and how to **parse** its header. Optionally it also declares:
- **What it claims** — the protocol identifiers it natively handles (e.g. "I am EtherType
  0x0800"), so routing wires up automatically.
- **What it expects to follow** — layers it typically sits behind, to bias heuristic guesses.
- **A probe** — a confidence score that it can parse given raw bytes; used only in fallback.
- **Its stream identity** *(new)* — which of its metadata fields form the flow key, and how to
  canonicalize direction, so the engine can aggregate this protocol into conversations. A
  plugin may also declare optional **stream state semantics** (e.g. how header flags advance a
  session lifecycle) and **rollup hints** (which fields to accumulate vs. sample vs. keep as a
  series).

A plugin with no declared stream identity still dissects fine; its layer simply doesn't
create a conversation of its own (it still contributes to the streams of the layers that do).

#### 4.B.2 Dissection is lazy and layer-by-layer
The parser yields one layer per step: pick a plugin, parse one header, emit the layer, its
metadata, the remaining payload, and a hint for what's next. The caller (typically the
aggregator) consumes as many layers as it needs.

#### 4.B.3 Routing is two-tiered
1. **Explicit (preferred).** A header field names what follows (EtherType, IP protocol, port).
   The plugin surfaces it as a hint; the router resolves it in one lookup. Hint kinds:
   single definite id; ranked candidate ids; **direct-by-name** dispatch (encapsulation — an
   outer tunnel that always wraps the same inner protocol); "unknown"; "terminal."
2. **Heuristic (fallback).** No usable route, or the routed plugin failed to parse ⇒ plugins
   in a fallback pool score the remaining bytes; highest wins, with a **predecessor prior**
   boosting plugins whose expected predecessor matches the layer just parsed.

#### 4.B.4 Safety on the unknown
Fallback is **gated**. If a layer named a next protocol that no plugin claims, the payload is
unsupported/encrypted — the parser **stops** rather than force-fitting opaque bytes. (The
motivating failure: encrypted UDP payload "recognized" as TCP → IPv6 → TCP forever.) This
matters doubly for streams: a misidentified layer would fabricate a bogus conversation.

#### 4.B.5 Extraction depth is caller-controlled
Depth levels (*none / key identifiers / structural / everything*). Crucially, the **flow-key
fields must be extracted whenever stream aggregation is on**, even at low depth — you cannot
aggregate a stream whose endpoints you didn't extract. So "key identifiers" is the natural
floor for stream mode: enough to identify conversations cheaply on a high-throughput path,
with fuller field capture reserved for deep inspection.

#### 4.B.6 Cross-layer context
A plugin can read metadata outer layers already produced (e.g. an app-layer plugin reading
the transport port for framing). On repeats (nested tunnels, stacked tags) it reaches the
nearest (innermost) occurrence. The stream hierarchy uses the same outer→inner layer order to
nest conversations.

---

## 5. Users & use cases

- **Protocol-plugin authors** (primary). Add a protocol without touching the engine, and by
  declaring its stream identity, get conversation/stream aggregation for free.
- **Traffic analysts** wanting the shape of a capture: who talks to whom, in what protocols,
  how much, for how long — the conversation list, not the packet list.
- **Tool builders** embedding the engine to reason about live or captured traffic as streams.
- **CLI end-users** (network engineers, learners) exploring a capture's conversations from the
  terminal.

### Representative use cases
1. Load a capture and list its **conversations** at each layer (MAC, IP, TCP session, UDP
   stream) with per-stream packet/byte counts, direction split, and duration.
2. Drill into one TCP session and see its rolled-up metadata stream (flags seen, lifecycle
   state, timing, byte totals per direction).
3. Live-capture and watch streams form and update in real time.
4. Explore the **flow hierarchy**: pick a MAC conversation, expand to its IP conversations,
   then to the sessions within.
5. Add a new protocol as a plugin and immediately see its streams appear in the aggregated
   view — endpoints as conversations, fields as metadata stream.
6. Correctly attribute tunneled inner traffic as a **nested** stream under the tunnel session.
7. Safely **stop** at the last understood layer on encrypted/unknown payloads — without
   inventing a phantom conversation.

---

## 6. Functional requirements

### Stream / aggregation layer (primary)
- **FR-1** A long-lived **aggregator** that consumes dissected packets and maintains the
  evolving set of streams across a whole capture or live session.
- **FR-2** Group packets into **conversations at every layer** that declares stream identity,
  keyed by that layer's flow key.
- **FR-3** **Canonicalize direction** so both directions of a stream share one identity, while
  tracking per-direction packet counts, byte counts, and timing.
- **FR-4** Maintain the **flow hierarchy** — link each layer's stream to its parent (the outer
  layer's stream) and children (inner layers), so streams are browsable top-down.
- **FR-5** Maintain a **metadata stream per conversation**: at minimum first/last seen,
  duration, total and per-direction packet/byte counts; plus protocol-specific rollups a
  plugin asks for (accumulated set, sampled value, or time-ordered series).
- **FR-6** Support **stream state/lifecycle** where a plugin defines it (e.g. TCP session
  setup/established/teardown derived from flags).
- **FR-7** Query/iterate streams: list conversations at a chosen layer, fetch one stream's
  rolled-up metadata, and traverse the hierarchy.
- **FR-8** Correctly nest **tunneled/encapsulated** inner streams beneath their outer stream.

### Dissection substrate
- **FR-9** A single plugin interface: required *name* + *parse*; optional *claims*,
  *expected predecessors*, *probe*, and *stream identity* (flow-key fields + direction
  canonicalization, with optional state and rollup hints).
- **FR-10** Dissection yields per layer: name, offset, header length, typed metadata map,
  remaining payload, and a next-layer hint.
- **FR-11** All hint kinds (single id, ranked candidates, direct-by-name, unknown, terminal).
- **FR-12** Router builder: auto-install routes from plugin *claims*; allow manual route
  overrides (always win over claims); enroll all plugins into the fallback pool in one call.
- **FR-13** Lazy iterator parser: one layer per step; known entry protocol *or* heuristic
  first-layer identification.
- **FR-14** Heuristic fallback with predecessor-prior weighting and deterministic tie-breaking.
- **FR-15** Gated fallback — stop rather than misidentify when a named route is unclaimed;
  never re-select a plugin that just failed on the same bytes.
- **FR-16** Extraction-depth levels honored by every plugin; flow-key fields always extracted
  when aggregation is enabled, regardless of depth floor.
- **FR-17** Cross-layer field lookup by protocol and field name, resolving to the innermost
  occurrence on repeats.
- **FR-18** Typed metadata values covering at least: byte sequences, unsigned/signed integers,
  booleans, strings, and ordered lists.

### Reference plugins
- **FR-19** Ship a set covering the common stack with stream identity declared where it makes
  sense: link (Ethernet → MAC conversation; VLAN tag), network (IPv4/IPv6 → IP conversation;
  ARP; ICMP; IGMP), transport (TCP → 5-tuple session with lifecycle; UDP → 5-tuple stream),
  tunneling (GRE, VXLAN → nested inner stream), application (DNS, DHCP, NTP → metadata rollups
  such as query names / message types).
- **FR-20** A minimal "reference/dummy" plugin as a copyable template showing both dissection
  and stream-identity declaration.
- **FR-21** At least one plugin demonstrating each of: a MAC conversation, an IP conversation,
  a TCP session with lifecycle state, a UDP stream, and a tunneled nested stream.

### CLI
- **FR-22** Read packets from a capture file **or** live-capture from a named interface.
- **FR-23** List available interfaces.
- **FR-24** A **conversation/stream view**: list streams at a chosen layer with per-stream
  counts, direction split, duration, and key metadata — the default lens, not per-packet.
- **FR-25** Drill-down into a single stream to print its rolled-up metadata stream and (where
  defined) its lifecycle state.
- **FR-26** A per-packet mode retained for debugging: summary line + optional per-layer fields
  under a verbosity/depth flag.
- **FR-27** Optional cap on packets processed; report totals, stream counts, and parse
  failures at the end.
- **FR-28** Human-friendly rendering of well-known fields (MAC, IPv4, IPv6) and typed values.

---

## 7. Non-functional requirements

- **Extensibility first.** Adding a protocol — including its stream semantics — must not
  require editing the engine or any other plugin.
- **Stateful memory discipline.** The aggregator holds live state for the whole capture, so
  stream storage must be bounded and predictable; long/live captures must not grow without
  limit (define eviction/expiry strategy as a decision below).
- **Performance.** Per-packet dissection + aggregation must stay cheap enough for live
  capture; the lazy path, depth control, and the "key identifiers" floor exist to serve this.
- **Determinism.** Same input + same registered plugins ⇒ same streams and same rollups.
- **Concurrency-friendly.** Engine/router shareable across threads; define the aggregator's
  concurrency model (single-writer vs. sharded) as a decision below.
- **Robustness.** Malformed/truncated input must never panic; unparseable ⇒ decline, and must
  never fabricate a phantom stream.
- **Cross-platform.** At least Linux and Windows for the capture CLI.
- **Testability.** Plugins unit-testable in isolation (bytes → layer + fields + hint + flow
  key); aggregation testable end-to-end (a synthetic multi-packet capture → expected streams,
  hierarchy, and rollups).

---

## 8. Success metrics
- **Time-to-new-protocol:** an author adds a working plugin — dissection *and* stream identity
  — in well under an hour, touching only their own new file plus a registration list, and its
  conversations appear in the aggregated view with no engine changes.
- **Stream fidelity:** on a known capture, the engine's conversation list and per-stream
  counts match an established reference tool's flow accounting.
- **Correct nesting:** tunneled traffic is attributed as nested streams under the tunnel.
- **No phantom streams:** unknown/encrypted payloads never create a conversation.
- **Depth pays off:** the "key identifiers" floor aggregates streams at materially lower cost
  than full field extraction on a fixed capture.

---

## 9. Open questions / decisions to make together
1. **Implementation language & capture backend.** Reference is Rust + libpcap/Npcap — keep or
   reconsider?
2. **Stream lifetime & eviction.** How long does a stream stay live? Idle timeout, explicit
   TCP-teardown close, capture-end flush, LRU cap? This governs memory for live captures.
3. **Direction canonicalization rule.** Endpoint sorting for the general case, plus how to
   record the "initiator" (who sent the first packet) for session semantics.
4. **How much of a metadata stream to retain.** Pure aggregates only, bounded samples, or full
   time-ordered series per field — and which fields warrant which.
5. **Aggregator concurrency model.** Single-writer, per-flow sharding, or lock-free index.
6. **Scope of v1 protocol set** and which stream semantics are must-have vs. later.
7. **Content vs. metadata boundary.** Confirm we track stream *metadata* only in v1 (no TCP
   payload reassembly / body parsing).
8. **Output formats.** Human text only for v1, or also a structured (JSON) stream emit for
   downstream tooling.
9. **Error surfacing.** How much to tell the user about why dissection stopped (unknown vs.
   truncated vs. unclaimed route) and how that reflects in the stream view.

---

## 10. Glossary
- **Frame / packet** — one captured byte buffer; the raw input, not the unit of interest.
- **Layer** — one protocol header within a packet.
- **Stack** — the ordered layers of one packet, outermost (link) to innermost (payload).
- **Flow key** — the fields identifying a stream at a given layer.
- **Conversation** — a bidirectional aggregate of packets sharing a canonicalized flow key at
  one layer (MAC conversation, IP conversation).
- **Stream / Session** — a conversation with protocol character (UDP stream, TCP session with
  lifecycle). "Stream" is the general term used throughout.
- **Flow hierarchy** — the nesting of streams across layers.
- **Metadata stream** — the metadata rolled up over a stream's lifetime.
- **Hint** — a plugin's declaration of what protocol follows its layer.
- **Route** — a mapping from a protocol identifier to the plugin that handles it.
- **Probe** — a plugin's self-scored confidence it can parse some bytes; used only in fallback.
- **Encapsulation / tunneling** — an outer protocol carrying a full inner stack, aggregated as
  a nested stream.
