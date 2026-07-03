# Adding a protocol

The whole job is one new file plus one registration line. Budget: well
under an hour (PRD §8 — the template exists to keep it that way).

1. **Copy the template.** `cp crates/pktflow-plugins/src/template.rs
   crates/pktflow-plugins/src/<your_protocol>.rs`, rename `Template` and
   the `name()` string (lowercase snake_case, unique).
2. **Fill in your header.** Replace the PKTT fields with your protocol's:
   field-name constants at the top, `parse()` reading through `ByteReader`
   only (no indexing), fields gated on `ctx.depth()` — flow-key fields at
   `>= Keys`, structure at `>= Structural`, everything else at `Full`.
   Return the most explicit `Hint` your header allows; decline with
   `ParseError` when the bytes aren't yours.
3. **Declare how you're reached.** `claims()` with your route ids
   (EtherType, IP protocol, ports, or a `Custom` space). Add an honest
   `probe()` + `has_probe()` only if your header is recognizably
   structured; most protocols should skip it.
4. **Declare your streams.** `stream_identity()` with the endpoint
   `KeyField`s and any rollups. Return `None` if your layer qualifies its
   parent instead of forming conversations (see vlan).
5. **Register it.** Add one `.plugin(your_protocol::YourProtocol)` line to
   `default_engine()` in `crates/pktflow-plugins/src/lib.rs`. Duplicate
   names or route claims fail the build with an error naming both parties.
6. **Test it.** Keep the in-file tests (fixture parse from real capture
   bytes with a source comment, truncation, hint). Then add a
   `ConformanceCase` for your plugin in `tests/conformance.rs` — the 09.1
   kit mechanically checks truncation safety, depth monotonicity, flow-key
   coherence/involution, header honesty, probe honesty, and lifecycle
   totality for you.

Run `just ci`. If the registry build or the kit rejects your plugin, the
message names the rule it violated.
