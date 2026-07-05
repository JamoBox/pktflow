# 03.2 — Registry & router builder

> Task: [03 Router](README.md) · Depends on: 03.1, 02.3 · PRD: FR-12

## Goal
One-call assembly: register plugins, auto-install their claimed routes, apply manual
overrides that always win, enroll the fallback pool — producing an immutable, shareable
router (D5).

## Specification

```rust
pub struct EngineBuilder { /* plugins, overrides, pool flags */ }
impl EngineBuilder {
    pub fn plugin(self, p: impl LayerPlugin + 'static) -> Self;         // registers + auto-routes claims
    pub fn route(self, id: RouteId, protocol: ProtocolName) -> Self;    // manual override (FR-12)
    pub fn unroute(self, id: RouteId) -> Self;                          // kill an auto route
    pub fn build(self) -> Result<Engine, RegistryError>;                // validates everything
}

pub struct Engine {  // immutable after build; Send + Sync
    registry: PluginRegistry,        // name → &dyn LayerPlugin
    routes: HashMap<RouteId, PluginIdx>,
    fallback_pool: Vec<PluginIdx>,   // every plugin with a probe, registration order
}
```

Build-time validation (all failures are `RegistryError` values naming the culprits):

1. **Duplicate plugin name** → error (names are the `ByProtocol`/cross-layer namespace).
2. **Claim collision** — two plugins claim one `RouteId` → error unless a manual
   `route()`/`unroute()` resolves that id (manual always wins, FR-12).
3. **Dangling override** — `route(id, name)` naming an unregistered plugin → error.
4. **Stream-identity sanity** — every `KeyField`/`RollupSpec` field name declared by a
   plugin's `StreamIdentity` is checked for basic well-formedness (non-empty; deep check of
   "actually extracted" is runtime, owned by 09.1).

Fallback pool = all plugins whose `probe` is overridden (detected by a registration flag the
plugin sets, or simply: plugins are enrolled unless probe returns `None` — measured at
build via a zero-byte probe call is *not* acceptable; use an explicit `has_probe()`
defaulted method returning `false`). Pool order = registration order (the determinism
tiebreak, 03.3).

## Acceptance criteria
- [x] Builder + validations implemented; each of the four error cases unit-tested.
- [x] `Engine: Send + Sync`, no interior mutability; shareable via `Arc<Engine>`.
- [x] Manual override demonstrably beats a claim in a routing test.
- [x] Registering the same plugin set in two different orders yields identical route tables
      (order only matters for the fallback pool, where it is preserved as documented).
