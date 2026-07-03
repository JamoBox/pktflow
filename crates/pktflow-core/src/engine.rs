//! Registry & router builder (03.2, FR-12).
//!
//! One-call assembly: register plugins, auto-install their claimed routes,
//! apply manual overrides that always win, enroll the fallback pool — an
//! immutable, shareable [`Engine`] comes out (D5).

use std::collections::hash_map::Entry;
use std::collections::HashMap;

use crate::packet::ProtocolName;
use crate::plugin::LayerPlugin;
use crate::route::RouteId;
use crate::stream::RollupKind;

/// Index into the engine's plugin table.
type PluginIdx = usize;

/// A build-time registry failure, naming the culprits. Silent shadowing is
/// how decode trees rot, so every ambiguity is an error, not a warning.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RegistryError {
    /// Names are the `ByProtocol`/cross-layer namespace — one owner each.
    #[error("duplicate plugin name {name:?}")]
    DuplicateName { name: ProtocolName },
    /// Two plugins claim one route id; resolve with an explicit
    /// `route()`/`unroute()` override (manual always wins, FR-12).
    #[error("route {id} claimed by both {first:?} and {second:?}; add a manual route()/unroute() to resolve")]
    ClaimCollision {
        id: RouteId,
        first: ProtocolName,
        second: ProtocolName,
    },
    /// A manual `route(id, name)` names a plugin that was never registered.
    #[error("manual route for {id} names unregistered plugin {name:?}")]
    DanglingOverride { id: RouteId, name: ProtocolName },
    /// A `StreamIdentity` declaration is statically malformed.
    #[error("plugin {plugin:?} has an invalid stream identity: {reason}")]
    InvalidIdentity {
        plugin: ProtocolName,
        reason: &'static str,
    },
}

/// Builder for [`Engine`]: `plugin(..).plugin(..).route(..).build()`.
#[derive(Default)]
pub struct EngineBuilder {
    plugins: Vec<Box<dyn LayerPlugin>>,
    overrides: Vec<(RouteId, ProtocolName)>,
    unroutes: Vec<RouteId>,
}

impl EngineBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a plugin and auto-installs routes for its `claims()`.
    pub fn plugin(mut self, p: impl LayerPlugin + 'static) -> Self {
        self.plugins.push(Box::new(p));
        self
    }

    /// Manual override (FR-12): this id dispatches to `protocol`,
    /// regardless of claims. Manual routes always win.
    pub fn route(mut self, id: RouteId, protocol: ProtocolName) -> Self {
        self.overrides.push((id, protocol));
        self
    }

    /// Kills an auto-installed route (also a valid way to resolve a claim
    /// collision by removing the id entirely).
    pub fn unroute(mut self, id: RouteId) -> Self {
        self.unroutes.push(id);
        self
    }

    /// Validates everything and produces the immutable engine.
    pub fn build(self) -> Result<Engine, RegistryError> {
        let EngineBuilder {
            plugins,
            overrides,
            unroutes,
        } = self;

        // 1. Duplicate plugin names.
        let mut by_name: HashMap<ProtocolName, PluginIdx> = HashMap::new();
        for (idx, p) in plugins.iter().enumerate() {
            if by_name.insert(p.name(), idx).is_some() {
                return Err(RegistryError::DuplicateName { name: p.name() });
            }
        }

        // 2. Auto-install claims, recording collisions.
        let mut routes: HashMap<RouteId, PluginIdx> = HashMap::new();
        let mut collisions: Vec<(RouteId, PluginIdx, PluginIdx)> = Vec::new();
        for (idx, p) in plugins.iter().enumerate() {
            for &id in p.claims() {
                match routes.entry(id) {
                    Entry::Occupied(e) => collisions.push((id, *e.get(), idx)),
                    Entry::Vacant(v) => {
                        v.insert(idx);
                    }
                }
            }
        }

        // Manual resolution: unroute removes the id, route re-targets it —
        // either settles a collision on that id.
        for id in &unroutes {
            routes.remove(id);
            collisions.retain(|(cid, _, _)| cid != id);
        }
        for &(id, name) in &overrides {
            let Some(&idx) = by_name.get(name) else {
                // 3. Dangling override.
                return Err(RegistryError::DanglingOverride { id, name });
            };
            routes.insert(id, idx);
            collisions.retain(|&(cid, _, _)| cid != id);
        }
        if let Some(&(id, first, second)) = collisions.first() {
            return Err(RegistryError::ClaimCollision {
                id,
                first: plugins[first].name(),
                second: plugins[second].name(),
            });
        }

        // 4. Stream-identity static sanity (deep "actually extracted"
        // checking is runtime, owned by 09.1).
        for p in &plugins {
            let Some(identity) = p.stream_identity() else {
                continue;
            };
            for kf in identity.key {
                if kf.a.is_empty() || kf.b.is_some_and(str::is_empty) {
                    return Err(RegistryError::InvalidIdentity {
                        plugin: p.name(),
                        reason: "empty key field name",
                    });
                }
            }
            for r in identity.rollups {
                if r.field.is_empty() {
                    return Err(RegistryError::InvalidIdentity {
                        plugin: p.name(),
                        reason: "empty rollup field name",
                    });
                }
                if matches!(r.kind, RollupKind::Series { cap: 0 }) {
                    return Err(RegistryError::InvalidIdentity {
                        plugin: p.name(),
                        reason: "Series rollup cap must be nonzero",
                    });
                }
            }
        }

        // Fallback pool: every plugin with a probe, registration order
        // (the determinism tiebreak, 03.3).
        let fallback_pool = plugins
            .iter()
            .enumerate()
            .filter(|(_, p)| p.has_probe())
            .map(|(idx, _)| idx)
            .collect();

        Ok(Engine {
            plugins,
            by_name,
            routes,
            fallback_pool,
        })
    }
}

/// The immutable dissection engine: plugin registry + route table +
/// fallback pool. `Send + Sync`, shared freely via `Arc` (D5); the lazy
/// parser (04.1) hangs off this type.
pub struct Engine {
    plugins: Vec<Box<dyn LayerPlugin>>,
    by_name: HashMap<ProtocolName, PluginIdx>,
    routes: HashMap<RouteId, PluginIdx>,
    /// Probe-capable plugins, registration order (03.3 determinism).
    fallback_pool: Vec<PluginIdx>,
}

impl Engine {
    pub fn builder() -> EngineBuilder {
        EngineBuilder::new()
    }

    /// The plugin a route id dispatches to, if the id is claimed.
    pub fn plugin_for_route(&self, id: RouteId) -> Option<&dyn LayerPlugin> {
        self.routes.get(&id).map(|&idx| &*self.plugins[idx])
    }

    /// Direct lookup by protocol name (the `ByProtocol` namespace).
    pub fn plugin_by_name(&self, name: &str) -> Option<&dyn LayerPlugin> {
        self.by_name.get(name).map(|&idx| &*self.plugins[idx])
    }

    /// Probe-capable plugins in registration order (03.3).
    pub fn fallback_pool(&self) -> impl Iterator<Item = &dyn LayerPlugin> {
        self.fallback_pool.iter().map(|&idx| &*self.plugins[idx])
    }

    /// The route table as (id, plugin name) pairs, unordered.
    pub fn routes(&self) -> impl Iterator<Item = (RouteId, ProtocolName)> + '_ {
        self.routes
            .iter()
            .map(|(&id, &idx)| (id, self.plugins[idx].name()))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::SystemTime;

    use super::*;
    use crate::context::ParseCtx;
    use crate::depth::Depth;
    use crate::error::ParseError;
    use crate::packet::{LinkType, PacketMeta};
    use crate::plugin::{Confidence, Hint, ParsedLayer};
    use crate::stream::{Canonicalize, KeyField, RollupSpec, StreamIdentity};
    use crate::value::FieldMap;

    // D5: immutable after build, shared freely.
    const _: fn() = || {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Engine>();
        assert_send_sync::<Arc<Engine>>();
    };

    /// Synthetic plugin: fixed name, claims, optional probe/identity.
    struct Fake {
        name: ProtocolName,
        claims: &'static [RouteId],
        probing: bool,
        identity: Option<StreamIdentity>,
    }

    impl Fake {
        fn new(name: ProtocolName, claims: &'static [RouteId]) -> Self {
            Self {
                name,
                claims,
                probing: false,
                identity: None,
            }
        }
    }

    impl LayerPlugin for Fake {
        fn name(&self) -> ProtocolName {
            self.name
        }

        fn parse(&self, bytes: &[u8], _ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
            if bytes.is_empty() {
                return Err(ParseError::Malformed("empty"));
            }
            Ok(ParsedLayer {
                header_len: 1,
                fields: FieldMap::new(),
                hint: Hint::Terminal,
            })
        }

        fn claims(&self) -> &'static [RouteId] {
            self.claims
        }

        fn has_probe(&self) -> bool {
            self.probing
        }

        fn probe(&self, _bytes: &[u8], _ctx: &ParseCtx) -> Option<Confidence> {
            self.probing.then(|| Confidence::new(90))
        }

        fn stream_identity(&self) -> Option<&StreamIdentity> {
            self.identity.as_ref()
        }
    }

    fn meta() -> PacketMeta {
        PacketMeta {
            timestamp: SystemTime::UNIX_EPOCH,
            caplen: 4,
            origlen: 4,
            link_type: LinkType::ETHERNET,
        }
    }

    /// `Engine` holds `dyn` plugins and has no `Debug`, so `expect_err`
    /// can't be used on build results.
    fn build_err(builder: EngineBuilder) -> RegistryError {
        match builder.build() {
            Err(e) => e,
            Ok(_) => panic!("expected a build error"),
        }
    }

    const MUX_ID: RouteId = RouteId::Custom {
        space: "testmux",
        id: 7,
    };

    #[test]
    fn cross_space_ids_do_not_collide_as_map_keys() {
        // 03.1: the number 6 means different things per namespace.
        let mut map: HashMap<RouteId, &str> = HashMap::new();
        map.insert(RouteId::EtherType(6), "ethertype-6");
        map.insert(RouteId::IpProtocol(6), "tcp");
        assert_eq!(map.len(), 2);
        assert_ne!(RouteId::EtherType(6), RouteId::IpProtocol(6));
        assert_ne!(RouteId::UdpPort(53), RouteId::TcpPort(53));
    }

    #[test]
    fn route_id_display_formats() {
        assert_eq!(RouteId::EtherType(0x0800).to_string(), "ethertype:0x0800");
        assert_eq!(RouteId::UdpPort(53).to_string(), "udp_port:53");
        assert_eq!(
            RouteId::Custom {
                space: "gre_flags",
                id: 1
            }
            .to_string(),
            "custom:gre_flags:1"
        );
    }

    #[test]
    fn custom_space_round_trips_claim_route_dispatch() {
        // 03.1: a plugin-defined space works end-to-end with no core edits.
        let engine = Engine::builder()
            .plugin(Fake::new("outer_mux", &[]))
            .plugin(Fake::new("inner_proto", &[MUX_ID]))
            .build()
            .expect("valid registry");

        let routed = engine.plugin_for_route(MUX_ID).expect("claim installed");
        assert_eq!(routed.name(), "inner_proto");

        // Dispatch: the routed plugin actually parses.
        let m = meta();
        let ctx = ParseCtx::new(&[], Depth::Full, &m);
        let parsed = routed.parse(&[0xFF], &ctx).expect("parses");
        assert_eq!(parsed.header_len, 1);
    }

    #[test]
    fn claimless_plugin_adds_no_routes_and_probeless_stays_out_of_pool() {
        // 02.3: defaults compile away.
        let engine = Engine::builder()
            .plugin(Fake::new("plain", &[]))
            .build()
            .expect("valid registry");
        assert_eq!(engine.routes().count(), 0);
        assert_eq!(engine.fallback_pool().count(), 0);

        let mut prober = Fake::new("prober", &[]);
        prober.probing = true;
        let engine = Engine::builder()
            .plugin(Fake::new("plain", &[]))
            .plugin(prober)
            .build()
            .expect("valid registry");
        let pool: Vec<_> = engine.fallback_pool().map(|p| p.name()).collect();
        assert_eq!(pool, ["prober"]);
    }

    #[test]
    fn duplicate_name_is_a_build_error() {
        let err = build_err(
            Engine::builder()
                .plugin(Fake::new("dup", &[]))
                .plugin(Fake::new("dup", &[])),
        );
        assert!(matches!(err, RegistryError::DuplicateName { name: "dup" }));
    }

    #[test]
    fn claim_collision_names_both_plugins() {
        let err = build_err(
            Engine::builder()
                .plugin(Fake::new("first_claimer", &[MUX_ID]))
                .plugin(Fake::new("second_claimer", &[MUX_ID])),
        );
        match err {
            RegistryError::ClaimCollision { id, first, second } => {
                assert_eq!(id, MUX_ID);
                assert_eq!(first, "first_claimer");
                assert_eq!(second, "second_claimer");
            }
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn manual_override_beats_a_claim() {
        // FR-12: route() resolves the collision and wins the id.
        let engine = Engine::builder()
            .plugin(Fake::new("claimer", &[MUX_ID]))
            .plugin(Fake::new("chosen", &[MUX_ID]))
            .route(MUX_ID, "chosen")
            .build()
            .expect("manual route resolves the collision");
        assert_eq!(
            engine.plugin_for_route(MUX_ID).map(|p| p.name()),
            Some("chosen")
        );

        // unroute() is the other resolution: nobody owns the id.
        let engine = Engine::builder()
            .plugin(Fake::new("claimer", &[MUX_ID]))
            .plugin(Fake::new("chosen", &[MUX_ID]))
            .unroute(MUX_ID)
            .build()
            .expect("unroute resolves the collision");
        assert!(engine.plugin_for_route(MUX_ID).is_none());
    }

    #[test]
    fn dangling_override_is_a_build_error() {
        let err = build_err(
            Engine::builder()
                .plugin(Fake::new("real", &[]))
                .route(MUX_ID, "ghost"),
        );
        assert!(matches!(
            err,
            RegistryError::DanglingOverride {
                id: MUX_ID,
                name: "ghost"
            }
        ));
    }

    #[test]
    fn malformed_stream_identity_is_a_build_error() {
        static BAD_KEY: &[KeyField] = &[KeyField { a: "", b: None }];
        static GOOD_KEY: &[KeyField] = &[KeyField {
            a: "src",
            b: Some("dst"),
        }];
        static ZERO_CAP: &[RollupSpec] = &[RollupSpec {
            field: "qname",
            kind: crate::stream::RollupKind::Series { cap: 0 },
        }];

        let mut bad = Fake::new("bad_ident", &[]);
        bad.identity = Some(StreamIdentity {
            key: BAD_KEY,
            canonicalize: Canonicalize::EndpointSort,
            lifecycle: None,
            rollups: &[],
        });
        let err = build_err(Engine::builder().plugin(bad));
        assert!(matches!(
            err,
            RegistryError::InvalidIdentity {
                plugin: "bad_ident",
                ..
            }
        ));

        let mut zero = Fake::new("zero_cap", &[]);
        zero.identity = Some(StreamIdentity {
            key: GOOD_KEY,
            canonicalize: Canonicalize::EndpointSort,
            lifecycle: None,
            rollups: ZERO_CAP,
        });
        let err = build_err(Engine::builder().plugin(zero));
        assert!(matches!(
            err,
            RegistryError::InvalidIdentity {
                plugin: "zero_cap",
                ..
            }
        ));
    }

    #[test]
    fn stream_identity_round_trips_without_engine_side_protocol_knowledge() {
        // 02.4: a 2-field endpoint key + Sample rollup, declared by the
        // plugin, read back generically — nothing below mentions the
        // protocol; the engine only ever sees the declaration types.
        static KEY: &[KeyField] = &[
            KeyField {
                a: "src_addr",
                b: Some("dst_addr"),
            },
            KeyField {
                a: "src_qual",
                b: Some("dst_qual"),
            },
        ];
        static ROLLUPS: &[RollupSpec] = &[RollupSpec {
            field: "label",
            kind: RollupKind::Sample,
        }];

        let mut p = Fake::new("pair_proto", &[]);
        p.identity = Some(StreamIdentity {
            key: KEY,
            canonicalize: Canonicalize::EndpointSort,
            lifecycle: None,
            rollups: ROLLUPS,
        });
        let engine = Engine::builder().plugin(p).build().expect("valid identity");

        // What the (future) aggregator will do per layer: fetch the plugin
        // by the layer's protocol name, read its declaration, and key on it.
        let plugin = engine.plugin_by_name("pair_proto").expect("registered");
        let identity = plugin.stream_identity().expect("declared");

        let pairs: Vec<_> = identity.key.iter().map(|kf| (kf.a, kf.b)).collect();
        assert_eq!(
            pairs,
            [
                ("src_addr", Some("dst_addr")),
                ("src_qual", Some("dst_qual"))
            ]
        );
        assert!(matches!(identity.canonicalize, Canonicalize::EndpointSort));
        assert!(identity.lifecycle.is_none());
        assert_eq!(
            identity.rollups,
            [RollupSpec {
                field: "label",
                kind: RollupKind::Sample
            }]
        );
    }

    #[test]
    fn registration_order_does_not_change_the_route_table() {
        const ID_A: RouteId = RouteId::EtherType(0x0800);
        const ID_B: RouteId = RouteId::IpProtocol(17);

        let table = |engine: &Engine| {
            let mut t: Vec<(String, ProtocolName)> = engine
                .routes()
                .map(|(id, name)| (id.to_string(), name))
                .collect();
            t.sort();
            t
        };

        let forward = Engine::builder()
            .plugin(Fake::new("alpha", &[ID_A]))
            .plugin(Fake::new("beta", &[ID_B]))
            .build()
            .expect("valid");
        let reverse = Engine::builder()
            .plugin(Fake::new("beta", &[ID_B]))
            .plugin(Fake::new("alpha", &[ID_A]))
            .build()
            .expect("valid");
        assert_eq!(table(&forward), table(&reverse));

        // Fallback pool is the one order-sensitive structure, as documented.
        let mut p1 = Fake::new("p1", &[]);
        p1.probing = true;
        let mut p2 = Fake::new("p2", &[]);
        p2.probing = true;
        let engine = Engine::builder()
            .plugin(p1)
            .plugin(p2)
            .build()
            .expect("valid");
        let pool: Vec<_> = engine.fallback_pool().map(|p| p.name()).collect();
        assert_eq!(pool, ["p1", "p2"]);
    }
}
