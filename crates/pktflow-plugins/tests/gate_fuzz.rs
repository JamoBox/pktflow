//! 03.4's property test: random bytes through the full reference-plugin
//! engine never panic and never yield a layer whose plugin's own `parse`
//! would decline those bytes.

use std::time::SystemTime;

use pktflow_core::{Depth, LinkType, PacketMeta, ParseCtx, ParseOpts};
use pktflow_plugins::default_engine;
use proptest::prelude::*;

proptest! {
    #[test]
    fn random_bytes_never_panic_and_every_layer_is_honest(
        bytes in proptest::collection::vec(any::<u8>(), 0..600),
        entry_heuristics in any::<bool>(),
    ) {
        let engine = default_engine();
        let meta = PacketMeta {
            timestamp: SystemTime::UNIX_EPOCH,
            caplen: bytes.len(),
            origlen: bytes.len(),
            link_type: LinkType::ETHERNET,
        };
        let opts = ParseOpts {
            allow_entry_heuristics: entry_heuristics,
            ..ParseOpts::default()
        };

        // Reaching here at all proves no panic.
        let packet = engine.dissect(&bytes, meta, opts);

        // Honesty: every emitted layer re-parses cleanly at its offset
        // with the context it was given.
        for (i, layer) in packet.layers.iter().enumerate() {
            let plugin = engine
                .plugin_by_name(layer.protocol)
                .expect("emitted layers name registered plugins");
            let slice = bytes.get(layer.offset..).unwrap_or(&[]);
            let ctx = ParseCtx::new(&packet.layers[..i], Depth::Full, &meta);
            let reparsed = plugin.parse(slice, &ctx);
            prop_assert!(
                reparsed.is_ok(),
                "layer {i} ({}) at offset {} does not re-parse",
                layer.protocol,
                layer.offset
            );
        }
    }
}
