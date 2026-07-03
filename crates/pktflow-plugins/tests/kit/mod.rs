//! The 09.1 plugin conformance kit: bytes → layer + fields + hint + flow
//! key, mechanically enforcing the contract rules of 01.3, 02.1, and 02.4
//! so plugin review is about protocol correctness, not contract compliance.
//!
//! Failure messages name the plugin, the rule, and the byte offset.

use std::collections::BTreeSet;
use std::time::SystemTime;

use pktflow_core::{
    Canonicalize, Depth, FieldMap, Hint, LayerPlugin, LayerRecord, LinkType, PacketDirection,
    PacketMeta, ParseCtx, StateName, Value, MIN_CONFIDENCE,
};
use pktflow_flows::flow_key;

/// One known-good sample: real header bytes plus the author's expectations.
pub struct GoodPacket {
    /// Header bytes (may include trailing payload beyond `header_len`).
    pub bytes: Vec<u8>,
    pub expected_header_len: usize,
    /// Exact field set expected at `Depth::Full`.
    pub expected_full_fields: Vec<(&'static str, Value)>,
    pub expected_hint: Hint,
}

pub struct ConformanceCase {
    pub plugin: Box<dyn LayerPlugin>,
    pub good: Vec<GoodPacket>,
    /// Simulated outer layers where the plugin reads cross-layer context.
    pub outer_ctx: Vec<LayerRecord>,
}

fn meta(len: usize) -> PacketMeta {
    PacketMeta {
        timestamp: SystemTime::UNIX_EPOCH,
        caplen: len,
        origlen: len,
        link_type: LinkType::ETHERNET,
    }
}

/// Deterministic xorshift for the probe-honesty and lifecycle fuzz checks
/// (no rand dependency, reproducible failures).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

pub fn run_conformance(case: &ConformanceCase) {
    let plugin = &*case.plugin;
    let name = plugin.name();
    assert!(!case.good.is_empty(), "[{name}] kit needs >= 1 good sample");

    for (sample_no, good) in case.good.iter().enumerate() {
        let m = meta(good.bytes.len());
        let full = ParseCtx::new(&case.outer_ctx, Depth::Full, &m);

        // Author expectations first: header_len, hint, exact Full fields.
        let parsed = plugin
            .parse(&good.bytes, &full)
            .unwrap_or_else(|e| panic!("[{name}] sample {sample_no}: good bytes declined: {e}"));
        assert_eq!(
            parsed.header_len, good.expected_header_len,
            "[{name}] sample {sample_no}: header_len"
        );
        assert_eq!(
            parsed.hint, good.expected_hint,
            "[{name}] sample {sample_no}: hint"
        );
        let mut got: Vec<(&str, &Value)> = parsed.fields.iter().map(|(n, v)| (*n, v)).collect();
        got.sort_by_key(|(n, _)| *n);
        let mut want: Vec<(&str, &Value)> = good
            .expected_full_fields
            .iter()
            .map(|(n, v)| (*n, v))
            .collect();
        want.sort_by_key(|(n, _)| *n);
        assert_eq!(got, want, "[{name}] sample {sample_no}: Full field set");

        // Rule 1 — truncation sweep: every strict prefix declines, cleanly.
        for n in 0..parsed.header_len {
            let prefix = &good.bytes[..n];
            if plugin.parse(prefix, &full).is_ok() {
                panic!(
                    "[{name}] sample {sample_no}: rule 1 (truncation): \
                     short success at byte offset {n} of {}",
                    parsed.header_len
                );
            }
        }

        // Rule 4 — header_len honesty: fits, and the header is
        // self-contained (re-parsing exactly header_len bytes succeeds).
        assert!(
            parsed.header_len <= good.bytes.len(),
            "[{name}] sample {sample_no}: rule 4: header_len {} > {} available",
            parsed.header_len,
            good.bytes.len()
        );
        let self_contained = plugin
            .parse(&good.bytes[..parsed.header_len], &full)
            .unwrap_or_else(|e| {
                panic!("[{name}] sample {sample_no}: rule 4: header not self-contained: {e}")
            });
        assert_eq!(
            self_contained.header_len, parsed.header_len,
            "[{name}] sample {sample_no}: rule 4: header_len changed on re-parse"
        );

        // Rule 2 — depth ladder: monotonic field sets, key fields at >= Keys.
        let mut previous: BTreeSet<&str> = BTreeSet::new();
        for depth in [Depth::None, Depth::Keys, Depth::Structural, Depth::Full] {
            let ctx = ParseCtx::new(&case.outer_ctx, depth, &m);
            let at_depth = plugin.parse(&good.bytes, &ctx).unwrap_or_else(|e| {
                panic!("[{name}] sample {sample_no}: rule 2: declined at {depth:?}: {e}")
            });
            let names: BTreeSet<&str> = at_depth.fields.iter().map(|(n, _)| *n).collect();
            assert!(
                previous.is_subset(&names),
                "[{name}] sample {sample_no}: rule 2: fields at {depth:?} \
                 dropped {:?}",
                previous.difference(&names).collect::<Vec<_>>()
            );
            if depth >= Depth::Keys {
                if let Some(identity) = plugin.stream_identity() {
                    for kf in identity.key {
                        for key_name in [Some(kf.a), kf.b].into_iter().flatten() {
                            assert!(
                                names.contains(key_name),
                                "[{name}] sample {sample_no}: rule 2: flow-key \
                                 field {key_name:?} missing at {depth:?} (01.3)"
                            );
                        }
                    }
                }
            }
            previous = names;
        }

        // Rule 3 — identity coherence: declared names appear in the Full
        // parse; the key builds; involution holds (05.1).
        if let Some(identity) = plugin.stream_identity() {
            for kf in identity.key {
                for key_name in [Some(kf.a), kf.b].into_iter().flatten() {
                    assert!(
                        parsed.fields.get(key_name).is_some(),
                        "[{name}] sample {sample_no}: rule 3: key field {key_name:?} \
                         not extracted at Full"
                    );
                }
            }
            for spec in identity.rollups {
                // Rollup fields may be conditional per packet, but the
                // declaration must at least name a real field somewhere;
                // check against this sample when present is too weak, so
                // require it for good samples (they are canonical).
                assert!(
                    parsed.fields.get(spec.field).is_some(),
                    "[{name}] sample {sample_no}: rule 3: rollup field {:?} \
                     not extracted at Full",
                    spec.field
                );
            }

            let (key, dir) = flow_key(identity, &parsed.fields).unwrap_or_else(|e| {
                panic!("[{name}] sample {sample_no}: rule 3: key build failed: {e}")
            });
            if matches!(identity.canonicalize, Canonicalize::EndpointSort) {
                let mut swapped = FieldMap::new();
                for (n, v) in parsed.fields.iter() {
                    swapped.insert(n, v.clone());
                }
                let mut symmetric = true;
                for kf in identity.key {
                    if let Some(b) = kf.b {
                        let va = parsed.fields.get(kf.a).cloned();
                        let vb = parsed.fields.get(b).cloned();
                        symmetric &= va == vb;
                        if let (Some(va), Some(vb)) = (va, vb) {
                            swapped.insert(kf.a, vb);
                            swapped.insert(b, va);
                        }
                    }
                }
                let (key2, dir2) = flow_key(identity, &swapped).unwrap_or_else(|e| {
                    panic!("[{name}] sample {sample_no}: rule 3: swapped key failed: {e}")
                });
                assert_eq!(
                    key, key2,
                    "[{name}] sample {sample_no}: rule 3: involution key mismatch"
                );
                if !symmetric {
                    assert_ne!(
                        dir, dir2,
                        "[{name}] sample {sample_no}: rule 3: direction did not flip"
                    );
                }
            }
        }

        // Rule 5 — probe sanity: confident on good bytes, near-silent on
        // noise (02.3 honesty).
        if plugin.has_probe() {
            let score = plugin
                .probe(&good.bytes, &full)
                .unwrap_or_else(|| {
                    panic!("[{name}] sample {sample_no}: rule 5: no probe on good bytes")
                })
                .get();
            assert!(
                score >= MIN_CONFIDENCE,
                "[{name}] sample {sample_no}: rule 5: probe {score} below floor"
            );

            let mut rng = Rng(0x5EED_0001);
            let mut confident = 0u32;
            for _ in 0..1000 {
                let len = (rng.next() % 64) as usize;
                let buf: Vec<u8> = (0..len).map(|_| (rng.next() & 0xFF) as u8).collect();
                if let Some(c) = plugin.probe(&buf, &full) {
                    if c.get() >= MIN_CONFIDENCE {
                        confident += 1;
                    }
                }
            }
            assert!(
                confident <= 10,
                "[{name}] rule 5: probe confident on {confident}/1000 random buffers"
            );
        }
    }

    // Rule 6 — lifecycle totality: fuzz advance across states, directions,
    // and arbitrary field maps; the state vocabulary must stay bounded.
    if let Some(identity) = case.plugin.stream_identity() {
        if let Some(spec) = identity.lifecycle {
            let mut rng = Rng(0x5EED_0002);
            let mut vocabulary: BTreeSet<StateName> = BTreeSet::new();
            vocabulary.insert(spec.initial);
            vocabulary.extend(spec.closed_states.iter().copied());
            let mut frontier: Vec<StateName> = vocabulary.iter().copied().collect();
            let mut steps = 0;
            while let Some(state) = frontier.pop() {
                for _ in 0..64 {
                    steps += 1;
                    assert!(
                        steps < 100_000,
                        "[{}] rule 6: state vocabulary appears unbounded",
                        case.plugin.name()
                    );
                    let mut fields = FieldMap::new();
                    fields.insert("flag", Value::U64(rng.next() % 16));
                    fields.insert("fuzz", Value::Bool(rng.next().is_multiple_of(2)));
                    let dir = if rng.next().is_multiple_of(2) {
                        PacketDirection::AtoB
                    } else {
                        PacketDirection::BtoA
                    };
                    let next = (spec.advance)(&fields, state, dir);
                    if vocabulary.insert(next) {
                        frontier.push(next);
                    }
                }
            }
            assert!(
                vocabulary.len() <= 32,
                "[{}] rule 6: {} distinct states discovered",
                case.plugin.name(),
                vocabulary.len()
            );
        }
    }
}
