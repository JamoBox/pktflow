//! Flow-key construction & canonicalization (05.1, FR-2/FR-3, D3).
//!
//! Turns a layer's extracted fields + its plugin's `StreamIdentity` into a
//! canonical [`FlowKey`] plus the packet's [`PacketDirection`] — the
//! identity operation everything downstream keys on. Engine-side and
//! uniform for every protocol (PRD §4.A): no protocol names appear here.

use pktflow_core::{
    Canonicalize, FieldMap, FlowKey, KeyError, PacketDirection, StreamIdentity, Value,
};

/// Canonical key + direction for one layer.
///
/// 1. Fetch each `KeyField`'s values (missing ⇒ [`KeyError::MissingField`]).
/// 2. Encode values length-prefixed and type-tagged, so `["ab","c"]` ≠
///    `["a","bc"]` and `U64(1)` ≠ `Bool(true)`.
/// 3. `EndpointSort` (D3): the lexicographically smaller endpoint encoding
///    becomes canonical **A**; key = `shared ++ smaller ++ larger`. Equal
///    endpoints (self-talk) are fixed `AtoB`.
/// 4. `Custom` rules are called and trusted to be deterministic (09.1
///    spot-checks by running them twice).
pub fn flow_key(
    identity: &StreamIdentity,
    fields: &FieldMap,
) -> Result<(FlowKey, PacketDirection), KeyError> {
    match identity.canonicalize {
        Canonicalize::Custom(f) => f(fields),
        Canonicalize::EndpointSort => {
            let mut shared = Vec::new();
            let mut side_a = Vec::new();
            let mut side_b = Vec::new();

            for kf in identity.key {
                let va = fields.get(kf.a).ok_or(KeyError::MissingField(kf.a))?;
                match kf.b {
                    // Unpaired components belong to the stream, not an
                    // endpoint: they never influence direction.
                    None => encode_value(va, &mut shared),
                    Some(b) => {
                        let vb = fields.get(b).ok_or(KeyError::MissingField(b))?;
                        encode_value(va, &mut side_a);
                        encode_value(vb, &mut side_b);
                    }
                }
            }

            let direction = if side_a <= side_b {
                PacketDirection::AtoB
            } else {
                PacketDirection::BtoA
            };
            let (lo, hi) = match direction {
                PacketDirection::AtoB => (&side_a, &side_b),
                PacketDirection::BtoA => (&side_b, &side_a),
            };
            let mut encoded = shared;
            encoded.extend_from_slice(lo);
            encoded.extend_from_slice(hi);
            Ok((FlowKey::from_bytes(&encoded), direction))
        }
    }
}

// One tag byte per type keeps cross-type encodings distinct; u16 length
// prefixes keep the common keys inline in FlowKey's 40 bytes (an IPv6
// address encodes to 1 + 2 + 16 = 19, a pair to 38). Variable-length
// payloads are truncated at u16::MAX bytes — real key fields (addresses,
// ports, ids, names) are orders of magnitude smaller.
const TAG_BYTES: u8 = 0;
const TAG_U64: u8 = 1;
const TAG_I64: u8 = 2;
const TAG_BOOL: u8 = 3;
const TAG_STR: u8 = 4;
const TAG_LIST: u8 = 5;
const TAG_OTHER: u8 = 255;

fn encode_len_prefixed(tag: u8, payload: &[u8], out: &mut Vec<u8>) {
    let len = u16::try_from(payload.len()).unwrap_or(u16::MAX);
    out.push(tag);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload.get(..usize::from(len)).unwrap_or(payload));
}

fn encode_value(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Bytes(b) => encode_len_prefixed(TAG_BYTES, b, out),
        Value::U64(n) => {
            out.push(TAG_U64);
            out.extend_from_slice(&n.to_be_bytes());
        }
        Value::I64(n) => {
            out.push(TAG_I64);
            out.extend_from_slice(&n.to_be_bytes());
        }
        Value::Bool(b) => {
            out.push(TAG_BOOL);
            out.push(u8::from(*b));
        }
        Value::Str(s) => encode_len_prefixed(TAG_STR, s.as_bytes(), out),
        Value::List(vs) => {
            out.push(TAG_LIST);
            let count = u16::try_from(vs.len()).unwrap_or(u16::MAX);
            out.extend_from_slice(&count.to_be_bytes());
            for v in vs.iter().take(usize::from(count)) {
                encode_value(v, out);
            }
        }
        // Value is non_exhaustive: a future variant must not silently
        // alias an existing encoding.
        _ => encode_len_prefixed(TAG_OTHER, &[], out),
    }
}

#[cfg(test)]
mod tests {
    use pktflow_core::{KeyField, SmallBytes};
    use proptest::prelude::*;

    use super::*;

    static PAIRED_PLUS_SHARED: &[KeyField] = &[
        KeyField {
            a: "a0",
            b: Some("b0"),
        },
        KeyField {
            a: "a1",
            b: Some("b1"),
        },
        KeyField { a: "s0", b: None },
    ];
    static SINGLE: &[KeyField] = &[KeyField {
        a: "a0",
        b: Some("b0"),
    }];

    fn identity(key: &'static [KeyField]) -> StreamIdentity {
        StreamIdentity {
            key,
            canonicalize: Canonicalize::EndpointSort,
            lifecycle: None,
            rollups: &[],
        }
    }

    /// Random `Value`s including empty bytes/strings and lists (05.1's
    /// required corpus).
    fn value_strategy() -> impl Strategy<Value = Value> {
        let leaf = prop_oneof![
            proptest::collection::vec(any::<u8>(), 0..20)
                .prop_map(|b| Value::Bytes(SmallBytes::from_slice(&b))),
            any::<u64>().prop_map(Value::U64),
            any::<i64>().prop_map(Value::I64),
            any::<bool>().prop_map(Value::Bool),
            "[a-z]{0,8}".prop_map(|s| Value::from(s.as_str())),
        ];
        prop_oneof![
            leaf.clone(),
            proptest::collection::vec(leaf, 0..4).prop_map(Value::List),
        ]
    }

    fn map_of(entries: &[(&'static str, &Value)]) -> FieldMap {
        let mut m = FieldMap::new();
        for (name, v) in entries {
            m.insert(name, (*v).clone());
        }
        m
    }

    fn encoded(v: &Value) -> Vec<u8> {
        let mut out = Vec::new();
        encode_value(v, &mut out);
        out
    }

    proptest! {
        /// FR-3's core promise: swapping all a/b values yields the same
        /// key with flipped direction (self-talk pins AtoB).
        #[test]
        fn involution(
            va0 in value_strategy(), vb0 in value_strategy(),
            va1 in value_strategy(), vb1 in value_strategy(),
            vs in value_strategy(),
        ) {
            let ident = identity(PAIRED_PLUS_SHARED);
            let forward = map_of(&[
                ("a0", &va0), ("b0", &vb0),
                ("a1", &va1), ("b1", &vb1),
                ("s0", &vs),
            ]);
            let swapped = map_of(&[
                ("a0", &vb0), ("b0", &va0),
                ("a1", &vb1), ("b1", &va1),
                ("s0", &vs),
            ]);

            let (k1, d1) = flow_key(&ident, &forward).expect("all fields present");
            let (k2, d2) = flow_key(&ident, &swapped).expect("all fields present");
            prop_assert_eq!(&k1, &k2, "canonical key is direction-free");

            let endpoints_equal = {
                let mut ea = encoded(&va0); ea.extend(encoded(&va1));
                let mut eb = encoded(&vb0); eb.extend(encoded(&vb1));
                ea == eb
            };
            if endpoints_equal {
                prop_assert_eq!(d1, PacketDirection::AtoB);
                prop_assert_eq!(d2, PacketDirection::AtoB);
            } else {
                prop_assert_ne!(d1, d2, "directions flip");
            }
        }

        /// Injectivity within a protocol: distinct canonical endpoint sets
        /// produce distinct keys.
        #[test]
        fn injectivity(
            x1 in value_strategy(), y1 in value_strategy(),
            x2 in value_strategy(), y2 in value_strategy(),
        ) {
            let ident = identity(SINGLE);
            let (k1, _) = flow_key(&ident, &map_of(&[("a0", &x1), ("b0", &y1)]))
                .expect("present");
            let (k2, _) = flow_key(&ident, &map_of(&[("a0", &x2), ("b0", &y2)]))
                .expect("present");

            // Canonical endpoint set = the *sorted* encoding pair.
            let mut set1 = [encoded(&x1), encoded(&y1)];
            set1.sort();
            let mut set2 = [encoded(&x2), encoded(&y2)];
            set2.sort();
            if set1 == set2 {
                prop_assert_eq!(k1, k2);
            } else {
                prop_assert_ne!(k1, k2);
            }
        }
    }

    #[test]
    fn common_keys_stay_inline() {
        // MAC pair, IPv6 pair, port pair: all within FlowKey's 40 inline
        // bytes — no heap on the per-packet path.
        let cases: [(Value, Value); 3] = [
            (
                Value::from(&[0x00u8, 0x1B, 0x44, 0x11, 0x3A, 0xB7][..]),
                Value::from(&[0x00u8, 0x1B, 0x44, 0x11, 0x3A, 0xB8][..]),
            ),
            (
                Value::from(&[0x20u8; 16][..]),
                Value::from(&[0xFEu8; 16][..]),
            ),
            (Value::U64(443), Value::U64(49152)),
        ];
        for (va, vb) in &cases {
            let (key, _) =
                flow_key(&identity(SINGLE), &map_of(&[("a0", va), ("b0", vb)])).expect("present");
            assert!(
                key.as_bytes().len() <= 40,
                "key of {} bytes would spill",
                key.as_bytes().len()
            );
        }
    }

    #[test]
    fn missing_field_is_reported_by_name() {
        let m = map_of(&[("a0", &Value::U64(1))]); // b0 absent
        assert_eq!(
            flow_key(&identity(SINGLE), &m),
            Err(KeyError::MissingField("b0"))
        );
    }

    #[test]
    fn nested_list_boundaries_do_not_alias() {
        // ["ab","c"] vs ["a","bc"]: same concatenated content, different
        // keys — the length prefixes do their job.
        let l1 = Value::List(vec![Value::from("ab"), Value::from("c")]);
        let l2 = Value::List(vec![Value::from("a"), Value::from("bc")]);
        let shared = Value::U64(0);
        let ident = identity(SINGLE);
        let (k1, _) = flow_key(&ident, &map_of(&[("a0", &l1), ("b0", &shared)])).expect("ok");
        let (k2, _) = flow_key(&ident, &map_of(&[("a0", &l2), ("b0", &shared)])).expect("ok");
        assert_ne!(k1, k2);
    }

    #[test]
    fn custom_rule_is_called_verbatim() {
        fn fixed(_: &FieldMap) -> Result<(FlowKey, PacketDirection), KeyError> {
            Ok((FlowKey::from_bytes(b"custom"), PacketDirection::BtoA))
        }
        let ident = StreamIdentity {
            key: SINGLE,
            canonicalize: Canonicalize::Custom(fixed),
            lifecycle: None,
            rollups: &[],
        };
        let (key, dir) = flow_key(&ident, &FieldMap::new()).expect("custom");
        assert_eq!(key.as_bytes(), b"custom");
        assert_eq!(dir, PacketDirection::BtoA);
    }
}
