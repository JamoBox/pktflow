//! Typed metadata values and per-layer field maps (01.1, FR-18).
//!
//! Everything plugins extract is one of these values; each layer carries an
//! insertion-ordered [`FieldMap`] of them. Cheap on the hot path, stable to
//! render and serialize. Human-friendly rendering is a CLI concern (08.5) —
//! core stays presentation-free, so `Value` has no `Display`.

use compact_str::CompactString;
use smallvec::SmallVec;

/// Byte values up to 16 bytes long (MACs, v6 addresses, opaque ids) stay
/// inline — no heap allocation at or below that bound.
pub type SmallBytes = SmallVec<[u8; 16]>;

/// A typed metadata value extracted by a plugin.
///
/// Covers exactly FR-18's set. `Eq + Hash` are load-bearing: flow keys
/// (05.1) are built from `Value`s — which is why there is no float variant
/// in v1.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum Value {
    /// MAC addresses, opaque ids; inline (heap-free) at ≤16 bytes.
    Bytes(SmallBytes),
    U64(u64),
    I64(i64),
    Bool(bool),
    /// Decoded names (e.g. DNS qname); must already be valid UTF-8.
    Str(CompactString),
    /// Ordered lists, e.g. VLAN tag stack, DNS answers.
    List(Vec<Value>),
}

impl From<&[u8]> for Value {
    fn from(b: &[u8]) -> Self {
        Value::Bytes(SmallBytes::from_slice(b))
    }
}

impl From<u64> for Value {
    fn from(v: u64) -> Self {
        Value::U64(v)
    }
}

impl From<i64> for Value {
    fn from(v: i64) -> Self {
        Value::I64(v)
    }
}

impl From<bool> for Value {
    fn from(v: bool) -> Self {
        Value::Bool(v)
    }
}

impl From<&str> for Value {
    fn from(v: &str) -> Self {
        Value::Str(CompactString::from(v))
    }
}

/// Plugins own their field-name constants: `snake_case`, protocol-local
/// (`src_port`, not `tcp.src_port` — the layer already scopes it).
pub type FieldName = &'static str;

/// An insertion-ordered named map of [`Value`]s — one per layer.
///
/// Vec-backed with linear `get`: layers carry ~3–20 fields, so this beats a
/// hash map on both speed and memory, and insertion order is preserved for
/// deterministic output (PRD §7).
#[derive(Clone, PartialEq, Eq, Hash, Debug, Default)]
pub struct FieldMap {
    entries: Vec<(FieldName, Value)>,
}

impl FieldMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a field, preserving first-insertion order. Re-inserting an
    /// existing name replaces its value (last write wins) — plugins should
    /// not rely on it.
    pub fn insert(&mut self, name: FieldName, v: Value) {
        match self.entries.iter_mut().find(|(n, _)| *n == name) {
            Some((_, slot)) => *slot = v,
            None => self.entries.push((name, v)),
        }
    }

    pub fn get(&self, name: &str) -> Option<&Value> {
        self.entries
            .iter()
            .find_map(|(n, v)| (*n == name).then_some(v))
    }

    /// Fields in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&FieldName, &Value)> {
        self.entries.iter().map(|(n, v)| (n, v))
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Stable JSON shape (behind the `serde` feature): `Bytes` as a lowercase
/// hex string, every other variant as its native JSON type, `FieldMap` as
/// an object in insertion order.
#[cfg(feature = "serde")]
mod serde_impl {
    use serde::ser::{Serialize, SerializeMap, SerializeSeq, Serializer};

    use super::{FieldMap, Value};

    fn hex_lower(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push(char::from(HEX[usize::from(b >> 4)]));
            out.push(char::from(HEX[usize::from(b & 0x0F)]));
        }
        out
    }

    impl Serialize for Value {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            match self {
                Value::Bytes(b) => serializer.serialize_str(&hex_lower(b)),
                Value::U64(v) => serializer.serialize_u64(*v),
                Value::I64(v) => serializer.serialize_i64(*v),
                Value::Bool(v) => serializer.serialize_bool(*v),
                Value::Str(v) => serializer.serialize_str(v),
                Value::List(vs) => {
                    let mut seq = serializer.serialize_seq(Some(vs.len()))?;
                    for v in vs {
                        seq.serialize_element(v)?;
                    }
                    seq.end()
                }
            }
        }
    }

    impl Serialize for FieldMap {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let mut map = serializer.serialize_map(Some(self.len()))?;
            for (name, value) in self.iter() {
                map.serialize_entry(name, value)?;
            }
            map.end()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::hash::{DefaultHasher, Hash, Hasher};

    use super::*;

    fn hash_of<T: Hash>(t: &T) -> u64 {
        let mut h = DefaultHasher::new();
        t.hash(&mut h);
        h.finish()
    }

    #[test]
    fn duplicate_insert_replaces_in_place() {
        let mut m = FieldMap::new();
        m.insert("src_port", Value::U64(53));
        m.insert("dst_port", Value::U64(4242));
        m.insert("src_port", Value::U64(443));

        assert_eq!(m.len(), 2);
        assert_eq!(m.get("src_port"), Some(&Value::U64(443)));
        // Replacement keeps the original position, not the re-insert position.
        let order: Vec<_> = m.iter().map(|(n, _)| *n).collect();
        assert_eq!(order, ["src_port", "dst_port"]);
    }

    #[test]
    fn iteration_order_is_insertion_order() {
        let mut m = FieldMap::new();
        for name in ["zeta", "alpha", "mid", "beta"] {
            m.insert(name, Value::Bool(true));
        }
        let order: Vec<_> = m.iter().map(|(n, _)| *n).collect();
        assert_eq!(order, ["zeta", "alpha", "mid", "beta"]);
    }

    #[test]
    fn get_miss_is_none() {
        let mut m = FieldMap::new();
        m.insert("ttl", Value::U64(64));
        assert_eq!(m.get("hop_limit"), None);
        assert!(!m.is_empty());
    }

    #[test]
    fn equal_values_hash_equal() {
        let pairs = [
            (
                Value::from(&[0xDE, 0xAD][..]),
                Value::from(&[0xDE, 0xAD][..]),
            ),
            (Value::U64(7), Value::U64(7)),
            (Value::I64(-7), Value::I64(-7)),
            (Value::Bool(true), Value::Bool(true)),
            (Value::from("example.com"), Value::from("example.com")),
            (
                Value::List(vec![Value::U64(1), Value::from("a")]),
                Value::List(vec![Value::U64(1), Value::from("a")]),
            ),
        ];
        for (a, b) in &pairs {
            assert_eq!(a, b);
            assert_eq!(hash_of(a), hash_of(b), "equal values must hash equal");
        }

        let mut a = FieldMap::new();
        a.insert("x", Value::U64(1));
        let mut b = FieldMap::new();
        b.insert("x", Value::U64(1));
        assert_eq!(hash_of(&a), hash_of(&b));
    }

    #[test]
    fn bytes_up_to_16_stay_inline() {
        // The SmallVec bound is [u8; 16]: a full IPv6 address fits with no
        // heap allocation; 17 bytes spills.
        let inline = SmallBytes::from_slice(&[0xAB; 16]);
        assert!(!inline.spilled());
        let spilled = SmallBytes::from_slice(&[0xAB; 17]);
        assert!(spilled.spilled());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_json_shape_is_stable() {
        let mut m = FieldMap::new();
        m.insert(
            "src_mac",
            Value::from(&[0x00, 0x1B, 0x44, 0x11, 0x3A, 0xB7][..]),
        );
        m.insert("ttl", Value::U64(64));
        m.insert("offset", Value::I64(-2));
        m.insert("syn", Value::Bool(true));
        m.insert("qname", Value::from("example.com"));
        m.insert(
            "answers",
            Value::List(vec![Value::from("a.example.com"), Value::U64(300)]),
        );

        let json = serde_json::to_string(&m).expect("serialization cannot fail");
        assert_eq!(
            json,
            r#"{"src_mac":"001b44113ab7","ttl":64,"offset":-2,"syn":true,"qname":"example.com","answers":["a.example.com",300]}"#
        );
    }
}
