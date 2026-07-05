//! Metadata rollups (05.4, FR-5, D4): per-stream retention of
//! plugin-nominated fields beyond baseline stats.

use std::collections::VecDeque;
use std::time::SystemTime;

use pktflow_core::{FieldMap, FieldName, PacketDirection, RollupKind, RollupSpec, Value};

/// D4: an `Accumulate` set stops admitting *new distinct* values here but
/// keeps counting observations.
pub const ACCUMULATE_SET_CAP: usize = 64;

/// One time-ordered observation in a `Series` rollup.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SeriesPoint {
    pub ts: SystemTime,
    pub dir: PacketDirection,
    pub value: Value,
}

/// Retained state for one declared field.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Rollup {
    /// Running distinct-value set (insertion-ordered, deterministic) plus
    /// a total observation count. `overflow` = the cap was hit; the UI
    /// says "≥64 values" instead of lying by omission.
    Accumulate {
        values: Vec<Value>,
        count: u64,
        overflow: bool,
    },
    /// First and last observed value (`None` until the first observation).
    Sample {
        first: Option<Value>,
        last: Option<Value>,
    },
    /// Bounded time-ordered ring; overwrites oldest, `truncated` says so.
    Series {
        ring: VecDeque<SeriesPoint>,
        cap: usize,
        truncated: bool,
    },
}

/// One slot per `RollupSpec` the plugin declared (02.4).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct RollupSet {
    entries: Vec<(FieldName, Rollup)>,
}

impl RollupSet {
    /// Builds empty slots from the plugin's declaration. A `Series` cap of
    /// 0 in a spec means "use the configured default" (the registry
    /// rejects literal zero caps at build time, 03.2).
    pub fn new(specs: &[RollupSpec], series_default_cap: usize) -> Self {
        let entries = specs
            .iter()
            .map(|spec| {
                let rollup = match spec.kind {
                    RollupKind::Accumulate => Rollup::Accumulate {
                        values: Vec::new(),
                        count: 0,
                        overflow: false,
                    },
                    RollupKind::Sample => Rollup::Sample {
                        first: None,
                        last: None,
                    },
                    RollupKind::Series { cap } => Rollup::Series {
                        ring: VecDeque::new(),
                        cap: if cap == 0 { series_default_cap } else { cap },
                        truncated: false,
                    },
                };
                (spec.field, rollup)
            })
            .collect();
        Self { entries }
    }

    /// The per-packet update (called from 05.2's ingest). An absent field
    /// on a given packet is a no-op — fields can be depth-gated or
    /// conditional, and that is documented behavior, not an error.
    pub fn apply(&mut self, fields: &FieldMap, ts: SystemTime, dir: PacketDirection) {
        for (field, rollup) in &mut self.entries {
            let Some(v) = fields.get(field) else {
                continue;
            };
            match rollup {
                Rollup::Accumulate {
                    values,
                    count,
                    overflow,
                } => {
                    *count += 1;
                    if !values.contains(v) {
                        if values.len() < ACCUMULATE_SET_CAP {
                            values.push(v.clone());
                        } else {
                            *overflow = true;
                        }
                    }
                }
                Rollup::Sample { first, last } => {
                    if first.is_none() {
                        *first = Some(v.clone());
                    }
                    *last = Some(v.clone());
                }
                Rollup::Series {
                    ring,
                    cap,
                    truncated,
                } => {
                    if ring.len() >= *cap {
                        ring.pop_front();
                        *truncated = true;
                    }
                    ring.push_back(SeriesPoint {
                        ts,
                        dir,
                        value: v.clone(),
                    });
                }
            }
        }
    }

    pub fn get(&self, field: &str) -> Option<&Rollup> {
        self.entries
            .iter()
            .find_map(|(name, r)| (*name == field).then_some(r))
    }

    pub fn iter(&self) -> impl Iterator<Item = (&FieldName, &Rollup)> {
        self.entries.iter().map(|(n, r)| (n, r))
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TS: SystemTime = SystemTime::UNIX_EPOCH;
    const DIR: PacketDirection = PacketDirection::AtoB;

    fn one_field(v: u64) -> FieldMap {
        let mut m = FieldMap::new();
        m.insert("f", Value::U64(v));
        m
    }

    fn set_of(kind: RollupKind) -> RollupSet {
        RollupSet::new(&[RollupSpec { field: "f", kind }], 1024)
    }

    #[test]
    fn accumulate_cap_boundaries() {
        let cap = ACCUMULATE_SET_CAP as u64;
        for (observations, expect_len, expect_overflow) in [
            (cap - 1, cap - 1, false),
            (cap, cap, false),
            (cap + 1, cap, true),
        ] {
            let mut set = set_of(RollupKind::Accumulate);
            for i in 0..observations {
                set.apply(&one_field(i), TS, DIR);
            }
            // A duplicate never counts against the cap.
            set.apply(&one_field(0), TS, DIR);
            match set.get("f") {
                Some(Rollup::Accumulate {
                    values,
                    count,
                    overflow,
                }) => {
                    assert_eq!(values.len() as u64, expect_len);
                    assert_eq!(*count, observations + 1);
                    assert_eq!(*overflow, expect_overflow);
                }
                other => panic!("wrong rollup: {other:?}"),
            }
        }
    }

    #[test]
    fn sample_keeps_first_and_last() {
        let mut set = set_of(RollupKind::Sample);
        assert_eq!(
            set.get("f"),
            Some(&Rollup::Sample {
                first: None,
                last: None
            })
        );
        for i in [7, 8, 9] {
            set.apply(&one_field(i), TS, DIR);
        }
        assert_eq!(
            set.get("f"),
            Some(&Rollup::Sample {
                first: Some(Value::U64(7)),
                last: Some(Value::U64(9))
            })
        );
    }

    #[test]
    fn series_cap_boundaries() {
        for (observations, expect_len, expect_truncated, expect_front) in
            [(3u64, 3, false, 0), (4, 4, false, 0), (5, 4, true, 1)]
        {
            let mut set = set_of(RollupKind::Series { cap: 4 });
            for i in 0..observations {
                set.apply(&one_field(i), TS, DIR);
            }
            match set.get("f") {
                Some(Rollup::Series {
                    ring,
                    cap,
                    truncated,
                }) => {
                    assert_eq!(*cap, 4);
                    assert_eq!(ring.len() as u64, expect_len);
                    assert_eq!(*truncated, expect_truncated);
                    assert_eq!(
                        ring.front().map(|p| p.value.clone()),
                        Some(Value::U64(expect_front))
                    );
                }
                other => panic!("wrong rollup: {other:?}"),
            }
        }
    }

    #[test]
    fn same_sequence_yields_identical_contents_including_order() {
        let feed = |set: &mut RollupSet| {
            for i in [3u64, 1, 4, 1, 5, 9, 2, 6, 5, 3] {
                set.apply(&one_field(i), TS, DIR);
            }
        };
        let mut a = set_of(RollupKind::Accumulate);
        let mut b = set_of(RollupKind::Accumulate);
        feed(&mut a);
        feed(&mut b);
        assert_eq!(a, b);
        // Insertion order, not value order (PRD §7 determinism).
        match a.get("f") {
            Some(Rollup::Accumulate { values, .. }) => {
                let order: Vec<_> = values
                    .iter()
                    .map(|v| match v {
                        Value::U64(n) => *n,
                        other => panic!("unexpected {other:?}"),
                    })
                    .collect();
                assert_eq!(order, [3, 1, 4, 5, 9, 2, 6]);
            }
            other => panic!("wrong rollup: {other:?}"),
        }
    }

    #[test]
    fn absent_field_is_a_noop_not_an_error() {
        // Depth interaction (05.4): at Depth::Keys a Structural-only field
        // simply never arrives — the rollup stays empty.
        let mut set = set_of(RollupKind::Accumulate);
        let mut other = FieldMap::new();
        other.insert("unrelated", Value::Bool(true));
        set.apply(&other, TS, DIR);
        assert_eq!(
            set.get("f"),
            Some(&Rollup::Accumulate {
                values: Vec::new(),
                count: 0,
                overflow: false
            })
        );
    }
}
