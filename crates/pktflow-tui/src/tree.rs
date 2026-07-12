//! The browsable tree model: the stream hierarchy flattened to visible
//! rows under the current sort, collapse set, and filter. Pure functions
//! over a snapshot — the render layer never walks the hierarchy itself.

use std::collections::{HashMap, HashSet};

use pktflow_flows::{AggregatorSnapshot, Stream, StreamId};
use pktflow_view::query::matching_with_ancestors;
use pktflow_view::{by_id, total_bytes, total_packets, StreamQuery};

/// Sibling sort order (mirrors the CLI's `--sort` values).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Sort {
    Bytes,
    Packets,
    FirstSeen,
    Duration,
}

impl Sort {
    pub fn next(self) -> Self {
        match self {
            Sort::Bytes => Sort::Packets,
            Sort::Packets => Sort::FirstSeen,
            Sort::FirstSeen => Sort::Duration,
            Sort::Duration => Sort::Bytes,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Sort::Bytes => "bytes",
            Sort::Packets => "packets",
            Sort::FirstSeen => "first-seen",
            Sort::Duration => "duration",
        }
    }
}

/// One visible row of the tree pane.
pub struct TreeRow<'a> {
    pub stream: &'a Stream,
    /// Tree glyph prefix (`│  ├─ ` …), ready to print before the label.
    pub prefix: String,
    pub has_children: bool,
    pub expanded: bool,
}

fn sort_siblings(streams: &mut [&Stream], order: Sort) {
    match order {
        Sort::Bytes => streams.sort_by_key(|s| std::cmp::Reverse(total_bytes(s))),
        Sort::Packets => streams.sort_by_key(|s| std::cmp::Reverse(total_packets(s))),
        Sort::FirstSeen => streams.sort_by_key(|s| s.created_seq),
        Sort::Duration => streams.sort_by_key(|s| {
            std::cmp::Reverse(s.last_seen.duration_since(s.first_seen).unwrap_or_default())
        }),
    }
}

/// Flattens the hierarchy into visible rows. With no query, a collapsed
/// node hides its subtree. With a query, rows are the matches plus every
/// ancestor of a match (auto-expanded so results are always reachable).
pub fn flatten<'a>(
    snapshot: &'a AggregatorSnapshot,
    sort: Sort,
    collapsed: &HashSet<u64>,
    query: Option<&StreamQuery>,
) -> Vec<TreeRow<'a>> {
    let ids = by_id(snapshot);

    // Filtered mode: the visible set is matches ∪ their ancestors.
    let visible: Option<HashSet<u64>> =
        query.map(|q| matching_with_ancestors(&snapshot.streams, &ids, q));

    let mut rows = Vec::new();
    let mut roots: Vec<&Stream> = snapshot
        .roots
        .iter()
        .filter_map(|id| ids.get(id).copied())
        .filter(|s| visible.as_ref().is_none_or(|v| v.contains(&s.created_seq)))
        .collect();
    sort_siblings(&mut roots, sort);
    for root in roots {
        push_subtree(root, &ids, "", sort, collapsed, visible.as_ref(), &mut rows);
    }
    rows
}

fn push_subtree<'a>(
    s: &'a Stream,
    ids: &HashMap<StreamId, &'a Stream>,
    prefix: &str,
    sort: Sort,
    collapsed: &HashSet<u64>,
    visible: Option<&HashSet<u64>>,
    rows: &mut Vec<TreeRow<'a>>,
) {
    let mut children: Vec<&Stream> = s
        .children
        .iter()
        .filter_map(|id| ids.get(id).copied())
        .filter(|c| visible.is_none_or(|v| v.contains(&c.created_seq)))
        .collect();
    sort_siblings(&mut children, sort);

    let has_children = !children.is_empty();
    // A query auto-expands: matches must always be reachable.
    let expanded = visible.is_some() || !collapsed.contains(&s.created_seq);
    rows.push(TreeRow {
        stream: s,
        prefix: prefix.to_string(),
        has_children,
        expanded,
    });
    if !expanded {
        return;
    }

    // Glyph prefixes: the label prefix ends with the branch glyph; child
    // subtrees continue with `│  ` under a `├─` and spaces under a `└─`.
    let bare = prefix.replace("├─ ", "│  ").replace("└─ ", "   ");
    let count = children.len();
    for (i, child) in children.into_iter().enumerate() {
        let last = i + 1 == count;
        let branch = if last { "└─ " } else { "├─ " };
        push_subtree(
            child,
            ids,
            &format!("{bare}{branch}"),
            sort,
            collapsed,
            visible,
            rows,
        );
    }
}
