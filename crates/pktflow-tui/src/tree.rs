//! The browsable tree model: the stream hierarchy flattened to visible
//! rows under the current sort, collapse set, and filter. Pure functions
//! over a snapshot — the render layer never walks the hierarchy itself.

use std::collections::HashSet;
use std::sync::Arc;

use pktflow_flows::Stream;
use pktflow_view::{total_bytes, total_packets, SnapshotIndex};

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

/// Cap on the rows a single flatten materializes (12.5): a keypress
/// must stay interactive whatever the capture holds, and no terminal
/// browses ten thousand rows anyway — narrow with a query instead.
pub const MAX_ROWS: usize = 10_000;

/// Flattens the hierarchy into visible rows. With no query, a collapsed
/// node hides its subtree. With a query, rows are the matches plus every
/// ancestor of a match (auto-expanded so results are always reachable).
/// Resolution and query evaluation come from the per-snapshot
/// [`SnapshotIndex`] (12.4): a keypress re-flattens, but never rebuilds
/// an id map or re-evaluates the filter — and never materializes more
/// than [`MAX_ROWS`] rows.
pub fn flatten<'a>(
    index: &'a SnapshotIndex,
    sort: Sort,
    collapsed: &HashSet<u64>,
    query: Option<&str>,
) -> Vec<TreeRow<'a>> {
    // Filtered mode: the visible set is matches ∪ their ancestors
    // (cached in the index per expression).
    let sets = query
        .filter(|q| !q.trim().is_empty())
        .and_then(|q| index.query_sets(q));
    let visible: Option<&HashSet<u64>> = sets.as_ref().map(|s| &s.1);

    let snapshot = Arc::clone(index.snapshot());
    let mut rows = Vec::new();
    let mut roots: Vec<&Stream> = snapshot
        .roots
        .iter()
        .filter_map(|&id| index.by_id(id))
        .filter(|s| visible.is_none_or(|v| v.contains(&s.created_seq)))
        .collect();
    sort_siblings(&mut roots, sort);
    for root in roots {
        if rows.len() >= MAX_ROWS {
            break;
        }
        push_subtree(root, index, "", sort, collapsed, visible, &mut rows);
    }
    rows
}

fn push_subtree<'a>(
    s: &'a Stream,
    index: &'a SnapshotIndex,
    prefix: &str,
    sort: Sort,
    collapsed: &HashSet<u64>,
    visible: Option<&HashSet<u64>>,
    rows: &mut Vec<TreeRow<'a>>,
) {
    if rows.len() >= MAX_ROWS {
        return;
    }
    let mut children: Vec<&Stream> = s
        .children
        .iter()
        .filter_map(|&id| index.by_id(id))
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
        if rows.len() >= MAX_ROWS {
            return;
        }
        let last = i + 1 == count;
        let branch = if last { "└─ " } else { "├─ " };
        push_subtree(
            child,
            index,
            &format!("{bare}{branch}"),
            sort,
            collapsed,
            visible,
            rows,
        );
    }
}
