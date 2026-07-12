//! App state and key handling — pure with respect to the terminal, so
//! every transition is unit-testable without a PTY.

use std::collections::HashSet;
use std::sync::Arc;

use pktflow_flows::AggregatorSnapshot;
use pktflow_view::StreamQuery;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::tree::{flatten, Sort};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tab {
    Streams,
    Timeline,
    Unknown,
    Summary,
}

impl Tab {
    pub fn next(self) -> Self {
        match self {
            Tab::Streams => Tab::Timeline,
            Tab::Timeline => Tab::Unknown,
            Tab::Unknown => Tab::Summary,
            Tab::Summary => Tab::Streams,
        }
    }
}

pub struct App {
    pub tab: Tab,
    pub sort: Sort,
    /// Collapsed stream ids (`created_seq`) — expand is the default so a
    /// fresh capture opens fully unfolded, like the CLI tree.
    pub collapsed: HashSet<u64>,
    /// Selection keyed by display id, not row index: stable while live
    /// updates insert and evict rows around it.
    pub selected: Option<u64>,
    pub filter: String,
    pub filter_editing: bool,
    /// The filter parsed as a query — `None` while empty or broken.
    pub query: Option<StreamQuery>,
    /// Why the filter failed to parse, shown until the next edit.
    pub query_error: Option<String>,
    pub detail_scroll: u16,
    pub unknown_index: usize,
    pub unknown_open: bool,
    pub popup_scroll: u16,
    pub help: bool,
    /// Freeze the rendered snapshot during live capture (aggregation
    /// keeps running; unfreezing jumps to the newest state).
    pub paused: bool,
    /// Timeline playhead as a fraction of the capture span; 1.0 = the
    /// live edge / capture end (the neutral position).
    pub timeline_t: f64,
    pub timeline_playing: bool,
    pub quit: bool,
}

impl Default for App {
    fn default() -> Self {
        Self {
            tab: Tab::Streams,
            sort: Sort::Bytes,
            collapsed: HashSet::new(),
            selected: None,
            filter: String::new(),
            filter_editing: false,
            query: None,
            query_error: None,
            detail_scroll: 0,
            unknown_index: 0,
            unknown_open: false,
            popup_scroll: 0,
            help: false,
            paused: false,
            timeline_t: 1.0,
            timeline_playing: false,
            quit: false,
        }
    }
}

impl App {
    /// Applies one key press against the snapshot currently on screen.
    pub fn on_key(&mut self, key: KeyEvent, snapshot: &Arc<AggregatorSnapshot>) {
        // Ctrl-C always quits, whatever mode we're in.
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.quit = true;
            return;
        }

        if self.filter_editing {
            match key.code {
                KeyCode::Esc => {
                    self.filter.clear();
                    self.filter_editing = false;
                }
                KeyCode::Enter => self.filter_editing = false,
                KeyCode::Backspace => {
                    self.filter.pop();
                }
                KeyCode::Char(c) => self.filter.push(c),
                _ => {}
            }
            self.refresh_query();
            return;
        }

        if self.help {
            self.help = false; // any key dismisses the overlay
            return;
        }

        if self.unknown_open {
            match key.code {
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {
                    self.unknown_open = false;
                    self.popup_scroll = 0;
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.popup_scroll = self.popup_scroll.saturating_sub(1)
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.popup_scroll = self.popup_scroll.saturating_add(1)
                }
                KeyCode::PageUp => self.popup_scroll = self.popup_scroll.saturating_sub(16),
                KeyCode::PageDown => self.popup_scroll = self.popup_scroll.saturating_add(16),
                _ => {}
            }
            return;
        }

        match key.code {
            KeyCode::Char('q') => self.quit = true,
            KeyCode::Char('?') => self.help = true,
            KeyCode::Char('1') => self.tab = Tab::Streams,
            KeyCode::Char('2') => self.tab = Tab::Timeline,
            KeyCode::Char('3') => self.tab = Tab::Unknown,
            KeyCode::Char('4') => self.tab = Tab::Summary,
            KeyCode::Tab => self.tab = self.tab.next(),
            KeyCode::Char('p') => self.paused = !self.paused,
            KeyCode::Char('/') if matches!(self.tab, Tab::Streams | Tab::Timeline) => {
                self.filter_editing = true
            }
            _ => match self.tab {
                Tab::Streams => self.on_streams_key(key, snapshot),
                Tab::Timeline => self.on_timeline_key(key, snapshot),
                Tab::Unknown => self.on_unknown_key(key, snapshot),
                Tab::Summary => {}
            },
        }
    }

    /// Re-parse the filter box into a query. A broken expression keeps
    /// the tree unfiltered and surfaces the error instead of silently
    /// hiding streams.
    pub fn refresh_query(&mut self) {
        let trimmed = self.filter.trim();
        if trimmed.is_empty() {
            self.query = None;
            self.query_error = None;
            return;
        }
        match StreamQuery::parse(trimmed) {
            Ok(query) => {
                self.query = Some(query);
                self.query_error = None;
            }
            Err(e) => {
                self.query = None;
                self.query_error = Some(e.to_string());
            }
        }
    }

    fn on_streams_key(&mut self, key: KeyEvent, snapshot: &Arc<AggregatorSnapshot>) {
        let rows = flatten(snapshot, self.sort, &self.collapsed, self.query.as_ref());
        let index = self.selected_index(&rows);
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.select_row(&rows, index.saturating_sub(1)),
            KeyCode::Down | KeyCode::Char('j') => self.select_row(&rows, index.saturating_add(1)),
            KeyCode::PageUp => self.select_row(&rows, index.saturating_sub(10)),
            KeyCode::PageDown => self.select_row(&rows, index.saturating_add(10)),
            KeyCode::Home | KeyCode::Char('g') => self.select_row(&rows, 0),
            KeyCode::End | KeyCode::Char('G') => self.select_row(&rows, rows.len()),
            KeyCode::Enter | KeyCode::Char(' ') => {
                if let Some(row) = rows.get(index) {
                    if row.has_children {
                        let seq = row.stream.created_seq;
                        if !self.collapsed.remove(&seq) {
                            self.collapsed.insert(seq);
                        }
                    }
                }
            }
            KeyCode::Right | KeyCode::Char('l') => {
                if let Some(row) = rows.get(index) {
                    self.collapsed.remove(&row.stream.created_seq);
                }
            }
            KeyCode::Left | KeyCode::Char('h') => {
                if let Some(row) = rows.get(index) {
                    let seq = row.stream.created_seq;
                    if row.has_children && row.expanded && self.filter.trim().is_empty() {
                        self.collapsed.insert(seq);
                    } else if let Some(parent_id) = row.stream.parent {
                        // Jump to the parent row instead of a no-op.
                        if let Some(pi) = rows.iter().position(|r| r.stream.id == parent_id) {
                            self.select_row(&rows, pi);
                        }
                    }
                }
            }
            KeyCode::Char('e') => self.collapsed.clear(),
            KeyCode::Char('c') => {
                self.collapsed = snapshot
                    .streams
                    .iter()
                    .filter(|s| !s.children.is_empty())
                    .map(|s| s.created_seq)
                    .collect();
            }
            KeyCode::Char('s') => self.sort = self.sort.next(),
            KeyCode::Char('J') => self.detail_scroll = self.detail_scroll.saturating_add(1),
            KeyCode::Char('K') => self.detail_scroll = self.detail_scroll.saturating_sub(1),
            _ => {}
        }
    }

    /// Timeline: ←→ scrub (2% steps), `[`/`]` coarse (10%), Space
    /// plays the playhead across the span, ↑↓ move the lane selection,
    /// Enter opens the selected stream in the Streams tab.
    fn on_timeline_key(&mut self, key: KeyEvent, snapshot: &Arc<AggregatorSnapshot>) {
        let rows = flatten(snapshot, self.sort, &self.collapsed, self.query.as_ref());
        let index = self.selected_index(&rows);
        match key.code {
            KeyCode::Left | KeyCode::Char('h') => self.scrub(-0.02),
            KeyCode::Right | KeyCode::Char('l') => self.scrub(0.02),
            KeyCode::Char('[') | KeyCode::PageUp => self.scrub(-0.10),
            KeyCode::Char(']') | KeyCode::PageDown => self.scrub(0.10),
            KeyCode::Home | KeyCode::Char('g') => self.scrub(f64::NEG_INFINITY),
            KeyCode::End | KeyCode::Char('G') => self.scrub(f64::INFINITY),
            KeyCode::Char(' ') => {
                // Replay from the start when playing from the live edge.
                if !self.timeline_playing && self.timeline_t >= 1.0 {
                    self.timeline_t = 0.0;
                }
                self.timeline_playing = !self.timeline_playing;
            }
            KeyCode::Up | KeyCode::Char('k') => self.select_row(&rows, index.saturating_sub(1)),
            KeyCode::Down | KeyCode::Char('j') => self.select_row(&rows, index.saturating_add(1)),
            KeyCode::Enter => self.tab = Tab::Streams,
            _ => {}
        }
    }

    fn scrub(&mut self, delta: f64) {
        self.timeline_playing = false;
        self.timeline_t = (self.timeline_t + delta).clamp(0.0, 1.0);
    }

    /// One animation tick from the event loop (~10/s while playing).
    pub fn tick(&mut self) {
        if self.tab == Tab::Timeline && self.timeline_playing {
            self.timeline_t += 0.01;
            if self.timeline_t >= 1.0 {
                self.timeline_t = 1.0;
                self.timeline_playing = false;
            }
        }
    }

    fn on_unknown_key(&mut self, key: KeyEvent, snapshot: &Arc<AggregatorSnapshot>) {
        let count = snapshot.unknowns.len();
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.unknown_index = self.unknown_index.saturating_sub(1)
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.unknown_index = (self.unknown_index + 1).min(count.saturating_sub(1))
            }
            KeyCode::Home | KeyCode::Char('g') => self.unknown_index = 0,
            KeyCode::End | KeyCode::Char('G') => self.unknown_index = count.saturating_sub(1),
            KeyCode::Enter if count > 0 => {
                self.unknown_open = true;
                self.popup_scroll = 0;
            }
            _ => {}
        }
    }

    /// The selected row's index under the current row set; falls back to
    /// the first row when the selection evicted or nothing is selected.
    pub fn selected_index(&self, rows: &[crate::tree::TreeRow<'_>]) -> usize {
        self.selected
            .and_then(|seq| rows.iter().position(|r| r.stream.created_seq == seq))
            .unwrap_or(0)
    }

    fn select_row(&mut self, rows: &[crate::tree::TreeRow<'_>], index: usize) {
        if rows.is_empty() {
            self.selected = None;
            return;
        }
        let clamped = index.min(rows.len() - 1);
        if let Some(row) = rows.get(clamped) {
            if self.selected != Some(row.stream.created_seq) {
                self.detail_scroll = 0; // fresh stream, fresh detail view
            }
            self.selected = Some(row.stream.created_seq);
        }
    }
}
