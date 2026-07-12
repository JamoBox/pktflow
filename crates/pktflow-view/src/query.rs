//! The stream query language — one engine behind the TUI filter box, the
//! web UI's search bar, and the CLI's `--where`, so the same expression
//! means the same thing everywhere.
//!
//! Grammar (case-insensitive keywords, `WHERE` optional and ignored):
//!
//! ```text
//! query   := [WHERE] or
//! or      := and (OR and)*
//! and     := unary ([AND] unary)*        -- juxtaposition is AND
//! unary   := NOT unary | primary
//! primary := '(' or ')' | comparison | flag | free-text | /regex/
//! comparison := field op value
//! op      := == | = | is | != | =~ | !~ | > | >= | < | <= | contains | has
//! ```
//!
//! - **Free text** (`dns`, `"192.168.202.1"`) substring-matches a stream's
//!   searchable text: protocol, `#id`, rendered endpoints, state. A bare
//!   `/regex/` does the same as a case-insensitive regex.
//! - **Fields**: `proto`, `id`, `packets`, `bytes`, `opaque`, `duration`,
//!   `depth`, `children`, `state`, `reason`, `endpoint`, `port` (this
//!   layer *or any ancestor* — "riding on port 443"), `parent`, `under`
//!   (any ancestor protocol). Any other name resolves against the
//!   stream's key fields and rollup values (`vni == 100`,
//!   `qname =~ /google/`).
//! - **Flags**: bare `closed`, `live`, `root`, `leaf`.
//! - **Values**: numbers take magnitude suffixes on byte/count fields
//!   (`10k`, `1.5M`, `2g`) and time suffixes on `duration` (`500ms`,
//!   `90s`, `5m`, `1h`). String comparisons are case-insensitive; `=~`
//!   compiles a case-insensitive regex.

use std::collections::HashMap;

use pktflow_flows::{Rollup, Stream, StreamId};
use regex::{Regex, RegexBuilder};

use crate::fmt::field_value_str;
use crate::stream_view::{close_reason_str, endpoint_sides, endpoints_str};

/// A parse failure: message plus byte offset into the input, so UIs can
/// point at the offending spot.
#[derive(Clone, Debug)]
pub struct QueryError {
    pub message: String,
    pub position: usize,
}

impl std::fmt::Display for QueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (at column {})", self.message, self.position + 1)
    }
}

impl std::error::Error for QueryError {}

/// A parsed, ready-to-evaluate query.
#[derive(Debug)]
pub struct StreamQuery {
    root: Expr,
}

#[derive(Debug)]
enum Expr {
    Or(Box<Expr>, Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    /// Lowercased substring over the searchable text.
    FreeText(String),
    /// Case-insensitive regex over the searchable text.
    FreeRegex(Regex),
    Flag(Flag),
    Cmp {
        field: Field,
        op: CmpOp,
        value: Literal,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Flag {
    Closed,
    Live,
    Root,
    Leaf,
}

#[derive(Clone, PartialEq, Eq, Debug)]
enum Field {
    Proto,
    Id,
    Packets,
    Bytes,
    Opaque,
    Duration,
    Depth,
    Children,
    State,
    Reason,
    Endpoint,
    Port,
    Parent,
    Under,
    /// Key-field or rollup lookup by name.
    Custom(String),
}

impl Field {
    fn resolve(name: &str) -> Field {
        match name.to_ascii_lowercase().as_str() {
            "proto" | "protocol" => Field::Proto,
            "id" => Field::Id,
            "packets" | "pkts" => Field::Packets,
            "bytes" => Field::Bytes,
            "opaque" => Field::Opaque,
            "duration" | "dur" => Field::Duration,
            "depth" => Field::Depth,
            "children" => Field::Children,
            "state" => Field::State,
            "reason" | "close_reason" => Field::Reason,
            "endpoint" | "ep" | "host" | "addr" => Field::Endpoint,
            "port" => Field::Port,
            "parent" => Field::Parent,
            "under" | "ancestor" | "in" => Field::Under,
            _ => Field::Custom(name.to_string()),
        }
    }

    /// How a numeric literal's suffix is scaled for this field.
    fn suffix_scale(&self, suffix: &str) -> Option<f64> {
        let s = suffix.to_ascii_lowercase();
        if s.is_empty() {
            return Some(1.0);
        }
        if *self == Field::Duration {
            return match s.as_str() {
                "ms" => Some(0.001),
                "s" => Some(1.0),
                "m" => Some(60.0),
                "h" => Some(3600.0),
                _ => None,
            };
        }
        match s.as_str() {
            "k" | "kb" => Some(1e3),
            "m" | "mb" => Some(1e6),
            "g" | "gb" => Some(1e9),
            "t" | "tb" => Some(1e12),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum CmpOp {
    Eq,
    Ne,
    Re,
    NotRe,
    Gt,
    Ge,
    Lt,
    Le,
    Contains,
}

/// A comparison's right-hand side: the raw text, an optional numeric
/// reading (`(magnitude, suffix)`), and a compiled regex for `=~`/`!~`.
#[derive(Debug)]
struct Literal {
    raw: String,
    number: Option<(f64, String)>,
    regex: Option<Regex>,
}

/// One candidate value of a field on one stream: rendered text plus a
/// numeric reading when the underlying value is numeric. Comparisons
/// match if *any* candidate matches.
struct Candidate {
    text: String,
    number: Option<f64>,
}

impl Candidate {
    fn text(t: String) -> Self {
        Candidate {
            text: t,
            number: None,
        }
    }

    fn num(n: f64) -> Self {
        Candidate {
            text: format!("{n}"),
            number: Some(n),
        }
    }
}

/* ── lexer ─────────────────────────────────────────────────────────── */

#[derive(Clone, Debug)]
enum Tok {
    LParen,
    RParen,
    And,
    Or,
    Not,
    Op(CmpOp),
    /// Bare word — field name, value, or free text depending on position.
    Word(String),
    /// Quoted string — value or free text, never a field/keyword.
    Str(String),
    /// `/…/` literal.
    Regex(String),
}

/// The operators recognized *inside* a word (`bytes>=10k`), longest first.
const WORD_OPS: [(&str, CmpOp); 8] = [
    ("==", CmpOp::Eq),
    ("!=", CmpOp::Ne),
    ("=~", CmpOp::Re),
    ("!~", CmpOp::NotRe),
    (">=", CmpOp::Ge),
    ("<=", CmpOp::Le),
    (">", CmpOp::Gt),
    ("<", CmpOp::Lt),
];

fn lex(input: &str) -> Result<Vec<(Tok, usize)>, QueryError> {
    let bytes = input.as_bytes();
    let mut toks = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if c == '(' {
            toks.push((Tok::LParen, i));
            i += 1;
            continue;
        }
        if c == ')' {
            toks.push((Tok::RParen, i));
            i += 1;
            continue;
        }
        if c == '"' || c == '\'' {
            let quote = c;
            let start = i + 1;
            let mut j = start;
            while j < bytes.len() && bytes[j] as char != quote {
                j += 1;
            }
            if j >= bytes.len() {
                return Err(QueryError {
                    message: format!("unclosed {quote} quote"),
                    position: i,
                });
            }
            toks.push((Tok::Str(input[start..j].to_string()), i));
            i = j + 1;
            continue;
        }
        if c == '/' {
            // Regex literal: `/…/` with `\/` escapes.
            let start = i + 1;
            let mut j = start;
            let mut pattern = String::new();
            while j < bytes.len() {
                let cj = bytes[j] as char;
                if cj == '\\' && j + 1 < bytes.len() && bytes[j + 1] as char == '/' {
                    pattern.push('/');
                    j += 2;
                    continue;
                }
                if cj == '/' {
                    break;
                }
                pattern.push(cj);
                j += 1;
            }
            if j >= bytes.len() {
                return Err(QueryError {
                    message: "unclosed /regex/ literal".into(),
                    position: i,
                });
            }
            toks.push((Tok::Regex(pattern), i));
            i = j + 1;
            continue;
        }

        // A word: up to whitespace, paren, or quote. Split embedded
        // comparison operators (`bytes>=10k`) into three tokens.
        let start = i;
        let mut j = i;
        while j < bytes.len() {
            let cj = bytes[j] as char;
            if cj.is_whitespace() || cj == '(' || cj == ')' || cj == '"' || cj == '\'' {
                break;
            }
            j += 1;
        }
        let word = &input[start..j];
        i = j;

        let mut split = None;
        for (sym, op) in WORD_OPS {
            if let Some(p) = word.find(sym) {
                let better = match split {
                    Some((q, _, existing_len)) => p < q || (p == q && sym.len() > existing_len),
                    None => true,
                };
                if better {
                    split = Some((p, op, sym.len()));
                }
            }
        }
        match split {
            Some((p, op, sym_len)) => {
                if p > 0 {
                    push_word(&mut toks, &word[..p], start);
                }
                toks.push((Tok::Op(op), start + p));
                let rest = &word[p + sym_len..];
                if !rest.is_empty() {
                    // RHS after an operator is always a value, never a
                    // keyword — keep it opaque as a Str.
                    toks.push((Tok::Str(rest.to_string()), start + p + sym_len));
                }
            }
            None => push_word(&mut toks, word, start),
        }
    }
    Ok(toks)
}

fn push_word(toks: &mut Vec<(Tok, usize)>, word: &str, pos: usize) {
    let tok = match word.to_ascii_lowercase().as_str() {
        "and" | "&&" => Tok::And,
        "or" | "||" => Tok::Or,
        "not" | "!" => Tok::Not,
        "where" => return, // optional keyword, ignored
        "=" | "==" | "is" => Tok::Op(CmpOp::Eq),
        "contains" | "has" => Tok::Op(CmpOp::Contains),
        _ => Tok::Word(word.to_string()),
    };
    toks.push((tok, pos));
}

/* ── parser ────────────────────────────────────────────────────────── */

struct Parser {
    toks: Vec<(Tok, usize)>,
    at: usize,
    input_len: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.at).map(|(t, _)| t)
    }

    fn peek2(&self) -> Option<&Tok> {
        self.toks.get(self.at + 1).map(|(t, _)| t)
    }

    fn pos(&self) -> usize {
        self.toks
            .get(self.at)
            .map(|(_, p)| *p)
            .unwrap_or(self.input_len)
    }

    fn bump(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.at).map(|(t, _)| t.clone());
        self.at += 1;
        t
    }

    fn err(&self, message: impl Into<String>) -> QueryError {
        QueryError {
            message: message.into(),
            position: self.pos(),
        }
    }

    fn parse_or(&mut self) -> Result<Expr, QueryError> {
        let mut left = self.parse_and()?;
        while matches!(self.peek(), Some(Tok::Or)) {
            self.bump();
            let right = self.parse_and()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Expr, QueryError> {
        let mut left = self.parse_unary()?;
        loop {
            match self.peek() {
                Some(Tok::And) => {
                    self.bump();
                }
                // Juxtaposition: `dns 192.168` = AND of two terms.
                Some(Tok::Word(_) | Tok::Str(_) | Tok::Regex(_) | Tok::LParen | Tok::Not) => {}
                _ => break,
            }
            let right = self.parse_unary()?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_unary(&mut self) -> Result<Expr, QueryError> {
        if matches!(self.peek(), Some(Tok::Not)) {
            self.bump();
            return Ok(Expr::Not(Box::new(self.parse_unary()?)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Expr, QueryError> {
        match self.peek() {
            Some(Tok::LParen) => {
                self.bump();
                let inner = self.parse_or()?;
                match self.bump() {
                    Some(Tok::RParen) => Ok(inner),
                    _ => Err(self.err("expected ')'")),
                }
            }
            Some(Tok::Regex(_)) => {
                let Some(Tok::Regex(pattern)) = self.bump() else {
                    return Err(self.err("internal: regex token vanished"));
                };
                Ok(Expr::FreeRegex(self.compile(&pattern)?))
            }
            Some(Tok::Str(_)) => {
                let Some(Tok::Str(s)) = self.bump() else {
                    return Err(self.err("internal: string token vanished"));
                };
                Ok(Expr::FreeText(s.to_lowercase()))
            }
            Some(Tok::Word(_)) => {
                // `word op value` is a comparison; anything else is free
                // text (or a bare flag).
                if matches!(self.peek2(), Some(Tok::Op(_))) {
                    return self.parse_comparison();
                }
                let Some(Tok::Word(w)) = self.bump() else {
                    return Err(self.err("internal: word token vanished"));
                };
                match w.to_ascii_lowercase().as_str() {
                    "closed" => Ok(Expr::Flag(Flag::Closed)),
                    "live" | "open" => Ok(Expr::Flag(Flag::Live)),
                    "root" => Ok(Expr::Flag(Flag::Root)),
                    "leaf" => Ok(Expr::Flag(Flag::Leaf)),
                    _ => Ok(Expr::FreeText(w.to_lowercase())),
                }
            }
            Some(Tok::Op(_)) => Err(self.err("comparison operator needs a field on its left")),
            Some(Tok::RParen) => Err(self.err("unexpected ')'")),
            Some(Tok::And | Tok::Or) => Err(self.err("AND/OR needs a term on both sides")),
            Some(Tok::Not) => Err(self.err("internal: NOT handled in parse_unary")),
            None => Err(self.err("expected a search term")),
        }
    }

    fn parse_comparison(&mut self) -> Result<Expr, QueryError> {
        let Some(Tok::Word(name)) = self.bump() else {
            return Err(self.err("expected a field name"));
        };
        let Some(Tok::Op(op)) = self.bump() else {
            return Err(self.err("expected a comparison operator"));
        };
        let field = Field::resolve(&name);
        let value_pos = self.pos();
        let raw = match self.bump() {
            Some(Tok::Word(w) | Tok::Str(w)) => w,
            Some(Tok::Regex(pattern)) => {
                // `field == /re/` reads as intent to regex-match.
                let op = match op {
                    CmpOp::Ne | CmpOp::NotRe => CmpOp::NotRe,
                    _ => CmpOp::Re,
                };
                return Ok(Expr::Cmp {
                    field,
                    op,
                    value: Literal {
                        raw: pattern.clone(),
                        number: None,
                        regex: Some(self.compile(&pattern)?),
                    },
                });
            }
            _ => {
                return Err(QueryError {
                    message: format!("'{name}' comparison is missing its value"),
                    position: value_pos,
                })
            }
        };

        let number = parse_number(&raw);
        if matches!(op, CmpOp::Gt | CmpOp::Ge | CmpOp::Lt | CmpOp::Le) && number.is_none() {
            return Err(QueryError {
                message: format!("'{raw}' is not a number (>, >=, <, <= compare numbers)"),
                position: value_pos,
            });
        }
        let regex = if matches!(op, CmpOp::Re | CmpOp::NotRe) {
            Some(self.compile(&raw)?)
        } else {
            None
        };
        Ok(Expr::Cmp {
            field,
            op,
            value: Literal { raw, number, regex },
        })
    }

    fn compile(&self, pattern: &str) -> Result<Regex, QueryError> {
        RegexBuilder::new(pattern)
            .case_insensitive(true)
            .size_limit(1 << 20)
            .build()
            .map_err(|e| QueryError {
                message: format!("bad regex: {e}"),
                position: self
                    .toks
                    .get(self.at.saturating_sub(1))
                    .map_or(0, |(_, p)| *p),
            })
    }
}

/// `10`, `1.5k`, `500ms` → (magnitude, suffix). The suffix is scaled per
/// field at eval time (`m` is minutes on `duration`, mega elsewhere).
fn parse_number(raw: &str) -> Option<(f64, String)> {
    let split = raw
        .char_indices()
        .find(|(_, c)| !(c.is_ascii_digit() || *c == '.' || *c == '-' || *c == '+'))
        .map(|(i, _)| i)
        .unwrap_or(raw.len());
    if split == 0 {
        return None;
    }
    let mag: f64 = raw[..split].parse().ok()?;
    let suffix = &raw[split..];
    if !suffix.chars().all(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    Some((mag, suffix.to_string()))
}

/* ── evaluation ────────────────────────────────────────────────────── */

impl StreamQuery {
    pub fn parse(input: &str) -> Result<StreamQuery, QueryError> {
        let toks = lex(input)?;
        if toks.is_empty() {
            return Err(QueryError {
                message: "empty query".into(),
                position: 0,
            });
        }
        let input_len = input.len();
        let mut parser = Parser {
            toks,
            at: 0,
            input_len,
        };
        let root = parser.parse_or()?;
        if parser.peek().is_some() {
            return Err(parser.err("unexpected trailing input"));
        }
        Ok(StreamQuery { root })
    }

    /// Does one stream satisfy the query? `ids` supplies the ancestry
    /// (lineage fields, ancestor ports, depth).
    pub fn matches(&self, s: &Stream, ids: &HashMap<StreamId, &Stream>) -> bool {
        eval(&self.root, s, ids)
    }
}

fn eval(e: &Expr, s: &Stream, ids: &HashMap<StreamId, &Stream>) -> bool {
    match e {
        Expr::Or(l, r) => eval(l, s, ids) || eval(r, s, ids),
        Expr::And(l, r) => eval(l, s, ids) && eval(r, s, ids),
        Expr::Not(inner) => !eval(inner, s, ids),
        Expr::FreeText(needle) => searchable_text(s).to_lowercase().contains(needle),
        Expr::FreeRegex(re) => re.is_match(&searchable_text(s)),
        Expr::Flag(flag) => match flag {
            Flag::Closed => s.closed.is_some(),
            Flag::Live => s.closed.is_none(),
            Flag::Root => s.parent.is_none(),
            Flag::Leaf => s.children.is_empty(),
        },
        Expr::Cmp { field, op, value } => {
            let candidates = field_candidates(field, s, ids);
            candidates.iter().any(|c| compare(c, *op, value, field))
        }
    }
}

/// The free-text haystack: protocol, `#id`, rendered endpoints, state —
/// exactly what a streams-view row shows.
pub fn searchable_text(s: &Stream) -> String {
    let mut t = format!("{} #{} {}", s.protocol, s.created_seq, endpoints_str(s));
    if let Some(state) = s.state {
        t.push(' ');
        t.push_str(state);
    }
    t
}

fn ancestors<'a>(
    s: &'a Stream,
    ids: &'a HashMap<StreamId, &'a Stream>,
) -> impl Iterator<Item = &'a Stream> {
    std::iter::successors(s.parent.and_then(|p| ids.get(&p).copied()), |cur| {
        cur.parent.and_then(|p| ids.get(&p).copied())
    })
}

fn field_candidates(field: &Field, s: &Stream, ids: &HashMap<StreamId, &Stream>) -> Vec<Candidate> {
    match field {
        Field::Proto => vec![Candidate::text(s.protocol.to_string())],
        Field::Id => vec![Candidate::num(s.created_seq as f64)],
        Field::Packets => {
            vec![Candidate::num(
                (s.stats[0].packets + s.stats[1].packets) as f64,
            )]
        }
        Field::Bytes => vec![Candidate::num((s.stats[0].bytes + s.stats[1].bytes) as f64)],
        Field::Opaque => vec![Candidate::num(s.opaque_bytes as f64)],
        Field::Duration => {
            let d = s.last_seen.duration_since(s.first_seen).unwrap_or_default();
            vec![Candidate::num(d.as_secs_f64())]
        }
        Field::Depth => vec![Candidate::num(ancestors(s, ids).count() as f64)],
        Field::Children => vec![Candidate::num(s.children.len() as f64)],
        Field::State => vec![Candidate::text(s.state.unwrap_or("").to_string())],
        Field::Reason => vec![Candidate::text(
            s.closed.map(close_reason_str).unwrap_or("").to_string(),
        )],
        Field::Endpoint => {
            let (a, b, extras) = endpoint_sides(s);
            let mut out = vec![Candidate::text(a), Candidate::text(b)];
            out.extend(extras.into_iter().map(Candidate::text));
            out
        }
        Field::Port => {
            // "riding on port N": this layer or any ancestor.
            let mut out = Vec::new();
            for stream in std::iter::once(s).chain(ancestors(s, ids)) {
                for (name, value) in stream.key_fields.iter() {
                    if name.ends_with("port") {
                        if let Some(n) = value_as_number(value) {
                            out.push(Candidate::num(n));
                        }
                    }
                }
            }
            out
        }
        Field::Parent => vec![Candidate::text(
            s.parent
                .and_then(|p| ids.get(&p))
                .map(|p| p.protocol.to_string())
                .unwrap_or_default(),
        )],
        Field::Under => ancestors(s, ids)
            .map(|a| Candidate::text(a.protocol.to_string()))
            .collect(),
        Field::Custom(name) => custom_candidates(name, s),
    }
}

/// Key fields first, then rollup contents — any observed value counts.
fn custom_candidates(name: &str, s: &Stream) -> Vec<Candidate> {
    let mut out = Vec::new();
    if let Some(value) = s.key_fields.get(name) {
        out.push(candidate_of(s.protocol, name, value));
    }
    match s.rollups.get(name) {
        Some(Rollup::Accumulate { values, .. }) => {
            out.extend(values.iter().map(|v| candidate_of(s.protocol, name, v)));
        }
        Some(Rollup::Sample { first, last }) => {
            out.extend(
                [first, last]
                    .into_iter()
                    .flatten()
                    .map(|v| candidate_of(s.protocol, name, v)),
            );
        }
        Some(Rollup::Series { ring, .. }) => {
            out.extend(
                ring.iter()
                    .map(|p| candidate_of(s.protocol, name, &p.value)),
            );
        }
        None => {}
    }
    out
}

fn candidate_of(protocol: &str, name: &str, value: &pktflow_core::Value) -> Candidate {
    Candidate {
        text: field_value_str(protocol, name, value),
        number: value_as_number(value),
    }
}

fn value_as_number(value: &pktflow_core::Value) -> Option<f64> {
    match value {
        pktflow_core::Value::U64(v) => Some(*v as f64),
        pktflow_core::Value::I64(v) => Some(*v as f64),
        _ => None,
    }
}

fn compare(c: &Candidate, op: CmpOp, value: &Literal, field: &Field) -> bool {
    let rhs_num = value
        .number
        .as_ref()
        .and_then(|(mag, suffix)| field.suffix_scale(suffix).map(|scale| mag * scale));
    match op {
        CmpOp::Gt | CmpOp::Ge | CmpOp::Lt | CmpOp::Le => {
            let (Some(lhs), Some(rhs)) = (c.number, rhs_num) else {
                return false;
            };
            match op {
                CmpOp::Gt => lhs > rhs,
                CmpOp::Ge => lhs >= rhs,
                CmpOp::Lt => lhs < rhs,
                CmpOp::Le => lhs <= rhs,
                _ => false,
            }
        }
        CmpOp::Eq | CmpOp::Ne => {
            let hit = match (c.number, rhs_num) {
                (Some(lhs), Some(rhs)) => lhs == rhs,
                _ => c.text.eq_ignore_ascii_case(&value.raw),
            };
            hit == (op == CmpOp::Eq)
        }
        CmpOp::Contains => c.text.to_lowercase().contains(&value.raw.to_lowercase()),
        CmpOp::Re | CmpOp::NotRe => {
            let hit = value.regex.as_ref().is_some_and(|re| re.is_match(&c.text));
            hit == (op == CmpOp::Re)
        }
    }
}

/* ── filtering helpers shared by the UIs ───────────────────────────── */

/// The ids (`created_seq`) of matching streams plus every ancestor of a
/// match — the visible set both UIs display, so results always sit in
/// their hierarchy context.
pub fn matching_with_ancestors(
    streams: &[Stream],
    ids: &HashMap<StreamId, &Stream>,
    query: &StreamQuery,
) -> std::collections::HashSet<u64> {
    let mut keep = std::collections::HashSet::new();
    for s in streams {
        if query.matches(s, ids) {
            keep.insert(s.created_seq);
            let mut cursor = s.parent;
            while let Some(pid) = cursor {
                let Some(parent) = ids.get(&pid) else { break };
                if !keep.insert(parent.created_seq) {
                    break;
                }
                cursor = parent.parent;
            }
        }
    }
    keep
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    use pktflow_core::{
        Canonicalize, DissectedPacket, Engine, FieldMap, KeyField, LayerPlugin, LayerRecord,
        LinkType, PacketMeta, ParseCtx, ParseError, ParsedLayer, ProtocolName, RollupKind,
        RollupSpec, StopReason, StreamIdentity, Value,
    };
    use pktflow_flows::{Aggregator, AggregatorConfig, AggregatorSnapshot};

    use super::*;
    use crate::stream_view::by_id;

    /// Identity-bearing test plugin with a port-pair key and a qname
    /// accumulate rollup; ingest never calls parse.
    struct Keyed {
        name: ProtocolName,
        identity: StreamIdentity,
    }

    impl LayerPlugin for Keyed {
        fn name(&self) -> ProtocolName {
            self.name
        }

        fn parse(&self, _bytes: &[u8], _ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
            Err(ParseError::Malformed("ingest-only test plugin"))
        }

        fn stream_identity(&self) -> Option<&StreamIdentity> {
            Some(&self.identity)
        }
    }

    static ADDR_KEY: &[KeyField] = &[KeyField {
        a: "src_addr",
        b: Some("dst_addr"),
    }];
    static PORT_KEY: &[KeyField] = &[KeyField {
        a: "src_port",
        b: Some("dst_port"),
    }];
    static QNAME_ROLLUP: &[RollupSpec] = &[RollupSpec {
        field: "qname",
        kind: RollupKind::Accumulate,
    }];

    fn engine() -> Arc<Engine> {
        Arc::new(
            Engine::builder()
                .plugin(Keyed {
                    name: "ipv4",
                    identity: StreamIdentity {
                        key: ADDR_KEY,
                        canonicalize: Canonicalize::EndpointSort,
                        lifecycle: None,
                        rollups: &[],
                    },
                })
                .plugin(Keyed {
                    name: "udp",
                    identity: StreamIdentity {
                        key: PORT_KEY,
                        canonicalize: Canonicalize::EndpointSort,
                        lifecycle: None,
                        rollups: &[],
                    },
                })
                .plugin(Keyed {
                    name: "dns",
                    identity: StreamIdentity {
                        key: PORT_KEY,
                        canonicalize: Canonicalize::EndpointSort,
                        lifecycle: None,
                        rollups: QNAME_ROLLUP,
                    },
                })
                .build()
                .expect("valid registry"),
        )
    }

    fn layer(protocol: ProtocolName, fields: &[(&'static str, Value)]) -> LayerRecord {
        let mut map = FieldMap::new();
        for (name, value) in fields {
            map.insert(name, value.clone());
        }
        LayerRecord {
            protocol,
            offset: 0,
            header_len: 0,
            fields: map,
        }
    }

    fn addr(a: u8, b: u8, c: u8, d: u8) -> Value {
        Value::from(&[a, b, c, d][..])
    }

    /// ipv4(10.0.0.1↔10.0.0.2) ▸ udp(:53↔:40000) ▸ dns(qname rollup),
    /// plus a fat second root ipv4(192.168.1.9↔192.168.1.10), 30 s long.
    fn snapshot() -> AggregatorSnapshot {
        let mut agg = Aggregator::new(&engine(), AggregatorConfig::default());
        let ts = |ms: u64| SystemTime::UNIX_EPOCH + Duration::from_millis(ms);
        agg.ingest(&DissectedPacket {
            meta: PacketMeta {
                timestamp: ts(0),
                caplen: 90,
                origlen: 90,
                link_type: LinkType::ETHERNET,
            },
            layers: vec![
                layer(
                    "ipv4",
                    &[
                        ("src_addr", addr(10, 0, 0, 1)),
                        ("dst_addr", addr(10, 0, 0, 2)),
                    ],
                ),
                layer(
                    "udp",
                    &[
                        ("src_port", Value::U64(40000)),
                        ("dst_port", Value::U64(53)),
                    ],
                ),
                layer(
                    "dns",
                    &[
                        ("src_port", Value::U64(40000)),
                        ("dst_port", Value::U64(53)),
                        ("qname", Value::Str("api.Google.com".into())),
                    ],
                ),
            ],
            stop: StopReason::Complete,
            opaque_len: 0,
            unknown: None,
        });
        for ms in [1_000u64, 31_000] {
            agg.ingest(&DissectedPacket {
                meta: PacketMeta {
                    timestamp: ts(ms),
                    caplen: 60_000,
                    origlen: 60_000,
                    link_type: LinkType::ETHERNET,
                },
                layers: vec![layer(
                    "ipv4",
                    &[
                        ("src_addr", addr(192, 168, 1, 9)),
                        ("dst_addr", addr(192, 168, 1, 10)),
                    ],
                )],
                stop: StopReason::Complete,
                opaque_len: 0,
                unknown: None,
            });
        }
        agg.snapshot()
    }

    fn ids_of(query: &str, snap: &AggregatorSnapshot) -> Vec<u64> {
        let q = StreamQuery::parse(query).expect("query parses");
        let ids = by_id(snap);
        let mut out: Vec<u64> = snap
            .streams
            .iter()
            .filter(|s| q.matches(s, &ids))
            .map(|s| s.created_seq)
            .collect();
        out.sort_unstable();
        out
    }

    // Stream ids in the fixture: 0=ipv4 A, 1=udp, 2=dns, 3=ipv4 B (fat).

    #[test]
    fn free_text_and_regex_terms() {
        let snap = snapshot();
        assert_eq!(ids_of("dns", &snap), [2]);
        assert_eq!(ids_of("10.0.0.1", &snap), [0]);
        assert_eq!(ids_of("/192\\.168\\.1\\.(9|10)/", &snap), [3]);
        assert_eq!(ids_of("DNS", &snap), [2], "free text is case-insensitive");
    }

    #[test]
    fn boolean_operators_and_grouping() {
        let snap = snapshot();
        assert_eq!(ids_of("proto == udp OR proto == dns", &snap), [1, 2]);
        assert_eq!(ids_of("ipv4 AND bytes > 1k", &snap), [3]);
        assert_eq!(ids_of("NOT proto == ipv4", &snap), [1, 2]);
        assert_eq!(
            ids_of("(proto = udp or proto = dns) and port == 53", &snap),
            [1, 2],
            "keywords are case-insensitive; = is =="
        );
        // Juxtaposition is AND.
        assert_eq!(ids_of("ipv4 10.0", &snap), [0]);
    }

    #[test]
    fn numeric_fields_with_suffixes() {
        let snap = snapshot();
        assert_eq!(ids_of("bytes >= 100k", &snap), [3]);
        assert_eq!(ids_of("bytes<1k", &snap), [0, 1, 2], "no-space operator");
        assert_eq!(ids_of("duration > 5s", &snap), [3]);
        assert_eq!(ids_of("duration >= 0.5m", &snap), [3], "m = minutes here");
        assert_eq!(ids_of("packets == 2", &snap), [3]);
        assert_eq!(ids_of("id == 1", &snap), [1]);
    }

    #[test]
    fn structure_fields() {
        let snap = snapshot();
        assert_eq!(ids_of("under == udp", &snap), [2]);
        assert_eq!(ids_of("parent == ipv4", &snap), [1]);
        assert_eq!(ids_of("depth == 0 AND leaf", &snap), [3]);
        assert_eq!(ids_of("root", &snap), [0, 3]);
        assert_eq!(ids_of("port == 53", &snap), [1, 2], "port sees ancestors");
    }

    #[test]
    fn custom_fields_hit_keys_and_rollups() {
        let snap = snapshot();
        assert_eq!(ids_of("qname =~ /google/", &snap), [2], "rollup + ci regex");
        assert_eq!(ids_of("qname contains api.", &snap), [2]);
        assert_eq!(ids_of("src_port == 40000", &snap), [1, 2], "key field");
        assert_eq!(ids_of("qname == nosuch.com", &snap), [0u64; 0]);
    }

    #[test]
    fn where_prefix_and_quoted_text() {
        let snap = snapshot();
        assert_eq!(ids_of("WHERE proto == dns", &snap), [2]);
        assert_eq!(ids_of("\"192.168.1.9\"", &snap), [3]);
    }

    #[test]
    fn ancestors_ride_along_for_display() {
        let snap = snapshot();
        let q = StreamQuery::parse("proto == dns").expect("parses");
        let ids = by_id(&snap);
        let mut visible: Vec<u64> = matching_with_ancestors(&snap.streams, &ids, &q)
            .into_iter()
            .collect();
        visible.sort_unstable();
        assert_eq!(visible, [0, 1, 2], "dns plus its udp/ipv4 lineage");
    }

    #[test]
    fn parse_errors_are_positioned_and_informative() {
        for (query, needle) in [
            ("bytes >", "missing its value"),
            ("== 5", "needs a field on its left"),
            ("(dns", "expected ')'"),
            ("proto == dns AND", "expected a search term"),
            ("/unclosed", "unclosed /regex/"),
            ("\"unclosed", "unclosed"),
            ("bytes > lots", "not a number"),
            ("qname =~ /((/", "bad regex"),
            ("", "empty query"),
        ] {
            let err = StreamQuery::parse(query).expect_err(query);
            assert!(
                err.to_string().contains(needle),
                "{query:?} → {err} (wanted {needle:?})"
            );
        }
    }
}
