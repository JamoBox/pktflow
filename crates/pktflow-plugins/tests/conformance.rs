//! Every reference plugin runs the 09.1 conformance kit here — one
//! `ConformanceCase` per plugin. Add yours when you copy template.rs.

mod kit;

use pktflow_core::{Hint, Value};
use pktflow_plugins::template::Template;

use kit::{run_conformance, ConformanceCase, GoodPacket};

#[test]
fn template_conforms() {
    run_conformance(&ConformanceCase {
        plugin: Box::new(Template),
        good: vec![
            // Terminal PKTT frame: src=3 dst=7 type=2 len=8.
            GoodPacket {
                bytes: vec![0x00, 0x03, 0x00, 0x07, 0x00, 0x02, 0x00, 0x08],
                expected_header_len: 8,
                expected_full_fields: vec![
                    ("src", Value::U64(3)),
                    ("dst", Value::U64(7)),
                    ("type", Value::U64(2)),
                    ("len", Value::U64(8)),
                ],
                expected_hint: Hint::Terminal,
            },
            // Self-nesting frame: type=1 wraps another PKTT (16 bytes total).
            GoodPacket {
                bytes: vec![
                    0x00, 0x0A, 0x00, 0x0B, 0x00, 0x01, 0x00, 0x10, // outer
                    0x00, 0x01, 0x00, 0x02, 0x00, 0x02, 0x00, 0x08, // inner
                ],
                expected_header_len: 8,
                expected_full_fields: vec![
                    ("src", Value::U64(10)),
                    ("dst", Value::U64(11)),
                    ("type", Value::U64(1)),
                    ("len", Value::U64(16)),
                ],
                expected_hint: Hint::ByProtocol("template"),
            },
        ],
        outer_ctx: Vec::new(),
    });
}
