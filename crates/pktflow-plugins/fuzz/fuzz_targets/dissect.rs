//! 09.1 fuzz target: raw bytes → `Engine::dissect` with the full default
//! engine (Ethernet entry). No-panic is the only property under test —
//! `ParseError`/`StopReason` are legitimate outcomes on garbage input,
//! a crash never is.
#![no_main]

use std::sync::OnceLock;
use std::time::SystemTime;

use libfuzzer_sys::fuzz_target;
use pktflow_core::{Engine, LinkType, PacketMeta, ParseOpts};

fn engine() -> &'static Engine {
    static ENGINE: OnceLock<Engine> = OnceLock::new();
    ENGINE.get_or_init(pktflow_plugins::default_engine)
}

fuzz_target!(|data: &[u8]| {
    let meta = PacketMeta {
        timestamp: SystemTime::UNIX_EPOCH,
        caplen: data.len(),
        origlen: data.len(),
        link_type: LinkType::ETHERNET,
    };
    let _ = engine().dissect(data, meta, ParseOpts::default());
});
