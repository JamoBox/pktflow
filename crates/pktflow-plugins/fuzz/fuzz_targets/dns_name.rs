//! 09.1 fuzz target: the DNS name decoder standalone (06.6) — the
//! pointer-compression/backward-jump logic is the trickiest bit of
//! bounds arithmetic in the whole plugin set (it already caught one
//! real underflow during development). First two bytes (LE) pick the
//! start offset — deliberately including out-of-range values — the
//! rest is the message buffer.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pktflow_plugins::dns::decode_name;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let start = u16::from_le_bytes([data[0], data[1]]) as usize;
    let msg = &data[2..];
    let _ = decode_name(msg, start);
});
