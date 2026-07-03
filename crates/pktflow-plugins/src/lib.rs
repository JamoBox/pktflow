//! `pktflow-plugins` — the reference protocol plugin set (task 06).
//!
//! All protocol knowledge lives here: link, network, transport, tunnel, and
//! application plugins, plus the registration list.

use pktflow_core::Engine;

pub mod ethernet;
pub mod template;
pub mod vlan;

/// The one registration list (PRD §8): adding a protocol end-to-end is a
/// new file plus one `.plugin(...)` line here.
pub fn default_engine() -> Engine {
    Engine::builder()
        .plugin(template::Template)
        .plugin(ethernet::Ethernet)
        .plugin(vlan::Vlan)
        .build()
        // Not input-derived: a collision here is a bug in this very list,
        // caught by the registry's build-time validation (03.2).
        .expect("default plugin set must build collision-free")
}
