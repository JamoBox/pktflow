//! `pktflow-plugins` — the reference protocol plugin set (task 06).
//!
//! All protocol knowledge lives here: link, network, transport, tunnel, and
//! application plugins, plus the registration list.

use pktflow_core::Engine;

pub mod arp;
pub mod dhcp;
pub mod dns;
pub mod ethernet;
pub mod gre;
pub mod icmpv4;
pub mod igmp;
pub mod ipv4;
pub mod ipv6;
pub mod ntp;
pub mod tcp;
pub mod template;
pub mod udp;
pub mod vlan;
pub mod vxlan;

/// The one registration list (PRD §8): adding a protocol end-to-end is a
/// new file plus one `.plugin(...)` line here.
pub fn default_engine() -> Engine {
    Engine::builder()
        .plugin(template::Template)
        .plugin(ethernet::Ethernet)
        .plugin(vlan::Vlan)
        .plugin(ipv4::Ipv4)
        .plugin(ipv6::Ipv6)
        .plugin(arp::Arp)
        .plugin(icmpv4::Icmpv4)
        .plugin(igmp::Igmp)
        .plugin(tcp::Tcp)
        .plugin(udp::Udp)
        .plugin(gre::Gre)
        .plugin(vxlan::Vxlan)
        .plugin(dns::Dns)
        .plugin(dhcp::Dhcp)
        .plugin(ntp::Ntp)
        .build()
        // Not input-derived: a collision here is a bug in this very list,
        // caught by the registry's build-time validation (03.2).
        .expect("default plugin set must build collision-free")
}
