//! `pktflow-plugins` — the reference protocol plugin set (task 06).
//!
//! All protocol knowledge lives here: link, network, transport, tunnel, and
//! application plugins, plus the registration list.

use pktflow_core::Engine;

pub mod arp;
pub mod cdp;
pub mod dhcp;
pub mod dhcpv6;
pub mod dns;
pub mod dot11;
pub mod eapol;
pub mod ethernet;
pub mod gre;
pub mod hsrp;
pub mod icmpv4;
pub mod icmpv6;
pub mod igmp;
pub mod ipv4;
pub mod ipv6;
pub mod lacp;
pub mod llc;
pub mod lldp;
pub mod mld;
pub mod modbus;
pub mod ndp;
pub mod ntp;
pub mod pvst_plus;
pub mod radiotap;
pub mod stp;
pub mod tcp;
pub mod template;
pub mod udp;
pub mod vlan;
pub mod vrrp;
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
        .plugin(cdp::Cdp)
        .plugin(icmpv4::Icmpv4)
        .plugin(icmpv6::Icmpv6)
        .plugin(ndp::Ndp)
        .plugin(mld::Mld)
        .plugin(igmp::Igmp)
        .plugin(vrrp::Vrrp)
        .plugin(hsrp::Hsrp)
        .plugin(tcp::Tcp)
        .plugin(udp::Udp)
        .plugin(gre::Gre)
        .plugin(vxlan::Vxlan)
        .plugin(dns::Dns)
        .plugin(dhcp::Dhcp)
        .plugin(dhcpv6::Dhcpv6)
        .plugin(ntp::Ntp)
        .plugin(lldp::Lldp)
        .plugin(llc::Llc)
        .plugin(lacp::Lacp)
        .plugin(stp::Stp)
        .plugin(pvst_plus::PvstPlus)
        .plugin(eapol::Eapol)
        .plugin(radiotap::Radiotap)
        .plugin(dot11::Dot11)
        .plugin(modbus::Modbus)
        .build()
        // Not input-derived: a collision here is a bug in this very list,
        // caught by the registry's build-time validation (03.2).
        .expect("default plugin set must build collision-free")
}
