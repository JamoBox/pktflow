//! `pktflow-plugins` — the reference protocol plugin set (task 06).
//!
//! All protocol knowledge lives here: link, network, transport, tunnel, and
//! application plugins, plus the registration list.

use pktflow_core::Engine;

pub mod ah;
pub mod arp;
pub mod bacnet_ip;
pub mod bgp;
pub mod cdp;
pub mod dhcp;
pub mod dhcpv6;
pub mod dnp3;
pub mod dns;
pub mod dot11;
pub mod eapol;
pub mod enip;
pub mod esp;
pub mod ethernet;
pub mod geneve;
pub mod gre;
pub mod hsrp;
pub mod icmpv4;
pub mod icmpv6;
pub mod igmp;
pub mod ipfix;
pub mod ipv4;
pub mod ipv6;
pub mod l2tpv3;
pub mod lacp;
pub mod llc;
pub mod lldp;
pub mod mdns;
pub mod mld;
pub mod modbus;
pub mod ndp;
pub mod netflow9;
pub mod ntp;
pub mod ospf;
pub mod ppp;
pub mod pppoe;
pub mod pvst_plus;
pub mod quic;
pub mod radiotap;
pub mod sctp;
pub mod snmp;
pub mod stp;
pub mod syslog;
pub mod tcp;
pub mod template;
pub mod udp;
pub mod vlan;
pub mod vrrp;
pub mod vxlan;
pub mod wireguard;

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
        .plugin(ospf::Ospf)
        .plugin(tcp::Tcp)
        .plugin(sctp::Sctp)
        .plugin(quic::Quic)
        .plugin(udp::Udp)
        .plugin(bgp::Bgp)
        .plugin(gre::Gre)
        .plugin(vxlan::Vxlan)
        .plugin(geneve::Geneve)
        .plugin(esp::Esp)
        .plugin(ah::Ah)
        .plugin(wireguard::Wireguard)
        .plugin(l2tpv3::L2tpv3)
        .plugin(pppoe::Pppoe)
        .plugin(ppp::Ppp)
        .plugin(dns::Dns)
        .plugin(mdns::Mdns)
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
        .plugin(dnp3::Dnp3)
        .plugin(enip::Enip)
        .plugin(bacnet_ip::BacnetIp)
        .plugin(syslog::Syslog)
        .plugin(snmp::Snmp)
        .plugin(netflow9::Netflow9)
        .plugin(ipfix::Ipfix)
        .build()
        // Not input-derived: a collision here is a bug in this very list,
        // caught by the registry's build-time validation (03.2).
        .expect("default plugin set must build collision-free")
}
