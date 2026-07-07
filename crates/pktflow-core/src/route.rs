//! Route identifiers: protocol ids that carry their namespace (03.1).
//!
//! The number 6 means TCP in the IP protocol space and something unrelated
//! elsewhere, so ids are qualified by the id *space* they belong to.
//! Variants name id spaces, not protocols — the engine stays protocol-free.

use core::fmt;

/// A namespaced protocol identifier.
///
/// Well-known spaces are enum variants (fast, `Copy`, exhaustive matching);
/// unforeseen spaces go through [`RouteId::Custom`] so adding a protocol
/// never requires editing this enum.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum RouteId {
    /// pcap DLT space — entry routing (04.2).
    LinkType(u16),
    /// Ethernet/VLAN "what's next" space.
    EtherType(u16),
    /// IPv4 protocol / IPv6 next-header space.
    IpProtocol(u8),
    UdpPort(u16),
    TcpPort(u16),
    /// Escape hatch for plugin-defined spaces (e.g. a custom mux protocol
    /// can mint its own space without touching core).
    Custom {
        space: &'static str,
        id: u64,
    },
}

impl fmt::Display for RouteId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RouteId::LinkType(id) => write!(f, "link_type:{id}"),
            RouteId::EtherType(id) => write!(f, "ethertype:{id:#06x}"),
            RouteId::IpProtocol(id) => write!(f, "ip_protocol:{id}"),
            RouteId::UdpPort(id) => write!(f, "udp_port:{id}"),
            RouteId::TcpPort(id) => write!(f, "tcp_port:{id}"),
            RouteId::Custom { space, id } => write!(f, "custom:{space}:{id}"),
        }
    }
}
