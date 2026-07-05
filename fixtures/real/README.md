# Real capture corpus (09.2)

Curated real (non-synthetic) captures used by the `pktflow-cli` e2e suite for tshark
parity (09.3) and the QUIC "honest-unknowns" no-phantom-streams check. All five files
total under 30 KB.

Each file is either unmodified as pulled from its source, or (for the QUIC one) a
tshark-filtered subset of packets from an unmodified source file — verified below by
SHA-256. None contain personal or sensitive traffic: four are small, long-public
regression fixtures from the tcpdump project's own test suite; the fifth is a
Wireshark-project test capture built specifically for public dissector testing
(its filename literally advertises that it ships its own decryption keys).

## Provenance

| File | Source | SHA-256 | What it is |
|---|---|---|---|
| `dhcp_dora.pcap` | [`tcpdump/tests/dhcp-rfc3004.pcap`](https://github.com/the-tcpdump-group/tcpdump/blob/6800515e86654f5c1e7a0c6b9320e48c9eb0e749/tests/dhcp-rfc3004.pcap) | `a06e659da64050df9896acc0fe9d95fb72fa089607da0d4805165284893f6f9` | Full DHCPv4 DORA exchange (Discover, Offer, Request, Ack) between `0.0.0.0`/broadcast and `192.168.1.1` |
| `vxlan_overlay.pcap` | [`tcpdump/tests/vxlan.pcap`](https://github.com/the-tcpdump-group/tcpdump/blob/6800515e86654f5c1e7a0c6b9320e48c9eb0e749/tests/vxlan.pcap) | `dcb83420e7512dd4085e790d40a040bc5749decb5e551fb807da5689b990fa6` | VXLAN-encapsulated ARP + ICMP echo between two hosts, outer UDP/4789 with asymmetric outer ports per direction |
| `dns_lookup.pcap` | [`tcpdump/tests/dns_udp.pcap`](https://github.com/the-tcpdump-group/tcpdump/blob/6800515e86654f5c1e7a0c6b9320e48c9eb0e749/tests/dns_udp.pcap) | `ece9342a016e16fa49031f17f59883aafd475a64d5dc84a19ec05292e0bb1f0` | A real DNS query/response pair (`www.tcpdump.org`) over UDP/53 |
| `http_transaction.pcap` | [`tcpdump/tests/ipv4_tcp_http_xml.pcap`](https://github.com/the-tcpdump-group/tcpdump/blob/6800515e86654f5c1e7a0c6b9320e48c9eb0e749/tests/ipv4_tcp_http_xml.pcap) | `d45eff30fc39ce0e3df91931f86d28c56acc67d23a26bb050064de023c643ea` | A real HTTP/1.1 200 OK response frame over TCP |
| `quic_unknown.pcap` | UDP-only slice of [`wireshark/test/captures/quic-with-secrets.pcapng`](https://github.com/wireshark/wireshark/blob/e1a4317c88d385311ea9f9e4b29bd596ea3a23b1/test/captures/quic-with-secrets.pcapng), filtered with `tshark -Y udp -w quic_unknown.pcap` | `c455796c31da06bfec92452ce4c0c4d17be3fa507c0c6ab597624566598d192` | Real QUIC handshake + HTTP/3 traffic to `cloudflare-quic.com` over IPv6/UDP — pktflow has no QUIC plugin, so this is the "honest unknowns" fixture (09.3) |

`dhcp_dora.pcap`, `vxlan_overlay.pcap`, `dns_lookup.pcap`, and `http_transaction.pcap` are
from [`the-tcpdump-group/tcpdump`](https://github.com/the-tcpdump-group/tcpdump) (commit
`6800515e`), under the project's BSD-style license (reproduced below). tcpdump ships
these as dissector regression fixtures, so each is small and focused rather than a full
multi-minute session; `dns_lookup.pcap` and `http_transaction.pcap` stand in for the
spec's "one browsing session (eth/ip/tcp/dns mix)" fixture, since tcpdump's corpus
doesn't carry one organic multi-protocol session under a permissive license — DNS and
TCP/HTTP are exercised as two genuine (if brief) real captures instead of one
synthesized/stitched file.

`quic_unknown.pcap` is from [`wireshark/wireshark`](https://github.com/wireshark/wireshark)
(commit `e1a4317c`), under the project's [GPLv2 license](https://github.com/wireshark/wireshark/blob/master/COPYING).
The original `quic-with-secrets.pcapng` also contains an unrelated TCP/TLS/HTTP2 session
to the same host (a "happy eyeballs" style test capture); it's filtered down to just the
QUIC/UDP packets with `tshark -Y udp -w`, which only selects existing frames byte-for-byte
— no packet content is altered.

The original tcpdump QUIC test fixture (`tests/quic_handshake.pcap`) was tried first but
turned out to use BSD loopback (`DLT_NULL`) framing, which pktflow's reference plugin set
doesn't route (v1 only wires up Ethernet/Raw-IP entry points) — it would have stopped at
layer zero instead of exercising the intended "known link layers, unknown application
protocol" case.

All five open in Wireshark/tshark without warnings (verified via `tshark -r <file> -q`
locally before checking these in).

## Licenses

tcpdump (BSD):

```
License: BSD

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.

THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
```

Wireshark (GPLv2): see [`COPYING`](https://github.com/wireshark/wireshark/blob/master/COPYING)
in the Wireshark repository.
