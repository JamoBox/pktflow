//! Service & name discovery (11.12): SSDP end-to-end through the full
//! ethernet/ipv4/udp stack, its app-stream pattern (one `ssdp` child per
//! UDP stream, `nts` accumulated + `location` sampled), and malformed
//! input on the claimed port declining cleanly (03.4 row 3). Mirrors
//! application.rs's syslog/SNMP test shape for the same app-stream
//! family.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use pktflow_core::{LinkType, PacketMeta, ParseOpts, StopReason, Value};
use pktflow_flows::{Aggregator, AggregatorConfig, Rollup};
use pktflow_plugins::default_engine;
use pktflow_plugins::ipv4::internet_checksum;
use proptest::prelude::*;

fn meta(len: usize, ms: u64) -> PacketMeta {
    PacketMeta {
        timestamp: SystemTime::UNIX_EPOCH + Duration::from_millis(ms),
        caplen: len,
        origlen: len,
        link_type: LinkType::ETHERNET,
    }
}

fn eth() -> Vec<u8> {
    let mut f = vec![0xAA; 6];
    f.extend_from_slice(&[0xBB; 6]);
    f.extend_from_slice(&0x0800u16.to_be_bytes());
    f
}

fn ipv4_udp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut h = vec![
        0x45, 0x00, 0x00, 0x3C, 0x1C, 0x46, 0x40, 0x00, 0x40, 17, 0, 0,
    ];
    h.extend_from_slice(&src);
    h.extend_from_slice(&dst);
    let ck = internet_checksum(&h);
    h[10..12].copy_from_slice(&ck.to_be_bytes());
    h.extend_from_slice(&sport.to_be_bytes());
    h.extend_from_slice(&dport.to_be_bytes());
    h.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    h.extend_from_slice(&[0, 0]);
    h.extend_from_slice(payload);
    h
}

/// SSDP is always to/from UDP port 1900 (multicast search/advertisement,
/// or a unicast search response back to the searcher's ephemeral port —
/// modeled here as `dport == 1900`, the searcher-as-source direction).
fn ssdp_frame(src: [u8; 4], dst: [u8; 4], sport: u16, msg: &[u8]) -> Vec<u8> {
    let mut f = eth();
    f.extend_from_slice(&ipv4_udp(src, dst, sport, 1900, msg));
    f
}

const MSEARCH: &[u8] = b"M-SEARCH * HTTP/1.1\r\n\
    HOST: 239.255.255.250:1900\r\n\
    MAN: \"ssdp:discover\"\r\n\
    MX: 2\r\n\
    ST: ssdp:all\r\n\
    \r\n";

const NOTIFY_ALIVE: &[u8] = b"NOTIFY * HTTP/1.1\r\n\
    HOST: 239.255.255.250:1900\r\n\
    CACHE-CONTROL: max-age=1800\r\n\
    LOCATION: http://192.168.1.50:1400/xml/device_description.xml\r\n\
    NT: urn:schemas-upnp-org:device:ZonePlayer:1\r\n\
    NTS: ssdp:alive\r\n\
    SERVER: Linux/3.14 UPnP/1.0 Sonos/56.0\r\n\
    USN: uuid:RINCON_000E58B5A8E401400::urn:schemas-upnp-org:device:ZonePlayer:1\r\n\
    \r\n";

const NOTIFY_BYEBYE: &[u8] = b"NOTIFY * HTTP/1.1\r\n\
    HOST: 239.255.255.250:1900\r\n\
    NT: urn:schemas-upnp-org:device:ZonePlayer:1\r\n\
    NTS: ssdp:byebye\r\n\
    USN: uuid:RINCON_000E58B5A8E401400::urn:schemas-upnp-org:device:ZonePlayer:1\r\n\
    \r\n";

const SEARCH_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\n\
    CACHE-CONTROL: max-age=1800\r\n\
    EXT:\r\n\
    LOCATION: http://192.168.1.50:1400/xml/device_description.xml\r\n\
    SERVER: Linux/3.14 UPnP/1.0 Sonos/56.0\r\n\
    ST: urn:schemas-upnp-org:device:ZonePlayer:1\r\n\
    USN: uuid:RINCON_000E58B5A8E401400::urn:schemas-upnp-org:device:ZonePlayer:1\r\n\
    \r\n";

/// Acceptance criteria (11.12): M-SEARCH, NOTIFY `ssdp:alive`/`ssdp:byebye`,
/// and a search response all dissect through the full stack, with
/// `location` extracted exactly where present.
type ExpectedFields<'a> = &'a [(&'a str, Value)];

#[test]
fn ssdp_all_message_forms_parse_through_full_stack() {
    let engine = Arc::new(default_engine());

    let cases: [(&[u8], ExpectedFields); 4] = [
        (
            MSEARCH,
            &[
                ("method", Value::from("M-SEARCH")),
                ("st", Value::from("ssdp:all")),
            ],
        ),
        (
            NOTIFY_ALIVE,
            &[
                ("method", Value::from("NOTIFY")),
                ("nts", Value::from("ssdp:alive")),
                (
                    "location",
                    Value::from("http://192.168.1.50:1400/xml/device_description.xml"),
                ),
            ],
        ),
        (
            NOTIFY_BYEBYE,
            &[
                ("method", Value::from("NOTIFY")),
                ("nts", Value::from("ssdp:byebye")),
            ],
        ),
        (
            SEARCH_RESPONSE,
            &[
                ("status_code", Value::U64(200)),
                (
                    "location",
                    Value::from("http://192.168.1.50:1400/xml/device_description.xml"),
                ),
            ],
        ),
    ];

    for (msg, expected) in cases {
        let frame = ssdp_frame([10, 0, 0, 5], [239, 255, 255, 250], 54321, msg);
        let packet = engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default());

        let protocols: Vec<_> = packet.layers.iter().map(|l| l.protocol).collect();
        assert_eq!(protocols, ["ethernet", "ipv4", "udp", "ssdp"]);
        assert_eq!(packet.stop, StopReason::Complete);

        let layer = &packet.layers[3];
        assert_eq!(layer.fields.get("app"), Some(&Value::from("ssdp")));
        for (name, value) in expected {
            assert_eq!(
                layer.fields.get(name),
                Some(value),
                "field {name} in {msg:?}"
            );
        }
    }
}

/// `NOTIFY ssdp:byebye` carries no `LOCATION` — the device has left, so
/// there is nothing to point at (UDA §1.2.3).
#[test]
fn ssdp_byebye_has_no_location() {
    let engine = Arc::new(default_engine());
    let frame = ssdp_frame([10, 0, 0, 5], [239, 255, 255, 250], 54321, NOTIFY_BYEBYE);
    let packet = engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default());
    assert_eq!(packet.layers[3].fields.get("location"), None);
}

/// Malformed SSDP on the claimed port declines cleanly (03.4 row 3):
/// no CRLFCRLF terminator at all, an unrecognized start line, and a
/// truncated NOTIFY missing its terminating blank line.
#[test]
fn ssdp_malformed_input_declines_safely() {
    let engine = Arc::new(default_engine());
    let bad_inputs: [&[u8]; 3] = [
        b"M-SEARCH * HTTP/1.1\r\nST: ssdp:all",
        b"BREW * HTTP/1.1\r\n\r\n",
        b"NOTIFY * HTTP/1.1\r\nNTS: ssdp:alive\r\n",
    ];
    for msg in bad_inputs {
        let frame = ssdp_frame([10, 0, 0, 5], [239, 255, 255, 250], 54321, msg);
        let packet = engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default());
        let protocols: Vec<_> = packet.layers.iter().map(|l| l.protocol).collect();
        assert_eq!(protocols, ["ethernet", "ipv4", "udp"]);
        assert_eq!(packet.stop, StopReason::PluginError);
    }
}

/// App-stream pattern (06.6): one `ssdp` child per UDP stream, `nts`
/// accumulated across an alive/byebye/alive sequence (repeat: no new
/// distinct value) and `location` sampled first/last.
#[test]
fn app_stream_pattern_one_ssdp_child_with_rollups() {
    let engine = Arc::new(default_engine());
    let mut agg = Aggregator::new(&engine, AggregatorConfig::default());

    let other_location: &[u8] = b"NOTIFY * HTTP/1.1\r\n\
        HOST: 239.255.255.250:1900\r\n\
        LOCATION: http://192.168.1.50:1400/xml/device_description2.xml\r\n\
        NT: urn:schemas-upnp-org:device:ZonePlayer:1\r\n\
        NTS: ssdp:alive\r\n\
        USN: uuid:RINCON_000E58B5A8E401401::urn:schemas-upnp-org:device:ZonePlayer:1\r\n\
        \r\n";

    let messages: [&[u8]; 3] = [NOTIFY_ALIVE, NOTIFY_BYEBYE, other_location];
    for (i, msg) in messages.iter().enumerate() {
        let frame = ssdp_frame([10, 0, 0, 5], [239, 255, 255, 250], 54321, msg);
        agg.ingest(&engine.dissect(&frame, meta(frame.len(), i as u64), ParseOpts::default()));
    }

    let udp_stream = agg.at_layer("udp")[0];
    let ssdp_streams = agg.at_layer("ssdp");
    assert_eq!(ssdp_streams.len(), 1, "one app-stream per transport stream");
    assert_eq!(ssdp_streams[0].parent, Some(udp_stream.id));

    match ssdp_streams[0].rollups.get("nts") {
        Some(Rollup::Accumulate { values, count, .. }) => {
            assert_eq!(*count, 3);
            assert_eq!(
                values.as_slice(),
                [Value::from("ssdp:alive"), Value::from("ssdp:byebye")]
            );
        }
        other => panic!("wrong rollup: {other:?}"),
    }

    match ssdp_streams[0].rollups.get("location") {
        Some(Rollup::Sample { first, last }) => {
            assert_eq!(
                first,
                &Some(Value::from(
                    "http://192.168.1.50:1400/xml/device_description.xml"
                ))
            );
            assert_eq!(
                last,
                &Some(Value::from(
                    "http://192.168.1.50:1400/xml/device_description2.xml"
                ))
            );
        }
        other => panic!("wrong rollup: {other:?}"),
    }
}

proptest! {
    /// The dissector must decline or succeed on arbitrary bytes behind a
    /// claimed port — never panic (parser-bomb discipline, same standard
    /// as the DNS/syslog/SNMP fuzzes in application.rs).
    #[test]
    fn ssdp_parse_never_panics(payload in proptest::collection::vec(any::<u8>(), 0..300)) {
        let engine = Arc::new(default_engine());
        let frame = ssdp_frame([10, 0, 0, 5], [239, 255, 255, 250], 54321, &payload);
        let _ = engine.dissect(&frame, meta(frame.len(), 0), ParseOpts::default());
    }
}
