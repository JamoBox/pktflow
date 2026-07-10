//! radiotap (11.2): the de facto capture wrapper for 802.11 frames on
//! Linux/macOS monitor-mode interfaces and most `.pcap`/`.pcapng` Wi-Fi
//! captures. *No formal standards body* — the canonical reference is the
//! community specification at <https://www.radiotap.org/> (field
//! defaults, alignment rule, and the present-word extension mechanism all
//! come from that document; see `radiotap.org/fields/defaults.html` and
//! `radiotap.org/#header-format`). Always wraps an 802.11 frame (11.2's
//! `dot11`), so the hint is unconditional direct-by-name dispatch — the
//! same shape as VXLAN wrapping ethernet (06.5).
//!
//! Layout: an 8-byte fixed prelude (version, pad, `it_len`, first
//! present-word), optionally followed by more present words — bit 31 of
//! each word signals another follows — then the field data itself, each
//! field aligned to a multiple of its own size *from the start of this
//! header* (radiotap.org "Alignment" note). Fields appear in strictly
//! increasing bit-index order; this plugin only names bits 0-5 (it needs
//! nothing past `antenna_signal`), so it walks that far and stops —
//! correct regardless of which higher-numbered fields a real capture also
//! carries, since order is fixed by the spec.

use pktflow_core::{
    ByteReader, Depth, FieldMap, FieldName, Hint, LayerPlugin, ParseCtx, ParseError, ParsedLayer,
    ProtocolName, RouteId, StreamIdentity, Value,
};

const IT_VERSION: FieldName = "it_version";
const IT_LEN: FieldName = "it_len";
const IT_PRESENT: FieldName = "it_present";
const ANTENNA_SIGNAL: FieldName = "antenna_signal";
const RATE: FieldName = "rate";
const CHANNEL_FREQ: FieldName = "channel_freq";

/// Bit 31 of a present word: another present word immediately follows
/// (radiotap.org "Extended presence masks").
const PRESENT_EXTENSION_BIT: u32 = 1 << 31;

/// Present-word chain bound: the spec is silent on a hard maximum, but an
/// unbounded chain is an unbounded read loop over hostile input. Eight
/// words (256 possible fields, far past every field radiotap.org defines
/// today) is a generous, still-finite ceiling — matching LLDP/CDP's
/// bounded-walk stance (11.1) applied to this header's own extension
/// mechanism.
const MAX_PRESENT_WORDS: usize = 8;

/// `(align, size)` in bytes for radiotap fields bit 0 through bit 5
/// (radiotap.org/fields/defaults.html) — every field this plugin needs to
/// walk past or read to reach `antenna_signal` (bit 5), the highest bit
/// index it names. Fields with a higher bit index never affect the offset
/// of a lower one (fields are strictly bit-order), so the table stops
/// here by construction, not by omission.
const FIELD_LAYOUT: [(usize, usize); 6] = [
    (8, 8), // 0 TSFT: u64
    (1, 1), // 1 Flags: u8
    (1, 1), // 2 Rate: u8 (500 kbps units)
    (2, 4), // 3 Channel: u16 freq (MHz) + u16 flags
    (1, 2), // 4 FHSS: u8 hop set + u8 hop pattern
    (1, 1), // 5 Antenna signal: i8, dBm
];

const BIT_RATE: u32 = 2;
const BIT_CHANNEL: u32 = 3;
const BIT_ANTENNA_SIGNAL: u32 = 5;

pub struct Radiotap;

impl LayerPlugin for Radiotap {
    fn name(&self) -> ProtocolName {
        "radiotap"
    }

    fn parse(&self, bytes: &[u8], ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
        let mut r = ByteReader::new(bytes);
        let it_version = r.u8()?;
        let _it_pad = r.u8()?;
        let it_len = r.u16_le()?;
        let header_len = usize::from(it_len);
        if header_len > bytes.len() {
            return Err(ParseError::Malformed(
                "radiotap: it_len exceeds captured bytes",
            ));
        }

        // Present-word chain: word 0 always exists; further words only if
        // the previous word's bit 31 is set, bounded (see MAX_PRESENT_WORDS).
        let it_present = r.u32_le()?;
        let mut word = it_present;
        let mut words_read = 1;
        while word & PRESENT_EXTENSION_BIT != 0 {
            if words_read >= MAX_PRESENT_WORDS {
                return Err(ParseError::Malformed(
                    "radiotap: present-word chain exceeds the 8-word bound",
                ));
            }
            word = r.u32_le()?;
            words_read += 1;
        }

        // Field data, walked in fixed bit order (radiotap.org), each
        // aligned to its own size measured from the start of this header
        // (offset 0 = it_version). Only bits 0-5 are ever visited — no
        // field this plugin doesn't name can shift where an earlier one
        // (lower bit index) landed.
        let mut rate = None;
        let mut channel_freq = None;
        let mut antenna_signal = None;
        for (bit_idx, &(align, size)) in FIELD_LAYOUT.iter().enumerate() {
            let bit = bit_idx as u32;
            if it_present & (1 << bit) == 0 {
                continue;
            }
            let offset = bytes.len() - r.remaining();
            let pad = align - offset % align;
            let pad = if pad == align { 0 } else { pad };
            if pad > 0 {
                r.take(pad)?;
            }
            let value = r.take(size)?;
            match bit {
                BIT_RATE => rate = Some(u64::from(value[0])),
                BIT_CHANNEL => {
                    channel_freq = Some(u64::from(u16::from_le_bytes([value[0], value[1]])));
                }
                BIT_ANTENNA_SIGNAL => antenna_signal = Some(i64::from(value[0] as i8)),
                _ => {}
            }
        }

        // The walk above only ever reads as far as bit 5's data; it must
        // never claim to have read past the header the capture declared.
        let consumed = bytes.len() - r.remaining();
        if consumed > header_len {
            return Err(ParseError::Malformed(
                "radiotap: present fields overrun it_len",
            ));
        }

        let mut fields = FieldMap::new();
        if ctx.depth() >= Depth::Structural {
            fields.insert(IT_VERSION, Value::U64(u64::from(it_version)));
            fields.insert(IT_LEN, Value::U64(u64::from(it_len)));
            fields.insert(IT_PRESENT, Value::U64(u64::from(it_present)));
        }
        if ctx.depth() >= Depth::Full {
            if let Some(v) = rate {
                fields.insert(RATE, Value::U64(v));
            }
            if let Some(v) = channel_freq {
                fields.insert(CHANNEL_FREQ, Value::U64(v));
            }
            if let Some(v) = antenna_signal {
                fields.insert(ANTENNA_SIGNAL, Value::I64(v));
            }
        }

        Ok(ParsedLayer {
            header_len,
            fields,
            hint: Hint::ByProtocol("dot11"),
        })
    }

    fn claims(&self) -> &'static [RouteId] {
        &[RouteId::LinkType(127 /* DLT_IEEE802_11_RADIOTAP */)]
    }

    // No probe: explicit entry via LinkType only (radiotap.org has no
    // magic number to sniff for; `it_version` is always 0, far too weak a
    // signal to probe on honestly).

    fn stream_identity(&self) -> Option<&StreamIdentity> {
        // Per-packet radio metadata, not conversation-bearing — no
        // identity of its own (11.2's documented v1 stance, same shape as
        // ARP's rollup gap, 06.3).
        None
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use pktflow_core::{LinkType, PacketMeta};

    use super::*;

    fn meta(len: usize) -> PacketMeta {
        PacketMeta {
            timestamp: SystemTime::UNIX_EPOCH,
            caplen: len,
            origlen: len,
            link_type: LinkType(127),
        }
    }

    fn ctx(depth: Depth, meta: &PacketMeta) -> ParseCtx<'_> {
        ParseCtx::new(&[], depth, meta)
    }

    fn parse(bytes: &[u8], depth: Depth) -> Result<ParsedLayer, ParseError> {
        let m = meta(bytes.len());
        Radiotap.parse(bytes, &ctx(depth, &m))
    }

    /// Minimal header: no fields present at all — `it_len` covers just
    /// the 8-byte prelude, `it_present` is zero.
    fn minimal_header() -> Vec<u8> {
        vec![
            0x00, 0x00, // it_version=0, it_pad
            0x08, 0x00, // it_len=8 (LE)
            0x00, 0x00, 0x00, 0x00, // it_present: nothing set
        ]
    }

    /// Rate + Antenna Signal present (bits 2 and 5): Rate is 1-byte
    /// aligned right after the header, Antenna Signal follows it
    /// immediately (also 1-byte aligned) — both land contiguously.
    /// Rate=0x02 (1 Mbps in 500 kbps units), Antenna Signal=-71 dBm.
    fn rate_and_signal_header() -> Vec<u8> {
        let present = (1u32 << BIT_RATE) | (1u32 << BIT_ANTENNA_SIGNAL);
        let mut b = vec![0x00, 0x00, 0x0A, 0x00];
        b.extend_from_slice(&present.to_le_bytes());
        b.push(0x02); // rate
        b.push((-71i8) as u8); // antenna_signal
        assert_eq!(b.len(), 10);
        b
    }

    /// Channel present alone (bit 3): 2-byte aligned, 4 bytes (freq +
    /// flags). freq=2437 MHz (channel 6), flags=0x00A0 (2.4GHz, dynamic CCK-OFDM).
    fn channel_header() -> Vec<u8> {
        let present = 1u32 << BIT_CHANNEL;
        let mut b = vec![0x00, 0x00, 0x0C, 0x00];
        b.extend_from_slice(&present.to_le_bytes());
        b.extend_from_slice(&2437u16.to_le_bytes());
        b.extend_from_slice(&0x00A0u16.to_le_bytes());
        assert_eq!(b.len(), 12);
        b
    }

    /// TSFT (bit 0, 8-byte aligned/sized) forces Rate (bit 2, right after)
    /// to start at offset 16, proving the alignment walk — not a fixed
    /// offset table — locates it.
    fn tsft_then_rate_header() -> Vec<u8> {
        let present = (1u32 << 0) | (1u32 << BIT_RATE);
        let mut b = vec![0x00, 0x00, 0x11, 0x00];
        b.extend_from_slice(&present.to_le_bytes());
        b.extend_from_slice(&0u64.to_le_bytes()); // TSFT
        b.push(0x0C); // rate = 6 Mbps
        assert_eq!(b.len(), 17);
        b
    }

    #[test]
    fn parses_the_minimal_header() {
        let bytes = minimal_header();
        let parsed = parse(&bytes, Depth::Full).expect("valid header");
        assert_eq!(parsed.header_len, 8);
        assert_eq!(parsed.fields.get(IT_VERSION), Some(&Value::U64(0)));
        assert_eq!(parsed.fields.get(IT_LEN), Some(&Value::U64(8)));
        assert_eq!(parsed.fields.get(IT_PRESENT), Some(&Value::U64(0)));
        assert_eq!(parsed.fields.get(RATE), None);
        assert_eq!(parsed.hint, Hint::ByProtocol("dot11"));
    }

    #[test]
    fn parses_rate_and_antenna_signal() {
        let bytes = rate_and_signal_header();
        let parsed = parse(&bytes, Depth::Full).expect("valid header");
        assert_eq!(parsed.header_len, 10);
        assert_eq!(parsed.fields.get(RATE), Some(&Value::U64(2)));
        assert_eq!(parsed.fields.get(ANTENNA_SIGNAL), Some(&Value::I64(-71)));
    }

    #[test]
    fn parses_channel_freq() {
        let bytes = channel_header();
        let parsed = parse(&bytes, Depth::Full).expect("valid header");
        assert_eq!(parsed.fields.get(CHANNEL_FREQ), Some(&Value::U64(2437)));
    }

    #[test]
    fn alignment_walk_locates_a_field_after_a_wider_one() {
        let bytes = tsft_then_rate_header();
        let parsed = parse(&bytes, Depth::Full).expect("valid header");
        assert_eq!(parsed.fields.get(RATE), Some(&Value::U64(0x0C)));
    }

    #[test]
    fn structural_depth_omits_full_only_fields() {
        let bytes = rate_and_signal_header();
        let parsed = parse(&bytes, Depth::Structural).expect("valid header");
        assert_eq!(parsed.fields.get(IT_PRESENT), Some(&Value::U64(0x24)));
        assert_eq!(parsed.fields.get(RATE), None);
        assert_eq!(parsed.fields.get(ANTENNA_SIGNAL), None);
    }

    #[test]
    fn present_word_chain_past_the_bound_declines() {
        // Every word sets bit 31 (continues forever); a 9th word would be
        // required to terminate the chain but is never offered.
        let mut b = vec![0x00, 0x00, 0x00, 0x00];
        let it_len = 4 + 4 * 9u16;
        b[2..4].copy_from_slice(&it_len.to_le_bytes());
        for _ in 0..9 {
            b.extend_from_slice(&PRESENT_EXTENSION_BIT.to_le_bytes());
        }
        assert!(parse(&b, Depth::Full).is_err());
    }

    #[test]
    fn present_word_chain_terminating_at_the_bound_is_accepted() {
        // Exactly 8 words, the 8th clears bit 31 — right at the ceiling.
        let mut b = vec![0x00, 0x00, 0x00, 0x00];
        let it_len = 4 + 4 * 8u16;
        b[2..4].copy_from_slice(&it_len.to_le_bytes());
        for _ in 0..7 {
            b.extend_from_slice(&PRESENT_EXTENSION_BIT.to_le_bytes());
        }
        b.extend_from_slice(&0u32.to_le_bytes());
        let parsed = parse(&b, Depth::Full).expect("exactly 8 words is within bound");
        assert_eq!(parsed.header_len, usize::from(it_len));
    }

    #[test]
    fn it_len_beyond_the_buffer_declines() {
        let mut bytes = minimal_header();
        bytes[2..4].copy_from_slice(&100u16.to_le_bytes());
        assert!(parse(&bytes, Depth::Full).is_err());
    }

    #[test]
    fn a_present_field_overrunning_a_short_it_len_declines() {
        // Claims Antenna Signal present but it_len only covers the
        // present word itself — the field byte would fall outside the
        // header the capture declared.
        let mut b = vec![0x00, 0x00, 0x08, 0x00];
        b.extend_from_slice(&(1u32 << BIT_ANTENNA_SIGNAL).to_le_bytes());
        b.push(0xAA); // the field byte exists in the buffer...
        assert_eq!(b.len(), 9);
        // ...but it_len (8) says the header ends before it.
        assert!(parse(&b, Depth::Full).is_err());
    }

    #[test]
    fn truncated_headers_decline() {
        for bytes in [
            minimal_header(),
            rate_and_signal_header(),
            channel_header(),
            tsft_then_rate_header(),
        ] {
            for n in 0..bytes.len() {
                assert!(
                    parse(&bytes[..n], Depth::Full).is_err(),
                    "prefix of {n}/{} bytes must decline",
                    bytes.len()
                );
            }
        }
    }

    #[test]
    fn always_hints_dot11_regardless_of_content() {
        for bytes in [minimal_header(), rate_and_signal_header()] {
            assert_eq!(
                parse(&bytes, Depth::Full).expect("valid").hint,
                Hint::ByProtocol("dot11")
            );
        }
    }
}
