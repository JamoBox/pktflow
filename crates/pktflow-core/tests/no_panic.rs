//! Crate-level robustness test (00.2 acceptance criterion 3): 0-, 1-, and
//! truncated-length buffers driven through `ByteReader` patterns must yield
//! `Err(Truncated)` — never a panic. This is the fuzz seed shape.

use pktflow_core::{ByteReader, Truncated};

/// A representative header-parse pattern: fixed fields, then a
/// length-prefixed body, then the rest. Any failure must be a clean
/// `Truncated` — reaching `Err` at all proves no read panicked.
fn parse_pattern(buf: &[u8]) -> Result<usize, Truncated> {
    let mut r = ByteReader::new(buf);
    let _version = r.u8()?;
    let _flags = r.u16_be()?;
    let _id = r.u32_be()?;
    let _timestamp = r.u64_be()?;
    let _offset = r.i32_be()?;
    let body_len = usize::from(r.u16_be()?);
    let _body = r.take(body_len)?;
    let rest = r.take(r.remaining())?;
    Ok(rest.len())
}

#[test]
fn zero_length_buffer_is_truncated_not_panic() {
    assert_eq!(parse_pattern(&[]), Err(Truncated { needed: 1, have: 0 }));
}

#[test]
fn one_byte_buffer_is_truncated_not_panic() {
    assert_eq!(
        parse_pattern(&[0xFF]),
        Err(Truncated { needed: 2, have: 0 })
    );
}

#[test]
fn every_truncation_point_is_a_clean_error() {
    // A buffer long enough to satisfy the full pattern, with a body length
    // prefix of 4. Truncate it at every possible point: each prefix must
    // parse to Err(Truncated), never panic; only the full buffer succeeds.
    let mut full = vec![
        0x01, // version
        0x00, 0x02, // flags
        0xDE, 0xAD, 0xBE, 0xEF, // id
        0, 0, 0, 0, 0, 0, 0, 42, // timestamp
        0xFF, 0xFF, 0xFF, 0xFE, // offset (-2)
        0x00, 0x04, // body_len = 4
    ];
    full.extend_from_slice(&[9, 8, 7, 6]); // body
    full.extend_from_slice(&[1, 2, 3]); // trailing rest

    // 21 fixed header bytes + 4 declared body bytes must all be present;
    // anything shorter is a truncation. The trailing rest is variable-length,
    // so cuts beyond that point parse cleanly with a shorter rest.
    let required = 25;
    for cut in 0..full.len() {
        let sliced = full.get(..cut).unwrap_or(&[]);
        let parsed = parse_pattern(sliced);
        if cut < required {
            assert!(
                matches!(parsed, Err(Truncated { .. })),
                "prefix of {cut} bytes must be Err(Truncated), got {parsed:?}"
            );
        } else {
            assert_eq!(parsed, Ok(cut - required), "prefix of {cut} bytes");
        }
    }
    assert_eq!(parse_pattern(&full), Ok(3));
}

#[test]
fn declared_length_beyond_buffer_is_truncated() {
    // Hostile input: the length prefix claims far more than is present.
    let mut buf = vec![
        0x01, // version
        0x00, 0x00, // flags
        0, 0, 0, 1, // id
        0, 0, 0, 0, 0, 0, 0, 1, // timestamp
        0, 0, 0, 0, // offset
        0xFF, 0xFF, // body_len = 65535
    ];
    buf.push(0xAA); // one lonely body byte
    assert_eq!(
        parse_pattern(&buf),
        Err(Truncated {
            needed: 65535,
            have: 1
        })
    );
}
