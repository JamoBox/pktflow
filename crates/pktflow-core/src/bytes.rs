//! Checked byte access: the only sanctioned way plugins read headers (00.2).
//!
//! Malformed, truncated, or hostile input must never panic the engine
//! (PRD §7): every read is bounds-checked and reports [`Truncated`] instead
//! of slicing out of range.

/// A read ran past the end of the input.
///
/// Routine data, not a program error: cheap, `Copy`, no allocation.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[error("truncated input: needed {needed} bytes, have {have}")]
pub struct Truncated {
    /// Bytes the failed read required.
    pub needed: usize,
    /// Bytes that were actually available.
    pub have: usize,
}

/// Checked cursor over an input slice.
///
/// All header reads go through this type; direct indexing or slicing on
/// input-derived values is forbidden in non-test code (no-panic policy).
pub struct ByteReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    /// Wraps `buf` with the cursor at offset 0.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Reads one byte.
    pub fn u8(&mut self) -> Result<u8, Truncated> {
        let [b] = self.array::<1>()?;
        Ok(b)
    }

    /// Reads a big-endian `u16`.
    pub fn u16_be(&mut self) -> Result<u16, Truncated> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    /// Reads a big-endian `u32`.
    pub fn u32_be(&mut self) -> Result<u32, Truncated> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    /// Reads a big-endian `u64`.
    pub fn u64_be(&mut self) -> Result<u64, Truncated> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    /// Reads a big-endian `i32`.
    pub fn i32_be(&mut self) -> Result<i32, Truncated> {
        Ok(i32::from_be_bytes(self.array()?))
    }

    /// Takes the next `n` bytes as a subslice of the input.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], Truncated> {
        let truncated = Truncated {
            needed: n,
            have: self.remaining(),
        };
        let end = self.pos.checked_add(n).ok_or(truncated)?;
        let slice = self.buf.get(self.pos..end).ok_or(truncated)?;
        self.pos = end;
        Ok(slice)
    }

    /// Bytes left between the cursor and the end of the input.
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], Truncated> {
        let have = self.remaining();
        let slice = self.take(N)?;
        <[u8; N]>::try_from(slice).map_err(|_| Truncated { needed: N, have })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u8_boundaries() {
        assert_eq!(
            ByteReader::new(&[]).u8(),
            Err(Truncated { needed: 1, have: 0 })
        );
        let mut exact = ByteReader::new(&[0xAB]);
        assert_eq!(exact.u8(), Ok(0xAB));
        assert_eq!(exact.remaining(), 0);
        assert_eq!(exact.u8(), Err(Truncated { needed: 1, have: 0 }));
    }

    #[test]
    fn u16_be_boundaries() {
        assert_eq!(
            ByteReader::new(&[]).u16_be(),
            Err(Truncated { needed: 2, have: 0 })
        );
        // Off-by-one: one byte short.
        assert_eq!(
            ByteReader::new(&[0x01]).u16_be(),
            Err(Truncated { needed: 2, have: 1 })
        );
        let mut exact = ByteReader::new(&[0x01, 0x02]);
        assert_eq!(exact.u16_be(), Ok(0x0102));
        assert_eq!(exact.remaining(), 0);
    }

    #[test]
    fn u32_be_boundaries() {
        assert_eq!(
            ByteReader::new(&[]).u32_be(),
            Err(Truncated { needed: 4, have: 0 })
        );
        assert_eq!(
            ByteReader::new(&[1, 2, 3]).u32_be(),
            Err(Truncated { needed: 4, have: 3 })
        );
        let mut exact = ByteReader::new(&[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(exact.u32_be(), Ok(0x0102_0304));
        assert_eq!(exact.remaining(), 0);
    }

    #[test]
    fn u64_be_boundaries() {
        assert_eq!(
            ByteReader::new(&[]).u64_be(),
            Err(Truncated { needed: 8, have: 0 })
        );
        assert_eq!(
            ByteReader::new(&[1, 2, 3, 4, 5, 6, 7]).u64_be(),
            Err(Truncated { needed: 8, have: 7 })
        );
        let mut exact = ByteReader::new(&[0, 0, 0, 0, 0, 0, 0, 0x2A]);
        assert_eq!(exact.u64_be(), Ok(0x2A));
        assert_eq!(exact.remaining(), 0);
    }

    #[test]
    fn i32_be_boundaries() {
        assert_eq!(
            ByteReader::new(&[]).i32_be(),
            Err(Truncated { needed: 4, have: 0 })
        );
        assert_eq!(
            ByteReader::new(&[0xFF, 0xFF, 0xFF]).i32_be(),
            Err(Truncated { needed: 4, have: 3 })
        );
        let mut exact = ByteReader::new(&[0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(exact.i32_be(), Ok(-1));
        assert_eq!(exact.remaining(), 0);
    }

    #[test]
    fn take_boundaries() {
        // Empty input: take(0) succeeds, take(1) reports Truncated.
        let mut empty = ByteReader::new(&[]);
        assert_eq!(empty.take(0), Ok(&[][..]));
        assert_eq!(empty.take(1), Err(Truncated { needed: 1, have: 0 }));

        // Exact length drains the input.
        let mut exact = ByteReader::new(&[1, 2, 3]);
        assert_eq!(exact.take(3), Ok(&[1, 2, 3][..]));
        assert_eq!(exact.remaining(), 0);

        // Off-by-one: one more than available.
        let mut short = ByteReader::new(&[1, 2, 3]);
        assert_eq!(short.take(4), Err(Truncated { needed: 4, have: 3 }));
        // A failed take must not advance the cursor.
        assert_eq!(short.remaining(), 3);

        // Absurd length (overflow guard) still reports Truncated, no panic.
        let mut huge = ByteReader::new(&[1]);
        huge.pos = 1;
        assert_eq!(
            huge.take(usize::MAX),
            Err(Truncated {
                needed: usize::MAX,
                have: 0
            })
        );
    }

    #[test]
    fn remaining_tracks_cursor() {
        assert_eq!(ByteReader::new(&[]).remaining(), 0);
        let mut r = ByteReader::new(&[1, 2, 3, 4]);
        assert_eq!(r.remaining(), 4);
        assert_eq!(r.u16_be(), Ok(0x0102));
        assert_eq!(r.remaining(), 2);
        assert_eq!(r.take(2), Ok(&[3, 4][..]));
        assert_eq!(r.remaining(), 0);
    }
}
