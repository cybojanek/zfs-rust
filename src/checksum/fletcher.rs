use core::mem;

/** Computes fletcher2 checksum where `data` is big endian.
 *
 * - Result is big endian.
 * - Consumes `data` 16 bytes at a time.
 * - Remainder bytes are not included in checksum.
 */
pub fn fletcher_2_be(data: &[u8]) -> [u64; 4] {
    let mut checksum: [u64; 4] = [0; 4];

    // Iterate two u64 at a time.
    for chunk in data.chunks_exact(2 * mem::size_of::<u64>()) {
        let (x, y) = (
            &chunk[0..mem::size_of::<u64>()],
            &chunk[mem::size_of::<u64>()..2 * mem::size_of::<u64>()],
        );

        // Update running checksum.
        let x = u64::from_be_bytes(x.try_into().unwrap());
        let y = u64::from_be_bytes(y.try_into().unwrap());

        checksum[0] = checksum[0].wrapping_add(x);
        checksum[1] = checksum[1].wrapping_add(y);
        checksum[2] = checksum[2].wrapping_add(checksum[0]);
        checksum[3] = checksum[3].wrapping_add(checksum[1]);
    }

    checksum
}

/** Computes fletcher2 checksum where `data` is little endian.
 *
 * - Result is in native encoding.
 * - Consumes `data` 16 bytes at a time.
 * - Remainder bytes are not included in checksum.
 */
pub fn fletcher_2_le(data: &[u8]) -> [u64; 4] {
    let mut checksum: [u64; 4] = [0; 4];

    // Iterate two u64 at a time.
    for chunk in data.chunks_exact(2 * mem::size_of::<u64>()) {
        let (x, y) = (
            &chunk[0..mem::size_of::<u64>()],
            &chunk[mem::size_of::<u64>()..2 * mem::size_of::<u64>()],
        );

        // Update running checksum.
        let x = u64::from_le_bytes(x.try_into().unwrap());
        let y = u64::from_le_bytes(y.try_into().unwrap());

        checksum[0] = checksum[0].wrapping_add(x);
        checksum[1] = checksum[1].wrapping_add(y);
        checksum[2] = checksum[2].wrapping_add(checksum[0]);
        checksum[3] = checksum[3].wrapping_add(checksum[1]);
    }

    checksum
}

/** Computes fletcher4 checksum where `data` is big endian.
 *
 * - Result is in native encoding.
 * - Consumes `data` 4 bytes at a time.
 * - Remainder bytes are not included in checksum.
 */
pub fn fletcher_4_be(data: &[u8]) -> [u64; 4] {
    let mut checksum: [u64; 4] = [0; 4];

    // Iterate one u32 at a time.
    for chunk in data.chunks_exact(mem::size_of::<u32>()) {
        // Update running checksum.
        let value = u64::from(u32::from_be_bytes(chunk.try_into().unwrap()));

        checksum[0] = checksum[0].wrapping_add(value);
        checksum[1] = checksum[0].wrapping_add(checksum[1]);
        checksum[2] = checksum[1].wrapping_add(checksum[2]);
        checksum[3] = checksum[2].wrapping_add(checksum[3]);
    }

    checksum
}

/** Computes fletcher4 checksum where `data` is little endian.
 *
 * - Result is in native encoding.
 * - Consumes `data` 4 bytes at a time.
 * - Remainder bytes are not included in checksum.
 */
pub fn fletcher_4_le(data: &[u8]) -> [u64; 4] {
    let mut checksum: [u64; 4] = [0; 4];

    // Iterate one u32 at a time.
    for chunk in data.chunks_exact(mem::size_of::<u32>()) {
        // Update running checksum.
        let value = u64::from(u32::from_le_bytes(chunk.try_into().unwrap()));

        checksum[0] = checksum[0].wrapping_add(value);
        checksum[1] = checksum[0].wrapping_add(checksum[1]);
        checksum[2] = checksum[1].wrapping_add(checksum[2]);
        checksum[3] = checksum[2].wrapping_add(checksum[3]);
    }

    checksum
}
