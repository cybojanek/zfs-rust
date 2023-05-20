use sha2::{Digest, Sha256};

/** Convert a SHA-256 digest to ZFS u64 format.
 */
fn digest_to_zfs_u64(digest: &[u8; 32]) -> [u64; 4] {
    // A SHA-256 [u8; 32] digest is encoded using big endian encoding, so decode
    // the bytes as such.
    let h = [
        u32::from_be_bytes(digest[0..4].try_into().unwrap()),
        u32::from_be_bytes(digest[4..8].try_into().unwrap()),
        u32::from_be_bytes(digest[8..12].try_into().unwrap()),
        u32::from_be_bytes(digest[12..16].try_into().unwrap()),
        u32::from_be_bytes(digest[16..20].try_into().unwrap()),
        u32::from_be_bytes(digest[20..24].try_into().unwrap()),
        u32::from_be_bytes(digest[24..28].try_into().unwrap()),
        u32::from_be_bytes(digest[28..32].try_into().unwrap()),
    ];

    // ZFS expects a [u64; 4] in native encoding.
    [
        (u64::from(h[0]) << 32) | u64::from(h[1]),
        (u64::from(h[2]) << 32) | u64::from(h[3]),
        (u64::from(h[4]) << 32) | u64::from(h[5]),
        (u64::from(h[6]) << 32) | u64::from(h[7]),
    ]
}

/** Compute sha256 checksum.
 *
 * - Result is native endian.
 */
pub fn sha_256_digest(data: &[u8]) -> [u64; 4] {
    let digest: [u8; 32] = Sha256::digest(data).try_into().unwrap();
    digest_to_zfs_u64(&digest)
}

/** Compute sha256 checksum.
 *
 * - Result is native endian.
 */
pub fn sha_256_digest_slices(datas: &[&[u8]]) -> [u64; 4] {
    let mut hasher = Sha256::new();

    for data in datas {
        hasher.update(data);
    }

    let digest: [u8; 32] = hasher.finalize().try_into().unwrap();
    digest_to_zfs_u64(&digest)
}
