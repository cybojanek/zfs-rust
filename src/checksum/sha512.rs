use sha2::{Digest, Sha512_256};

/** Convert a SHA-512-256 digest to ZFS u64 format.
 */
fn digest_to_zfs_u64(digest: &[u8; 32]) -> [u64; 4] {
    // A SHA-256-256 [u8; 32] digest is encoded using big endian encoding, so
    // decode the bytes as such.
    [
        u64::from_be_bytes(digest[0..8].try_into().unwrap()),
        u64::from_be_bytes(digest[8..16].try_into().unwrap()),
        u64::from_be_bytes(digest[16..24].try_into().unwrap()),
        u64::from_be_bytes(digest[24..32].try_into().unwrap()),
    ]
}

/** Compute sha512-256 checksum.
 *
 * - Result is native endian.
 */
pub fn sha_512_256_digest(data: &[u8]) -> [u64; 4] {
    let digest: [u8; 32] = Sha512_256::digest(data).try_into().unwrap();

    digest_to_zfs_u64(&digest)
}

/** Compute sha512-256 checksum.
 *
 * - Result is native endian.
 */
pub fn sha_512_256_digest_slices(datas: &[&[u8]]) -> [u64; 4] {
    let mut hasher = Sha512_256::new();

    for data in datas {
        hasher.update(data);
    }

    let digest: [u8; 32] = hasher.finalize().try_into().unwrap();
    digest_to_zfs_u64(&digest)
}
