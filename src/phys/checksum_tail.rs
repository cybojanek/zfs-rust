use crate::endian::{DecodeError, Decoder, EncodeError, Encoder, Endian};
use crate::phys::ChecksumValue;

////////////////////////////////////////////////////////////////////////////////

/** Checksum tail.
 *
 * - Bytes: 40
 * - C reference: `typedef struct zio_block_tail zio_block_tail_t`
 *
 * ```text
 *        6                   5                   4                   3                   2                   1                   0
 *  3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                           magic (64)                                                          |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                                                                                               |
 * |                                                         checksum (256)                                                        |
 * |                                                                                                                               |
 * |                                                                                                                               |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * ```
 */
#[derive(Debug)]
pub struct ChecksumTail {
    pub endian: Endian,
    pub value: ChecksumValue,
}

impl ChecksumTail {
    /// Byte length of an encoded [`ChecksumTail`] (40).
    pub const LENGTH: usize = 8 + ChecksumValue::LENGTH;

    /// Magic value for an encoded [`ChecksumTail`].
    pub const MAGIC: u64 = 0x210da7ab10c7a11;

    /** Decodes a [`ChecksumTail`].
     *
     * # Errors
     *
     * Returns [`DecodeError`] if there are not enough bytes, or magic is invalid.
     */
    pub fn from_bytes(bytes: &[u8; ChecksumTail::LENGTH]) -> Result<ChecksumTail, DecodeError> {
        let mut decoder = Decoder::from_u64_magic(bytes, ChecksumTail::MAGIC)?;

        Ok(ChecksumTail {
            endian: decoder.endian(),
            value: ChecksumValue::from_decoder(&mut decoder)?,
        })
    }

    /** Encodes a [`ChecksumTail`].
     *
     * # Errors
     *
     * Returns [`EncodeError`] if there are not enough bytes.
     */
    pub fn to_bytes(&self, bytes: &mut [u8; ChecksumTail::LENGTH]) -> Result<(), EncodeError> {
        let mut encoder = Encoder::to_bytes(bytes, self.endian);

        encoder.put_u64(ChecksumTail::MAGIC)?;
        self.value.to_encoder(&mut encoder)?;

        Ok(())
    }
}
