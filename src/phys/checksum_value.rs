use crate::endian::{DecodeError, Decoder, EncodeError, Encoder};

////////////////////////////////////////////////////////////////////////////////

/** Checksum value.
 *
 * - Bytes: 32
 * - C reference: `typedef struct zio_cksum zio_cksum_t`
 *
 * ```text
 *        6                   5                   4                   3                   2                   1                   0
 *  3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                         words[0] (64)                                                         |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                         words[1] (64)                                                         |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                         words[2] (64)                                                         |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                         words[3] (64)                                                         |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * ```
 */
#[derive(Debug)]
pub struct ChecksumValue {
    pub words: [u64; 4],
}

impl ChecksumValue {
    /// Byte length of an encoded [`ChecksumValue`].
    pub const LENGTH: usize = 32;

    /** Decodes a [`ChecksumValue`].
     *
     * # Errors
     *
     * Returns [`DecodeError`] if there are not enough bytes.
     */
    pub fn from_decoder(decoder: &mut Decoder) -> Result<ChecksumValue, DecodeError> {
        Ok(ChecksumValue {
            words: [
                decoder.get_u64()?,
                decoder.get_u64()?,
                decoder.get_u64()?,
                decoder.get_u64()?,
            ],
        })
    }

    /** Encodes a [`ChecksumValue`].
     *
     * # Errors
     *
     * Returns [`EncodeError`] if there are not enough bytes.
     */
    pub fn to_encoder(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.put_u64(self.words[0])?;
        encoder.put_u64(self.words[1])?;
        encoder.put_u64(self.words[2])?;
        encoder.put_u64(self.words[3])?;

        Ok(())
    }
}
