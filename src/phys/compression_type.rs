extern crate num;
extern crate strum;

/** Compression type.
 *
 * - C reference: `enum zio_compress`
 */
#[derive(Clone, Copy, Debug, FromPrimitive, strum::Display)]
pub enum CompressionType {
    Inherit = 0,
    On,
    Off,
    Lzjb,
    Empty,
    Gzip1,
    Gzip2,
    Gzip3,
    Gzip4,
    Gzip5,
    Gzip6,
    Gzip7,
    Gzip8,
    Gzip9,
    Zle,
    Lz4,
    Zstd,
}

impl CompressionType {
    /** Converts a [`u8`] to a [`CompressionType`], returning `None` if unknown. */
    pub fn from_u8(compression: u8) -> Option<CompressionType> {
        num::FromPrimitive::from_u8(compression)
    }
}
