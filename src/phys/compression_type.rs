use core::convert::TryFrom;
use core::fmt;
use core::result::Result;

#[cfg(feature = "std")]
use std::error;

extern crate num;
extern crate strum;

////////////////////////////////////////////////////////////////////////////////

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

////////////////////////////////////////////////////////////////////////////////

impl Into<u8> for CompressionType {
    fn into(self) -> u8 {
        // Check that type is not truncated, and limited to 7 bits, due to its
        // representation in a BlockPointer.
        debug_assert!((self as u64) < (i8::MAX as u64), "CompressionType: {self}");
        self as u8
    }
}

impl TryFrom<u8> for CompressionType {
    type Error = CompressionTypeError;

    fn try_from(compression: u8) -> Result<Self, Self::Error> {
        num::FromPrimitive::from_u8(compression)
            .ok_or(CompressionTypeError::InvalidValue { value: compression })
    }
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub enum CompressionTypeError {
    /** Invalid compression type value.
     *
     * - `value` - Invalid value.
     */
    InvalidValue { value: u8 },
}

impl fmt::Display for CompressionTypeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CompressionTypeError::InvalidValue { value } => {
                write!(f, "Compression Type error: invalid value: {value}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for CompressionTypeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}
