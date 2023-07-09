use core::convert::TryFrom;
use core::fmt;
use core::result::Result;

#[cfg(feature = "std")]
use std::error;

extern crate num;
extern crate strum;

////////////////////////////////////////////////////////////////////////////////

/** Checksum type.
 *
 * - C reference: `enum zio_checksum`
 */
#[derive(Clone, Copy, Debug, FromPrimitive, strum::Display)]
pub enum ChecksumType {
    Inherit = 0,
    On,
    Off,
    Label,
    GangHeader,
    Zilog,
    Fletcher2,
    Fletcher4,
    Sha256,
    Zilog2,
    NoParity,
    Sha512_256,
    Skein,
    EdonR,
    Blake3,
}

////////////////////////////////////////////////////////////////////////////////

impl Into<u8> for ChecksumType {
    fn into(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for ChecksumType {
    type Error = ChecksumTypeError;

    fn try_from(checksum: u8) -> Result<Self, Self::Error> {
        num::FromPrimitive::from_u8(checksum)
            .ok_or(ChecksumTypeError::InvalidValue { value: checksum })
    }
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub enum ChecksumTypeError {
    /** Invalid checksum type value.
     *
     * - `value` - Invalid value.
     */
    InvalidValue { value: u8 },
}

impl fmt::Display for ChecksumTypeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ChecksumTypeError::InvalidValue { value } => {
                write!(f, "Checksum Type error: invalid value: {value}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for ChecksumTypeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}
