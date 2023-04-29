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

impl ChecksumType {
    /** Converts a [`u8`] to a [`ChecksumType`], returning `None` if unknown. */
    pub fn from_u8(checksum: u8) -> Option<ChecksumType> {
        num::FromPrimitive::from_u8(checksum)
    }
}
