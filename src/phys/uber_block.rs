use core::fmt;
use core::result::Result;
use core::result::Result::{Err, Ok};

#[cfg(feature = "std")]
use std::error;

use crate::checksum::{label_verify, LabelVerifyError};
use crate::endian::{DecodeError, Decoder, Endian};
use crate::phys::{BlockPointer, BlockPointerDecodeError};

////////////////////////////////////////////////////////////////////////////////

/** Checksum tail.
 *
 * - Bytes: 1024
 * - C reference: `struct uberblock`
 *
 * ```text
 * +------------------+-----+
 * |            magic |   8 |
 * +------------------+-----+
 * |          version |   8 |
 * +------------------+-----+
 * |              txg |   8 |
 * +------------------+-----+
 * |         guid sum |   8 |
 * +------------------+-----+
 * |        timestamp |   8 |
 * +------------------+-----+
 * |    block pointer | 128 |
 * +------------------+-----+
 * | software version |   8 |
 * +------------------+-----+
 * |        mmp magic |   8 |
 * +------------------+-----+
 * |        mmp delay |   8 |
 * +------------------+-----+
 * |       mmp config |   8 |
 * +------------------+-----+
 * |   checkpoint txg |   8 |
 * +------------------+-----+
 * |          padding | 776 |
 * +------------------+-----+
 * |    checksum tail |  40 |
 * +------------------+-----+
 * ```
 */
#[derive(Debug)]
pub struct UberBlock {
    pub checkpoint_txg: u64,
    pub endian: Endian,
    pub guid_sum: u64,
    pub mmp_config: u64,
    pub mmp_delay: u64,
    pub ptr: BlockPointer,
    pub software_version: u64,
    pub timestamp: u64,
    pub txg: u64,
    pub version: u64,
}

impl UberBlock {
    /// Byte length of an encoded [`UberBlock`].
    pub const LENGTH: usize = 1024;

    /// Magic value for an encoded [`UberBlock`].
    pub const MAGIC: u64 = 0x0000000000bab10c;

    /// Magic value for MMP in [`UberBlock`].
    pub const MMP_MAGIC: u64 = 0x00000000a11cea11;

    /** Decodes an [`UberBlock`].
     *
     * # Errors
     *
     * Returns [`UberBlockDecodeError`] if there are not enough bytes, or magic is invalid.
     */
    pub fn from_bytes(
        bytes: &[u8; UberBlock::LENGTH],
        offset: u64,
    ) -> Result<UberBlock, UberBlockDecodeError> {
        // Verify checksum.
        match label_verify(bytes, offset) {
            Ok(_) => (),
            Err(_e @ LabelVerifyError::EmptyMagic {}) => {
                return Err(UberBlockDecodeError::EmptyLabelMagic {});
            }
            Err(e) => return Err(UberBlockDecodeError::LabelVerifyError { err: e }),
        };

        // Create decoder, and catch InvalidMagic error.
        // If the magic is 0, then return a more graceful error of empty magic.
        let mut decoder = match Decoder::from_u64_magic(bytes, UberBlock::MAGIC) {
            Ok(v) => v,
            Err(e) => match e {
                DecodeError::InvalidMagic {
                    expected: _,
                    actual,
                } => {
                    // The byte order does not matter for 0, so just use
                    // native encoding (ne).
                    if u64::from_ne_bytes(actual) == 0 {
                        return Err(UberBlockDecodeError::EmptyMagic {});
                    }
                    return Err(UberBlockDecodeError::EndianDecodeError { err: e });
                }
                _ => return Err(UberBlockDecodeError::EndianDecodeError { err: e }),
            },
        };

        // Decode fields.
        let version = decoder.get_u64()?;
        let txg = decoder.get_u64()?;
        let guid_sum = decoder.get_u64()?;
        let timestamp = decoder.get_u64()?;

        // Decode block pointer.
        let block_ptr = BlockPointer::from_decoder(&decoder)?;

        // Decode software version.
        let software_version = decoder.get_u64()?;

        // Decode MMP.
        let mmp_magic = decoder.get_u64()?;
        let mmp_delay = decoder.get_u64()?;
        let mmp_config = decoder.get_u64()?;

        // Check MMP magic.
        match mmp_magic {
            0 => {
                if mmp_delay != 0 || mmp_config != 0 {
                    return Err(UberBlockDecodeError::NonZeroMmpValues {
                        delay: mmp_delay,
                        config: mmp_config,
                    });
                }
            }
            UberBlock::MMP_MAGIC => (),
            _ => return Err(UberBlockDecodeError::InvalidMmpMagic { magic: mmp_magic }),
        }

        // Checkpoint transaction group.
        let checkpoint_txg = decoder.get_u64()?;

        // Check that the rest of the uber block (up to the checksum at the tail)
        // is all zeroes.
        decoder.skip_zero_padding(776)?;

        Ok(UberBlock {
            checkpoint_txg: checkpoint_txg,
            endian: decoder.endian(),
            guid_sum: guid_sum,
            mmp_config: mmp_config,
            mmp_delay: mmp_delay,
            ptr: block_ptr,
            software_version: software_version,
            timestamp: timestamp,
            txg: txg,
            version: version,
        })
    }
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub enum UberBlockDecodeError {
    /** [`BlockPointer`] decode error.
     *
     * - `err` - [`BlockPointerDecodeError`]
     */
    BlockPointerDecodeError { err: BlockPointerDecodeError },

    /** Empty label magic. */
    EmptyLabelMagic {},

    /** Empty magic. */
    EmptyMagic {},

    /** Endian decode error.
     *
     * - `err` - [`DecodeError`]
     */
    EndianDecodeError { err: DecodeError },

    /** Invalid MMP magic.
     *
     * - `magic` - Magic.
     */
    InvalidMmpMagic { magic: u64 },

    /** [`LabelVerifyError`] verify error.
     *
     * - `err` - [`LabelVerifyError`]
     */
    LabelVerifyError { err: LabelVerifyError },

    /** NonZero MMP values for MMP magic value of 0.
     *
     * - `delay`  - MMP delay.
     * - `config` - MMP config.
     */
    NonZeroMmpValues { delay: u64, config: u64 },
}

impl From<BlockPointerDecodeError> for UberBlockDecodeError {
    fn from(value: BlockPointerDecodeError) -> Self {
        UberBlockDecodeError::BlockPointerDecodeError { err: value }
    }
}

impl From<DecodeError> for UberBlockDecodeError {
    fn from(value: DecodeError) -> Self {
        UberBlockDecodeError::EndianDecodeError { err: value }
    }
}

impl fmt::Display for UberBlockDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UberBlockDecodeError::BlockPointerDecodeError { err } => {
                write!(f, "Uber Block Block Pointer decode error: {err}")
            }
            UberBlockDecodeError::EmptyLabelMagic {} => {
                write!(f, "Uber Block empty label magic error")
            }
            UberBlockDecodeError::EmptyMagic {} => {
                write!(f, "Uber Block empty magic error")
            }
            UberBlockDecodeError::EndianDecodeError { err } => {
                write!(f, "Uber Block Endian decode error: {err}")
            }
            UberBlockDecodeError::InvalidMmpMagic { magic } => {
                write!(
                    f,
                    "Uber Block decode error: invalid MMP magic 0x{magic:016x}"
                )
            }
            UberBlockDecodeError::LabelVerifyError { err } => {
                write!(f, "Uber Block decode checksum error: {err}")
            }
            UberBlockDecodeError::NonZeroMmpValues { delay, config } => {
                write!(
                    f,
                    "Uber Block decode error: non-zero MMP values delay 0x{delay:016x} config 0x{config:016x} for MMP magic 0"
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for UberBlockDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            UberBlockDecodeError::BlockPointerDecodeError { err } => Some(err),
            UberBlockDecodeError::LabelVerifyError { err } => Some(err),
            UberBlockDecodeError::EndianDecodeError { err } => Some(err),
            _ => None,
        }
    }
}
