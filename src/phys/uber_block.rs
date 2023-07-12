use core::fmt;
use core::result::Result;
use core::result::Result::{Err, Ok};

#[cfg(feature = "std")]
use std::error;

use crate::checksum::{label_checksum, label_verify, LabelChecksumError, LabelVerifyError};
use crate::endian::{DecodeError, Decoder, EncodeError, Encoder, Endian};
use crate::phys::{BlockPointer, BlockPointerDecodeError, BlockPointerEncodeError};

////////////////////////////////////////////////////////////////////////////////

/// UberBlock MMP configuration.
#[derive(Debug)]
pub struct UberBlockMmp {
    pub delay: u64,
    pub config: u64,
}

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
    pub mmp: Option<UberBlockMmp>,
    pub ptr: BlockPointer,
    pub software_version: u64,
    pub timestamp: u64,
    pub txg: u64,
    pub version: u64,
}

impl UberBlock {
    /// Byte length of an encoded [`UberBlock`].
    pub const LENGTH: usize = 1024;

    /// Padding size.
    const PADDING_SIZE: usize = 776;

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
        ////////////////////////////////
        // Verify checksum.
        label_verify(bytes, offset)?;

        ////////////////////////////////
        // Create decoder.
        let decoder = Decoder::from_u64_magic(bytes, UberBlock::MAGIC)?;

        ////////////////////////////////
        // Decode fields.
        let version = decoder.get_u64()?;
        let txg = decoder.get_u64()?;
        let guid_sum = decoder.get_u64()?;
        let timestamp = decoder.get_u64()?;

        ////////////////////////////////
        // Decode block pointer.
        let block_ptr = BlockPointer::from_decoder(&decoder)?;

        ////////////////////////////////
        // Decode software version.
        let software_version = decoder.get_u64()?;

        ////////////////////////////////
        // Decode MMP.
        let mmp_magic = decoder.get_u64()?;
        let mmp_delay = decoder.get_u64()?;
        let mmp_config = decoder.get_u64()?;

        // Check MMP magic.
        let mmp = match mmp_magic {
            0 => {
                if mmp_delay != 0 || mmp_config != 0 {
                    return Err(UberBlockDecodeError::NonZeroMmpValues {
                        delay: mmp_delay,
                        config: mmp_config,
                    });
                }
                None
            }
            UberBlock::MMP_MAGIC => Some(UberBlockMmp {
                config: mmp_config,
                delay: mmp_delay,
            }),
            _ => return Err(UberBlockDecodeError::InvalidMmpMagic { magic: mmp_magic }),
        };

        ////////////////////////////////
        // Decode checkpoint transaction group.
        let checkpoint_txg = decoder.get_u64()?;

        ////////////////////////////////
        // Check that the rest of the uber block (up to the checksum at the
        // tail) is all zeroes.
        decoder.skip_zero_padding(UberBlock::PADDING_SIZE)?;

        ////////////////////////////////
        // Success.
        Ok(UberBlock {
            checkpoint_txg: checkpoint_txg,
            endian: decoder.endian(),
            guid_sum: guid_sum,
            mmp: mmp,
            ptr: block_ptr,
            software_version: software_version,
            timestamp: timestamp,
            txg: txg,
            version: version,
        })
    }

    /** Encodes an [`UberBlock`].
     *
     * # Errors
     *
     * Returns [`UberBlockEncodeError`] if there is not enough space or
     * uberblock is invalid.
     */
    pub fn to_bytes(
        &self,
        bytes: &mut [u8; UberBlock::LENGTH],
        offset: u64,
    ) -> Result<(), UberBlockEncodeError> {
        ////////////////////////////////
        // Create encoder.
        let mut encoder = Encoder::to_bytes(bytes, self.endian);
        encoder.put_u64(UberBlock::MAGIC)?;

        ////////////////////////////////
        // Encode fields.
        encoder.put_u64(self.version)?;
        encoder.put_u64(self.txg)?;
        encoder.put_u64(self.guid_sum)?;
        encoder.put_u64(self.timestamp)?;

        ////////////////////////////////
        // Encode block pointer.
        self.ptr.to_encoder(&mut encoder)?;

        ////////////////////////////////
        // Encode software version.
        encoder.put_u64(self.software_version)?;

        ////////////////////////////////
        // Encode MMP (conditionaly).
        match &self.mmp {
            Some(mmp) => {
                encoder.put_u64(UberBlock::MMP_MAGIC)?;
                encoder.put_u64(mmp.delay)?;
                encoder.put_u64(mmp.config)?;
            }
            None => {
                encoder.put_zero_padding(24)?;
            }
        }

        ////////////////////////////////
        // Encode checkpoint transaction group.
        encoder.put_u64(self.checkpoint_txg)?;

        ////////////////////////////////
        // Encode padding.
        encoder.put_zero_padding(UberBlock::PADDING_SIZE)?;

        ////////////////////////////////
        // Compute checksum.
        label_checksum(bytes, offset, self.endian)?;

        ////////////////////////////////
        // Success.
        Ok(())
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

impl From<LabelVerifyError> for UberBlockDecodeError {
    fn from(value: LabelVerifyError) -> Self {
        UberBlockDecodeError::LabelVerifyError { err: value }
    }
}

impl fmt::Display for UberBlockDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UberBlockDecodeError::BlockPointerDecodeError { err } => {
                write!(f, "Uber Block Block Pointer decode error: {err}")
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
            UberBlockDecodeError::EndianDecodeError { err } => Some(err),
            UberBlockDecodeError::LabelVerifyError { err } => Some(err),
            _ => None,
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub enum UberBlockEncodeError {
    /** [`BlockPointer`] encode error.
     *
     * - `err` - [`BlockPointerEncodeError`]
     */
    BlockPointerEncodeError { err: BlockPointerEncodeError },

    /** Endian encode error.
     *
     * - `err` - [`DecodeError`]
     */
    EndianEncodeError { err: EncodeError },

    /** [`LabelChecksumError`] checksum error.
     *
     * - `err` - [`LabelChecksumError`]
     */
    LabelChecksumError { err: LabelChecksumError },
}

impl From<BlockPointerEncodeError> for UberBlockEncodeError {
    fn from(value: BlockPointerEncodeError) -> Self {
        UberBlockEncodeError::BlockPointerEncodeError { err: value }
    }
}

impl From<EncodeError> for UberBlockEncodeError {
    fn from(value: EncodeError) -> Self {
        UberBlockEncodeError::EndianEncodeError { err: value }
    }
}

impl From<LabelChecksumError> for UberBlockEncodeError {
    fn from(value: LabelChecksumError) -> Self {
        UberBlockEncodeError::LabelChecksumError { err: value }
    }
}

impl fmt::Display for UberBlockEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UberBlockEncodeError::BlockPointerEncodeError { err } => {
                write!(f, "Uber Block Block Pointer encode error: {err}")
            }
            UberBlockEncodeError::EndianEncodeError { err } => {
                write!(f, "Uber Block Endian encode error: {err}")
            }
            UberBlockEncodeError::LabelChecksumError { err } => {
                write!(f, "Uber Block encode checksum error: {err}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for UberBlockEncodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            UberBlockEncodeError::BlockPointerEncodeError { err } => Some(err),
            UberBlockEncodeError::EndianEncodeError { err } => Some(err),
            UberBlockEncodeError::LabelChecksumError { err } => Some(err),
        }
    }
}
