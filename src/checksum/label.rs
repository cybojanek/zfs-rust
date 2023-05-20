/*! Label checksum.
 *
 * * The `label` checksum is embedded at the tail end of a block.
 * * It uses `sha256`, where the checksum endian encoding is specified using the magic.
 * * It is used to checksum blocks in the label (boot block, nv list, uber blocks).
 * * The checksum is calculated over the entire block (including the tail).
 * * When calculating the checksum, `checksum 0` is set to the `offset` of the block,
 *   and `checksum 1`, `checksum 2`, `checksum 3` are all set to `0`.
 *
 * Embedded at tail of data.
 *
 * ```text
 *        6                   5                   4                   3                   2                   1                   0
 *  3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                              ...                                                              |
 * +                                                            payload                                                            +
 * |                                                              ...                                                              |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                           magic (64)                                                          |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                        checksum 0 (64)                                                        |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                        checksum 1 (64)                                                        |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                        checksum 2 (64)                                                        |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                        checksum 3 (64)                                                        |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * ```
 */
use core::fmt;
use core::result::Result;
use core::result::Result::{Err, Ok};

#[cfg(feature = "std")]
use std::error;

use crate::checksum::{sha_256_digest, sha_256_digest_slices};
use crate::endian;
use crate::endian::Endian;

////////////////////////////////////////////////////////////////////////////////

/// Byte length of an encoded label checksum (including magic).
pub const LENGTH: usize = 40;

/// Embedded checksum magic.
pub const MAGIC: u64 = 0x210da7ab10c7a11;

////////////////////////////////////////////////////////////////////////////////

/** Compute the checksum of the `data` block and encode it at the end of `data`.
 *
 * * `offset` is included in checksum computation
 * * `endian` specifies the checksum encoding
 *
 * # Errors
 *
 * Returns [`LabelChecksumError`] if slice is too short.
 */
pub fn label_checksum(
    data: &mut [u8],
    offset: u64,
    endian: Endian,
) -> Result<(), LabelChecksumError> {
    // Check length.
    let length = data.len();
    if length < LENGTH {
        return Err(LabelChecksumError::InvalidLength { length: length });
    }

    // Grab tail (including magic).
    let tail = &mut data[length - LENGTH..length];

    // Create encoder.
    let mut encoder = endian::Encoder::to_bytes(tail, endian);

    // Encode MAGIC, offset, and zeroes.
    encoder.put_u64(MAGIC)?;
    encoder.put_u64(offset)?;
    encoder.put_u64(0)?;
    encoder.put_u64(0)?;
    encoder.put_u64(0)?;

    // Compute checksum.
    let checksum = sha_256_digest(data);

    // Grab tail (excluding magic).
    let tail = &mut data[length - 32..length];

    // Create encoder.
    let mut encoder = endian::Encoder::to_bytes(tail, endian);

    // Encode checksum.
    encoder.put_u64(checksum[0])?;
    encoder.put_u64(checksum[1])?;
    encoder.put_u64(checksum[2])?;
    encoder.put_u64(checksum[3])?;

    Ok(())
}

/** Verify the checksum of the `data` block.
 *
 * * `offset` is included in checksum computation
 *
 * # Errors
 *
 * Returns [`LabelVerifyError`] if slice is too short, invalid magic, or
 * mismatched checksum.
 */
pub fn label_verify(data: &[u8], offset: u64) -> Result<(), LabelVerifyError> {
    // Check length.
    let length = data.len();
    if length < LENGTH {
        return Err(LabelVerifyError::InvalidLength { length: length });
    }

    // Grab tail (including magic).
    let tail = &data[length - LENGTH..length];
    let mut decoder = match endian::Decoder::from_u64_magic(tail, MAGIC) {
        Ok(v) => v,
        Err(e) => match e {
            endian::DecodeError::InvalidMagic {
                expected: _,
                actual,
            } => {
                // The byte order does not matter for 0, so just use
                // native encoding (ne).
                if u64::from_ne_bytes(actual) == 0 {
                    return Err(LabelVerifyError::EmptyMagic {});
                }
                return Err(LabelVerifyError::EndianDecodeError { err: e });
            }
            _ => return Err(LabelVerifyError::EndianDecodeError { err: e }),
        },
    };

    // Decode checksum.
    let data_checksum = [
        decoder.get_u64()?,
        decoder.get_u64()?,
        decoder.get_u64()?,
        decoder.get_u64()?,
    ];

    // Create offset checksum.
    let offset_checksum = &mut [0; 32];

    // Create encoder.
    let mut encoder = endian::Encoder::to_bytes(offset_checksum, decoder.endian());

    // Encode offset and zeroes.
    encoder.put_u64(offset)?;
    encoder.put_u64(0)?;
    encoder.put_u64(0)?;
    encoder.put_u64(0)?;

    // Compute checksum.
    let slices = &[&data[0..length - offset_checksum.len()], offset_checksum];
    let computed_checksum = sha_256_digest_slices(slices);

    // Compare checksum.
    if data_checksum == computed_checksum {
        Ok(())
    } else {
        Err(LabelVerifyError::Mismatch {})
    }
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub enum LabelChecksumError {
    /** Endian pack error:
     *
     * * `err` - [`endian::DecodeError`]
     */
    EndianEncodeError { err: endian::EncodeError },

    /** Invalid length.
     *
     * * `length` - Length of data.
     */
    InvalidLength { length: usize },
}

impl From<endian::EncodeError> for LabelChecksumError {
    fn from(value: endian::EncodeError) -> Self {
        LabelChecksumError::EndianEncodeError { err: value }
    }
}

impl fmt::Display for LabelChecksumError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LabelChecksumError::EndianEncodeError { err } => {
                write!(f, "Label checksum Endian pack error: {err}")
            }
            LabelChecksumError::InvalidLength { length } => {
                write!(
                    f,
                    "Label checksum error: invalid length {length} expected at least {LENGTH}"
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for LabelChecksumError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            LabelChecksumError::EndianEncodeError { err } => Some(err),
            _ => None,
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub enum LabelVerifyError {
    /** Empty magic.
     */
    EmptyMagic {},

    /** Endian pack error:
     *
     * * `err` - [`endian::DecodeError`]
     */
    EndianEncodeError { err: endian::EncodeError },

    /** Endian unpack error:
     *
     * * `err` - [`endian::DecodeError`]
     */
    EndianDecodeError { err: endian::DecodeError },

    /** Invalid length.
     *
     * * `length` - Length of data.
     */
    InvalidLength { length: usize },

    /** Checksum mismatch. */
    Mismatch {},
}

impl From<endian::EncodeError> for LabelVerifyError {
    fn from(value: endian::EncodeError) -> Self {
        LabelVerifyError::EndianEncodeError { err: value }
    }
}

impl From<endian::DecodeError> for LabelVerifyError {
    fn from(value: endian::DecodeError) -> Self {
        LabelVerifyError::EndianDecodeError { err: value }
    }
}

impl fmt::Display for LabelVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LabelVerifyError::EmptyMagic {} => {
                write!(f, "Label verify error: empty magic")
            }
            LabelVerifyError::EndianEncodeError { err } => {
                write!(f, "Label verify Endian pack error: {err}")
            }
            LabelVerifyError::EndianDecodeError { err } => {
                write!(f, "Label verify Endian unpack error: {err}")
            }
            LabelVerifyError::InvalidLength { length } => {
                write!(
                    f,
                    "Label verify error: invalid length {length} expected at least {LENGTH}"
                )
            }
            LabelVerifyError::Mismatch {} => write!(f, "Label verify checksum mismatch"),
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for LabelVerifyError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            LabelVerifyError::EndianEncodeError { err } => Some(err),
            LabelVerifyError::EndianDecodeError { err } => Some(err),
            _ => None,
        }
    }
}
