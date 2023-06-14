/*! Block checksum.
 */
use core::fmt;
use core::result::Result;
use core::result::Result::{Err, Ok};

#[cfg(feature = "std")]
use std::error;

use crate::checksum::{
    fletcher_2_be, fletcher_2_le, fletcher_4_be, fletcher_4_le, sha_256_digest, sha_512_256_digest,
};
use crate::endian::Endian;
use crate::phys::{ChecksumType, ChecksumValue};

////////////////////////////////////////////////////////////////////////////////

/** Computes the checksum of the `data` block.
 *
 * # Errors
 *
 * Returns [`BlockChecksumError`] in case of computation failure.
 */
pub fn block_checksum(
    data: &[u8],
    endian: Endian,
    checksum_type: ChecksumType,
) -> Result<ChecksumValue, BlockChecksumError> {
    let words = match checksum_type {
        ChecksumType::Fletcher2 => match endian {
            Endian::Little => fletcher_2_le(data),
            Endian::Big => fletcher_2_be(data),
        },
        ChecksumType::Fletcher4 => match endian {
            Endian::Little => fletcher_4_le(data),
            Endian::Big => fletcher_4_be(data),
        },
        ChecksumType::Sha256 => sha_256_digest(data),
        ChecksumType::Sha512_256 => sha_512_256_digest(data),
        _ => todo!(
            "Implement block_checksum for Checksum Type {}",
            checksum_type
        ),
    };

    Ok(ChecksumValue { words: words })
}

/** Verifies the checksum of the `data` block.
 *
 * # Errors
 *
 * Returns [`BlockVerifyError`] if computed checksum does not match.
 */
pub fn block_verify(
    data: &[u8],
    endian: Endian,
    checksum_type: ChecksumType,
    checksum_value: &ChecksumValue,
) -> Result<(), BlockVerifyError> {
    let computed = match checksum_type {
        ChecksumType::Fletcher2 => match endian {
            Endian::Little => fletcher_2_le(data),
            Endian::Big => fletcher_2_be(data),
        },
        ChecksumType::Fletcher4 => match endian {
            Endian::Little => fletcher_4_le(data),
            Endian::Big => fletcher_4_be(data),
        },
        ChecksumType::Sha256 => sha_256_digest(data),
        ChecksumType::Sha512_256 => sha_512_256_digest(data),
        _ => todo!("Implement block_verify for Checksum Type {}", checksum_type),
    };

    if computed == checksum_value.words {
        Ok(())
    } else {
        Err(BlockVerifyError::Mismatch {})
    }
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub enum BlockChecksumError {}

impl fmt::Display for BlockChecksumError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "")
    }
}

#[cfg(feature = "std")]
impl error::Error for BlockChecksumError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub enum BlockVerifyError {
    /** Mismatch.
     */
    Mismatch {},
}

impl fmt::Display for BlockVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockVerifyError::Mismatch {} => {
                write!(f, "Block verify error: checksum mismatch")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for BlockVerifyError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}
