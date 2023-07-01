use core::fmt;
use core::result::Result;
use core::result::Result::{Err, Ok};

#[cfg(feature = "std")]
use std::error;

extern crate fixedstr;
extern crate num;
extern crate strum;

use fixedstr::str16;

use crate::nv;

////////////////////////////////////////////////////////////////////////////////

/** Pool version.
 */
#[derive(Clone, Copy, Debug, FromPrimitive, strum::Display)]
pub enum PoolVersion {
    V1 = 1,
    V2 = 2,
    V3 = 3,
    V4 = 4,
    V5 = 5,
    V6 = 6,
    V7 = 7,
    V8 = 8,
    V9 = 9,
    V10 = 10,
    V11 = 11,
    V12 = 12,
    V13 = 13,
    V14 = 14,
    V15 = 15,
    V16 = 16,
    V17 = 17,
    V18 = 18,
    V19 = 19,
    V20 = 20,
    V21 = 21,
    V22 = 22,
    V23 = 23,
    V24 = 24,
    V25 = 25,
    V26 = 26,
    V27 = 27,
    V28 = 28,
    V5000 = 5000,
}

/** Pool type.
 *
 * - C reference: `enum pool_state pool_state_t`
 */
#[derive(Clone, Copy, Debug, FromPrimitive, strum::Display)]
pub enum PoolState {
    Active = 0,
    Exported = 1,
    Destroyed = 2,
    Spare = 3,
    L2Cache = 4,
}

////////////////////////////////////////////////////////////////////////////////

const POOL_CONFIG_KEY_GUID: &str = "guid";
const POOL_CONFIG_KEY_HOST_ID: &str = "hostid";
const POOL_CONFIG_KEY_HOST_NAME: &str = "hostname";
const POOL_CONFIG_KEY_NAME: &str = "name";
const POOL_CONFIG_KEY_POOL_GUID: &str = "pool_guid";
const POOL_CONFIG_KEY_STATE: &str = "state";
const POOL_CONFIG_KEY_TOP_GUID: &str = "top_guid";
const POOL_CONFIG_KEY_TXG: &str = "txg";
const POOL_CONFIG_KEY_VDEV_TREE: &str = "vdev_tree";
const POOL_CONFIG_KEY_VERSION: &str = "version";

////////////////////////////////////////////////////////////////////////////////

/// 'hostid' and 'hostname' fields of [`Pool`] NV list.
#[derive(Debug)]
pub struct PoolHost<'a> {
    pub id: u64,
    pub name: &'a str,
}

/**
 * Pool configuration extracted from label NV pair list.
 *
 * Many fields have been added over time. The required fields here, are based
 * on the `add_config`, `spa_config_generate`. `spa_load`, and
 * `zfs_ioc_pool_import` functions from the git commit hash
 * f41aed0d5f3 of the OpenSolaris code archive.
 * - guid, name, pool_guid, state, top_guid, txg, vdev_tree, version
 *
 * V6:
 * - hostid, hostname @ OpenSolaris c0c2cef3151
 */
#[derive(Debug)]
pub struct Pool<'a> {
    // V1.
    pub guid: u64,
    pub name: &'a str,
    pub pool_guid: u64,
    pub state: PoolState,
    pub top_guid: u64,
    pub txg: u64,
    pub version: PoolVersion,

    // V6
    pub host: Option<PoolHost<'a>>,
}

impl Pool<'_> {
    /** Decodes a [`Pool`] NV pair list.
     *
     * # Errors
     *
     * Returns [`PoolDecodeError`] in case of an error.
     */
    pub fn from_decoder<'a>(decoder: &'a nv::Decoder<'a>) -> Result<Pool<'a>, PoolDecodeError> {
        ////////////////////////////////
        // Get required fields.
        let guid = nv::find_require!(decoder, POOL_CONFIG_KEY_GUID, Uint64, PoolDecodeError)?;
        let name = nv::find_require!(decoder, POOL_CONFIG_KEY_NAME, String, PoolDecodeError)?;
        let pool_guid =
            nv::find_require!(decoder, POOL_CONFIG_KEY_POOL_GUID, Uint64, PoolDecodeError)?;
        let top_guid =
            nv::find_require!(decoder, POOL_CONFIG_KEY_TOP_GUID, Uint64, PoolDecodeError)?;
        let txg = nv::find_require!(decoder, POOL_CONFIG_KEY_TXG, Uint64, PoolDecodeError)?;

        let state_number =
            nv::find_require!(decoder, POOL_CONFIG_KEY_STATE, Uint64, PoolDecodeError)?;
        let version_number =
            nv::find_require!(decoder, POOL_CONFIG_KEY_VERSION, Uint64, PoolDecodeError)?;

        let state =
            num::FromPrimitive::from_u64(state_number).ok_or(PoolDecodeError::InvalidState {
                state: state_number,
            })?;
        let version = num::FromPrimitive::from_u64(version_number).ok_or(
            PoolDecodeError::UnsupportedVersion {
                version: version_number,
            },
        )?;

        ////////////////////////////////
        // Check for optional hostid, and hostname.
        let host =
            match nv::find_optional!(decoder, POOL_CONFIG_KEY_HOST_ID, Uint64, PoolDecodeError)? {
                Some(host_id) => {
                    // Check that if hostid is set, then so is hostname.
                    let host_name = nv::find_require!(
                        decoder,
                        POOL_CONFIG_KEY_HOST_NAME,
                        String,
                        PoolDecodeError
                    )?;
                    Some(PoolHost {
                        id: host_id,
                        name: host_name,
                    })
                }
                None => {
                    // Error if hostid is not set, but hostname is.
                    let host_name = nv::find_optional!(
                        decoder,
                        POOL_CONFIG_KEY_HOST_NAME,
                        String,
                        PoolDecodeError
                    )?;
                    if !host_name.is_none() {
                        return Err(PoolDecodeError::InvalidConfiguration {
                            reason: "'hostname' is set, but 'hostid' is not",
                        });
                    }
                    None
                }
            };

        ////////////////////////////////
        // Loop through all the pairs, and check for unknown names.

        let known_names = [
            POOL_CONFIG_KEY_GUID,
            POOL_CONFIG_KEY_HOST_ID,
            POOL_CONFIG_KEY_HOST_NAME,
            POOL_CONFIG_KEY_NAME,
            POOL_CONFIG_KEY_POOL_GUID,
            POOL_CONFIG_KEY_STATE,
            POOL_CONFIG_KEY_TOP_GUID,
            POOL_CONFIG_KEY_TXG,
            POOL_CONFIG_KEY_VDEV_TREE, // TODO(cybojanek): Implement
            POOL_CONFIG_KEY_VERSION,
        ];

        loop {
            // Get next pair.
            let pair = decoder.next_pair()?;

            // Check if its the end of the list.
            let pair = match pair {
                Some(v) => v,
                None => break,
            };

            if !known_names.contains(&pair.name) {
                // Key is unknown.
                return Err(PoolDecodeError::UnknownName {
                    name: pair.name.into(),
                    full_length: pair.name.len(),
                });
            }
        }

        ////////////////////////////////
        // Success!
        Ok(Pool {
            // V1
            guid: guid,
            name: name,
            pool_guid: pool_guid,
            state: state,
            top_guid: top_guid,
            txg: txg,
            version: version,

            // V6
            host: host,
        })
    }
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub enum PoolDecodeError {
    /** Invalid configuration.
     *
     * - `reason` - Reason for invalid configuration.
     */
    InvalidConfiguration { reason: &'static str },

    /** Invalid state field.
     *
     * - `state` - Version.
     */
    InvalidState { state: u64 },

    /** Missing NV pair.
     *
     * - `name` - Key.
     */
    MissingValue { name: &'static str },

    /** NV decoding error.
     *
     * - `err` - Error.
     */
    NvDecodeError { err: nv::DecodeError },

    /** Unknown name error.
     *
     * - `name`        - Truncated string of unknown name.
     * - `full_length` - The full length of the unknown name.
     */
    UnknownName { name: str16, full_length: usize },

    /** Invalid version field.
     *
     * - `version` - Version.
     */
    UnsupportedVersion { version: u64 },

    /** Value type mismatch
     *
     * - `name`      - Of NV pair.
     * - `data_type` - Of NV pair.
     */
    ValueTypeMismatch {
        name: &'static str,
        data_type: nv::DataType,
    },
}

impl From<nv::DecodeError> for PoolDecodeError {
    fn from(value: nv::DecodeError) -> Self {
        PoolDecodeError::NvDecodeError { err: value }
    }
}

impl fmt::Display for PoolDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PoolDecodeError::InvalidConfiguration { reason } => {
                write!(f, "Pool decode error: invalid configuration: {reason}")
            }
            PoolDecodeError::InvalidState { state } => {
                write!(f, "Pool decode error: invalid 'state' {state}")
            }
            PoolDecodeError::MissingValue { name } => {
                write!(f, "Pool decode error: missing '{name}'")
            }
            PoolDecodeError::NvDecodeError { err } => {
                write!(f, "Pool Nv decode error: {err}")
            }
            PoolDecodeError::UnknownName { name, full_length } => {
                if *full_length > name.len() {
                    write!(
                        f,
                        "Pool decode error: unknown name of length {full_length}: '{name}...'"
                    )
                } else {
                    write!(f, "Pool decode error: unknown name: '{name}'")
                }
            }
            PoolDecodeError::UnsupportedVersion { version } => {
                write!(f, "Pool decode error: invalid 'version' {version}")
            }
            PoolDecodeError::ValueTypeMismatch { name, data_type } => {
                write!(
                    f,
                    "Pool decode value type mismatch for '{name}' got {data_type}"
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for PoolDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            PoolDecodeError::NvDecodeError { err } => Some(err),
            _ => None,
        }
    }
}
