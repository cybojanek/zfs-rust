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

const VDEV_TYPE_DISK: &str = "disk";
const VDEV_TYPE_FILE: &str = "file";
const VDEV_TYPE_MIRROR: &str = "mirror";
const VDEV_TYPE_MISSING: &str = "missing";
const VDEV_TYPE_RAIDZ: &str = "raidz";
const VDEV_TYPE_REPLACING: &str = "replacing";
const VDEV_TYPE_ROOT: &str = "root";

////////////////////////////////////////////////////////////////////////////////

const POOL_CONFIG_KEY_VDEV_TREE: &str = "vdev_tree";

// V1
const VDEV_CONFIG_A_SHIFT: &str = "ashift";
const VDEV_CONFIG_A_SIZE: &str = "asize";
const VDEV_CONFIG_CREATE_TXG: &str = "create_txg";
const VDEV_CONFIG_DTL: &str = "DTL";
const VDEV_CONFIG_DEV_ID: &str = "devid";
const VDEV_CONFIG_GUID: &str = "guid";
const VDEV_CONFIG_ID: &str = "id";
const VDEV_CONFIG_META_SLAB_ARRAY: &str = "metaslab_array";
const VDEV_CONFIG_META_SLAB_SHIFT: &str = "metaslab_shift";
const VDEV_CONFIG_PATH: &str = "path";
const VDEV_CONFIG_TYPE: &str = "type";
const VDEV_CONFIG_WHOLE_DISK: &str = "whole_disk";

// V6
const VDEV_CONFIG_PHYS_PATH: &str = "phys_path";

// V7
const VDEV_CONFIG_IS_LOG: &str = "is_log";

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub struct VdevAlignmentMetaSlab {
    pub a_shift: u64,
    pub a_size: u64,
    pub meta_slab_array: u64,
    pub meta_slab_shift: u64,
}

impl VdevAlignmentMetaSlab {
    /** Decodes a [`VdevTree`] NV pair list.
     *
     * # Errors
     *
     * Returns [`VdevDecodeError`] in case of an error.
     */
    pub fn from_decoder<'a, 'b>(
        decoder: &'a nv::Decoder<'a>,
        nested_decoder: &'b nv::NestedDecoder<'b>,
    ) -> Result<Option<VdevAlignmentMetaSlab>, VdevDecodeError> {
        ////////////////////////////////
        // Use macros for cleaner code.
        macro_rules! find_u64 {
            ($name:expr) => {
                nv::find_nested!(decoder, nested_decoder, $name, Uint64, VdevDecodeError)?
            };
        }

        macro_rules! find_option_u64 {
            ($name:expr) => {
                nv::find_option_nested!(decoder, nested_decoder, $name, Uint64, VdevDecodeError)?
            };
        }

        ////////////////////////////////
        // If one is set, then all should be set.
        let a_shift = find_option_u64!(VDEV_CONFIG_A_SHIFT);
        match a_shift {
            Some(a_shift) => Ok(Some(VdevAlignmentMetaSlab {
                a_shift: a_shift,
                a_size: find_u64!(VDEV_CONFIG_A_SIZE),
                meta_slab_array: find_u64!(VDEV_CONFIG_META_SLAB_ARRAY),
                meta_slab_shift: find_u64!(VDEV_CONFIG_META_SLAB_SHIFT),
            })),
            None => {
                let a_size = find_option_u64!(VDEV_CONFIG_A_SIZE);
                let meta_slab_array = find_option_u64!(VDEV_CONFIG_META_SLAB_ARRAY);
                let meta_slab_shift = find_option_u64!(VDEV_CONFIG_META_SLAB_SHIFT);
                if !a_size.is_none() || !meta_slab_array.is_none() || !meta_slab_shift.is_none() {
                    return Err(VdevDecodeError::InvalidConfiguration{
                        reason: "'ashift' is set, but 'asize', 'metaslab_array', or 'metaslab_shift' is missing"
                    });
                }
                Ok(None)
            }
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub struct VdevDisk<'a> {
    pub path: &'a str,
    pub whole_disk: bool,

    pub a_meta_slab: Option<VdevAlignmentMetaSlab>,
    pub create_txg: Option<u64>,
    pub is_log: Option<bool>,
    pub dev_id: Option<&'a str>,
    pub phys_path: Option<&'a str>,
}

impl VdevDisk<'_> {
    /** Decodes a [`VdevTree`] NV pair list.
     *
     * # Errors
     *
     * Returns [`VdevDecodeError`] in case of an error.
     */
    pub fn from_decoder<'a, 'b>(
        decoder: &'a nv::Decoder<'a>,
        nested_decoder: &'b nv::NestedDecoder<'b>,
    ) -> Result<VdevDisk<'a>, VdevDecodeError> {
        ////////////////////////////////
        // Loop through all the pairs, and check for unknown names.
        let known = [
            // Common.
            VDEV_CONFIG_ID,
            VDEV_CONFIG_TYPE,
            VDEV_CONFIG_GUID,
            // Disk.
            VDEV_CONFIG_A_SHIFT,
            VDEV_CONFIG_A_SIZE,
            VDEV_CONFIG_CREATE_TXG,
            VDEV_CONFIG_DEV_ID,
            VDEV_CONFIG_IS_LOG,
            VDEV_CONFIG_META_SLAB_ARRAY,
            VDEV_CONFIG_META_SLAB_SHIFT,
            VDEV_CONFIG_PATH,
            VDEV_CONFIG_PHYS_PATH,
            VDEV_CONFIG_WHOLE_DISK,
        ];

        let nd = nested_decoder.get_decoder();
        nd.reset();

        loop {
            // Get next pair.
            let pair = nd.next_pair()?;

            // Check if its the end of the list.
            let pair = match pair {
                Some(v) => v,
                None => break,
            };

            if !known.contains(&pair.name) {
                // Name is unknown.
                return Err(VdevDecodeError::UnknownName {
                    name: pair.name.into(),
                    full_length: pair.name.len(),
                });
            }
        }

        ////////////////////////////////
        // Use macros for cleaner code.
        macro_rules! find_string {
            ($name:expr) => {
                nv::find_nested!(decoder, nested_decoder, $name, String, VdevDecodeError)?
            };
        }

        macro_rules! find_u64 {
            ($name:expr) => {
                nv::find_nested!(decoder, nested_decoder, $name, Uint64, VdevDecodeError)?
            };
        }

        macro_rules! find_u64_bool {
            ($name:expr) => {
                match find_u64!($name) {
                    0 => false,
                    1 => true,
                    n => {
                        return Err(VdevDecodeError::InvalidU64Bool {
                            name: $name,
                            value: n,
                        })
                    }
                }
            };
        }

        macro_rules! find_option_string {
            ($name:expr) => {
                nv::find_option_nested!(decoder, nested_decoder, $name, String, VdevDecodeError)?
            };
        }

        macro_rules! find_option_u64 {
            ($name:expr) => {
                nv::find_option_nested!(decoder, nested_decoder, $name, Uint64, VdevDecodeError)?
            };
        }

        macro_rules! find_option_u64_bool {
            ($name:expr) => {
                match nv::find_option_nested!(
                    decoder,
                    nested_decoder,
                    $name,
                    Uint64,
                    VdevDecodeError
                )? {
                    None => None,
                    Some(n) => match n {
                        0 => Some(false),
                        1 => Some(true),
                        _ => {
                            return Err(VdevDecodeError::InvalidU64Bool {
                                name: $name,
                                value: n,
                            })
                        }
                    },
                }
            };
        }

        ////////////////////////////////
        // Decode vdev.
        let disk = VdevDisk {
            path: find_string!(VDEV_CONFIG_PATH),
            whole_disk: find_u64_bool!(VDEV_CONFIG_WHOLE_DISK),

            a_meta_slab: VdevAlignmentMetaSlab::from_decoder(decoder, nested_decoder)?,
            create_txg: find_option_u64!(VDEV_CONFIG_CREATE_TXG),
            dev_id: find_option_string!(VDEV_CONFIG_DEV_ID),
            is_log: find_option_u64_bool!(VDEV_CONFIG_IS_LOG),
            phys_path: find_option_string!(VDEV_CONFIG_PHYS_PATH),
        };

        Ok(disk)
    }
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub enum Vdev<'a> {
    Disk(VdevDisk<'a>),
    File(),
    Mirror(),
    Missing(),
    RaidZ(),
    Replacing(),
    Root(),
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub struct VdevTree<'a> {
    pub id: u64,
    pub guid: u64,
    pub vdev: Vdev<'a>,
}

impl VdevTree<'_> {
    /** Decodes a [`VdevTree`] NV pair list.
     *
     * # Errors
     *
     * Returns [`VdevDecodeError`] in case of an error.
     */
    pub fn from_decoder<'a>(decoder: &'a nv::Decoder<'a>) -> Result<VdevTree<'a>, VdevDecodeError> {
        // TODO(cybojanek): Can find_nested be deprecated while fixing lifetimes?

        // Find vdev tree.
        let nested_decoder =
            &nv::find!(decoder, POOL_CONFIG_KEY_VDEV_TREE, NvList, VdevDecodeError)?;

        // Find vdev type.
        let vdev_type = nv::find_nested!(
            decoder,
            nested_decoder,
            VDEV_CONFIG_TYPE,
            String,
            VdevDecodeError
        )?;

        // Decode vdev.
        let vdev = match vdev_type {
            VDEV_TYPE_DISK => Vdev::Disk(VdevDisk::from_decoder(decoder, nested_decoder)?),
            VDEV_TYPE_FILE => todo!("Implement"),
            VDEV_TYPE_MIRROR => todo!("Implement"),
            VDEV_TYPE_MISSING => todo!("Implement"),
            VDEV_TYPE_RAIDZ => todo!("Implement"),
            VDEV_TYPE_REPLACING => todo!("Implement"),
            VDEV_TYPE_ROOT => todo!("Implement"),
            _ => {
                return Err(VdevDecodeError::UnknownType {
                    vdev_type: vdev_type.into(),
                    full_length: vdev_type.len(),
                })
            }
        };

        ////////////////////////////////
        // Use macros for cleaner code.
        macro_rules! find_u64 {
            ($name:expr) => {
                nv::find_nested!(decoder, nested_decoder, $name, Uint64, VdevDecodeError)?
            };
        }

        Ok(VdevTree {
            id: find_u64!(VDEV_CONFIG_ID),
            guid: find_u64!(VDEV_CONFIG_GUID),
            vdev: vdev,
        })
    }
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub enum VdevDecodeError {
    /** Invalid configuration.
     *
     * - `reason` - Reason for invalid configuration.
     */
    InvalidConfiguration { reason: &'static str },

    /** Invalid 64 bit unsigned integer boolean value.
     *
     * - `name`  - Of NV pair.
     * - `value` - Of NV pair.
     */
    InvalidU64Bool { name: &'static str, value: u64 },

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

    /** Unknown type error.
     *
     * - `vdev_type`   - Truncated string of unknown vdev_type.
     * - `full_length` - The full length of the unknown vdev_type.
     */
    UnknownType {
        vdev_type: str16,
        full_length: usize,
    },

    /** Value type mismatch.
     *
     * - `name`      - Of NV pair.
     * - `data_type` - Of NV pair.
     */
    ValueTypeMismatch {
        name: &'static str,
        data_type: nv::DataType,
    },
}

impl From<nv::DecodeError> for VdevDecodeError {
    fn from(value: nv::DecodeError) -> Self {
        VdevDecodeError::NvDecodeError { err: value }
    }
}

impl fmt::Display for VdevDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            VdevDecodeError::InvalidConfiguration { reason } => {
                write!(f, "Vdev decode error: invalid configuration: {reason}")
            }
            VdevDecodeError::InvalidU64Bool { name, value } => {
                write!(
                    f,
                    "Vdev decode error: invalid 64 bit unsigned boolean {value} for '{name}`"
                )
            }
            VdevDecodeError::MissingValue { name } => {
                write!(f, "Vdev decode error: missing '{name}'")
            }
            VdevDecodeError::NvDecodeError { err } => {
                write!(f, "Vdev Nv decode error: {err}")
            }
            VdevDecodeError::UnknownName { name, full_length } => {
                if *full_length > name.len() {
                    write!(
                        f,
                        "Vdev decode error: unknown name of length {full_length}: '{name}...'"
                    )
                } else {
                    write!(f, "Vdev decode error: unknown name: '{name}'")
                }
            }
            VdevDecodeError::UnknownType {
                vdev_type,
                full_length,
            } => {
                if *full_length > vdev_type.len() {
                    write!(
                        f,
                        "Vdev decode error: unknown vdev type of length {full_length}: '{vdev_type}...'"
                    )
                } else {
                    write!(f, "Vdev decode error: unknown vdev type: '{vdev_type}'")
                }
            }
            VdevDecodeError::ValueTypeMismatch { name, data_type } => {
                write!(
                    f,
                    "Vdev decode value type mismatch for '{name}' got {data_type}"
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for VdevDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            VdevDecodeError::NvDecodeError { err } => Some(err),
            _ => None,
        }
    }
}
