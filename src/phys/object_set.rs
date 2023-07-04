use core::fmt;
use core::result::Result;
use core::result::Result::{Err, Ok};

#[cfg(feature = "std")]
use std::error;

use crate::endian::{DecodeError, Decoder};
use crate::phys::{Dnode, DnodeDecodeError, ZilHeader, ZilHeaderDecodeError};

////////////////////////////////////////////////////////////////////////////////

/// User accounting complete flag for [`ObjectSet`] flags.
const FLAG_USER_ACCOUNTING_COMPLETE: u64 = 1 << 0;

/// User object accounting complete flag for [`ObjectSet`] flags.
const FLAG_USER_OBJECT_ACCOUNTING_COMPLETE: u64 = 1 << 1;

/// Project quota complete flag for [`ObjectSet`] flags.
const FLAG_PROJECT_QUOTA_COMPLETE: u64 = 1 << 2;

/// All flags for [`ObjectSet`] flags.
const FLAG_ALL: u64 = FLAG_USER_ACCOUNTING_COMPLETE
    | FLAG_USER_OBJECT_ACCOUNTING_COMPLETE
    | FLAG_PROJECT_QUOTA_COMPLETE;

/** Object set type.
 *
 * - C reference: `typedef enum dmu_objset_type dmu_objset_type_t`
 */
#[derive(Clone, Copy, Debug, FromPrimitive, strum::Display)]
pub enum ObjectSetType {
    None = 0,
    Meta,
    ZFS,
    ZVol,
    Other,
    Any,
    NumTypes,
}

/** Object set.
 *
 * - Bytes:
 *   - V1 - V14: 1024
 *   - V15 - V28: 2048
 *   - V5000: 4096
 * - C reference: `struct objset_phys objset_phys_t`
 *
 * ```text
 * vN: filesystem version
 *
 * +--------------+------+-------+
 * |      os_meta |  512 |    v1 |
 * +--------------+------+-------+
 * |   zil_header |  192 |    v1 |
 * +--------------+------+-------+
 * |         type |    8 |    v1 |
 * +--------------+------+-------+
 * |        flags |    8 |   v15 |
 * +--------------+------+-------+------------+
 * | portable_mac |   32 | v5000 | encryption |
 * +--------------+------+-------+------------+
 * |    local_mac |   32 | v5000 | encryption |
 * +--------------+------+-------+------------+
 * |      padding |  240 |    v1 |
 * +--------------+------+-------+
 * |    user_used |  512 |   v15 |
 * +--------------+------+-------+
 * |   group_used |  512 |   v15 |
 * +--------------+------+-------+---------------+
 * | project_used |  512 | v5000 | project quota |
 * +--------------+------+-------+---------------+
 * |      padding | 1536 | v5000 | project quota |
 * +--------------+------+-------+---------------+
 */
#[derive(Debug)]
pub struct ObjectSet {
    pub os_meta: Dnode,

    pub zil_header: ZilHeader,

    pub os_type: ObjectSetType,

    pub user_accounting_complete: bool,
    pub user_object_accounting_complete: bool,
    pub project_quota_complete: bool,

    pub portable_mac: [u8; ObjectSet::MAC_LEN],
    pub local_mac: [u8; ObjectSet::MAC_LEN],

    pub extension: ObjectSetExtension,
}

/** [`ObjectSet`] tail extensions.
 */
#[derive(Debug)]
pub enum ObjectSetExtension {
    None {},
    Two {
        user_used: Dnode,
        group_used: Dnode,
    },
    Three {
        user_used: Dnode,
        group_used: Dnode,
        project_used: Dnode,
    },
}

impl ObjectSet {
    /// Byte length of a encoded V1 [`ObjectSet`].
    pub const LENGTH_V1: usize =
        (Dnode::LENGTH + ZilHeader::LENGTH + 16 + ObjectSet::MAC_LEN * 2 + 240);

    /// Byte length of a encoded V2 [`ObjectSet`].
    pub const LENGTH_V2: usize = (ObjectSet::LENGTH_V1 + 2 * Dnode::LENGTH);

    /// Byte length of a encoded V3 [`ObjectSet`].
    pub const LENGTH_V3: usize = (ObjectSet::LENGTH_V2 + Dnode::LENGTH + 1536);

    /// Byte length of [`ObjectSet`] MAC.
    pub const MAC_LEN: usize = 32;

    /** Decodes an [`ObjectSet`].
     *
     * # Errors
     *
     * Returns [`DecodeError`] if there are not enough bytes, or magic is invalid.
     */
    pub fn from_decoder(decoder: &mut Decoder) -> Result<ObjectSet, ObjectSetDecodeError> {
        let os_meta = Dnode::from_decoder(decoder)?;
        let zil_header = ZilHeader::from_decoder(decoder)?;

        // Decode object set type.
        let os_type = decoder.get_u64()?;
        let os_type = match num::FromPrimitive::from_u64(os_type) {
            Some(os_type) => os_type,
            None => return Err(ObjectSetDecodeError::InvalidObjectSetType { os_type: os_type }),
        };

        // Decode flags.
        let flags = decoder.get_u64()?;
        if (flags & FLAG_ALL) != flags {
            return Err(ObjectSetDecodeError::InvalidFlags { flags: flags });
        }

        // Decode MACs.
        let portable_mac = decoder.get_bytes(ObjectSet::MAC_LEN)?.try_into().unwrap();
        let local_mac = decoder.get_bytes(ObjectSet::MAC_LEN)?.try_into().unwrap();

        // Padding up to LENGTH_V1.
        decoder.skip_zero_padding(240)?;

        // Check for extensions based on length.
        let mut extension = ObjectSetExtension::None {};

        if decoder.len() > 0 {
            let user_used = Dnode::from_decoder(decoder)?;
            let group_used = Dnode::from_decoder(decoder)?;

            if decoder.is_empty() {
                extension = ObjectSetExtension::Two {
                    user_used: user_used,
                    group_used: group_used,
                };
                // No padding for LENGTH_V2.
            } else {
                let project_used = Dnode::from_decoder(decoder)?;

                extension = ObjectSetExtension::Three {
                    user_used: user_used,
                    group_used: group_used,
                    project_used: project_used,
                };

                // Padding up to LENGTH_V3.
                decoder.skip_zero_padding(1536)?;
            }
        }

        Ok(ObjectSet {
            os_meta: os_meta,
            zil_header: zil_header,
            os_type: os_type,

            user_accounting_complete: (flags & FLAG_USER_ACCOUNTING_COMPLETE) != 0,
            user_object_accounting_complete: (flags & FLAG_USER_OBJECT_ACCOUNTING_COMPLETE) != 0,
            project_quota_complete: (flags & FLAG_PROJECT_QUOTA_COMPLETE) != 0,

            portable_mac: portable_mac,
            local_mac: local_mac,

            extension: extension,
        })
    }
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub enum ObjectSetDecodeError {
    /** [`Dnode`] decode error.
     *
     * - `err` - [`DnodeDecodeError`]
     */
    DnodeDecodeError { err: DnodeDecodeError },

    /** Endian decode error.
     *
     * - `err` - [`DecodeError`]
     */
    EndianDecodeError { err: DecodeError },

    /** Invalid flags.
     *
     * - `flags` - Flags.
     */
    InvalidFlags { flags: u64 },

    /** Invalid object set type.
     *
     * - `os_type` - Objecct set type.
     */
    InvalidObjectSetType { os_type: u64 },

    /** [`ZilHeader`] decode error.
     *
     * - `err` - [`ZilHeaderDecodeError`]
     */
    ZilHeaderDecodeError { err: ZilHeaderDecodeError },
}

impl From<DnodeDecodeError> for ObjectSetDecodeError {
    fn from(value: DnodeDecodeError) -> Self {
        ObjectSetDecodeError::DnodeDecodeError { err: value }
    }
}

impl From<DecodeError> for ObjectSetDecodeError {
    fn from(value: DecodeError) -> Self {
        ObjectSetDecodeError::EndianDecodeError { err: value }
    }
}

impl From<ZilHeaderDecodeError> for ObjectSetDecodeError {
    fn from(value: ZilHeaderDecodeError) -> Self {
        ObjectSetDecodeError::ZilHeaderDecodeError { err: value }
    }
}

impl fmt::Display for ObjectSetDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ObjectSetDecodeError::DnodeDecodeError { err } => {
                write!(f, "ObjectSet Dnode decode error: {err}")
            }
            ObjectSetDecodeError::EndianDecodeError { err } => {
                write!(f, "ObjectSet Endian decode error: {err}")
            }
            ObjectSetDecodeError::InvalidFlags { flags } => {
                write!(f, "ObjectSet invalid flags: {flags}")
            }
            ObjectSetDecodeError::InvalidObjectSetType { os_type } => {
                write!(f, "ObjectSet invalid type: {os_type}")
            }
            ObjectSetDecodeError::ZilHeaderDecodeError { err } => {
                write!(f, "ObjectSet Block Zil Header decode error: {err}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for ObjectSetDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            ObjectSetDecodeError::EndianDecodeError { err } => Some(err),
            _ => None,
        }
    }
}
