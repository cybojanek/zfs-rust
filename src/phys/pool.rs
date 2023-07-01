use core::fmt;
use core::result::Result;
use core::result::Result::{Err, Ok};

#[cfg(feature = "std")]
use std::error;

extern crate fixedstr;
extern crate num;
extern crate strum;

use fixedstr::{str16, str32};

use crate::nv;

////////////////////////////////////////////////////////////////////////////////

/** Pool version.
 *
 * - C reference: `SPA_VERSION`
 * - Historically, it was incremented when the format of data on disk changed.
 * - Since V5000, changes are indicated using [`PoolFeaturesForRead`].
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

////////////////////////////////////////////////////////////////////////////////

/** Pool state.
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

/** Pool health.
 *
 * Deprecated in V3.
 */
#[derive(Clone, Copy, Debug, strum::Display)]
pub enum PoolHealth {
    Degraded,
    Faulted,
    Online,
}

const POOL_HEALTH_DEGRADED: &str = "DEGRADED";
const POOL_HEALTH_FAULTED: &str = "FAULTED";
const POOL_HEALTH_ONLINE: &str = "ONLINE";

/** Gets the [`PoolHealth`] from the string.
 *
 * # Errors
 *
 * Returns [`PoolDecodeError::InvalidPoolHealth`] in case of an error.
 */
fn pool_health_from_str(string: &str) -> Result<PoolHealth, PoolDecodeError> {
    match string {
        POOL_HEALTH_DEGRADED => Ok(PoolHealth::Degraded),
        POOL_HEALTH_FAULTED => Ok(PoolHealth::Faulted),
        POOL_HEALTH_ONLINE => Ok(PoolHealth::Online),
        _ => Err(PoolDecodeError::InvalidPoolHealth {
            pool_health: string.into(),
            full_length: string.len(),
        }),
    }
}

////////////////////////////////////////////////////////////////////////////////

const POOL_FEATURE_FOR_READ_ALLOCATION_CLASSES: &str = "org.zfsonlinux:allocation_classes";
const POOL_FEATURE_FOR_READ_ASYNC_DESTROY: &str = "com.delphix:async_destroy";
const POOL_FEATURE_FOR_READ_BLAKE_3: &str = "org.openzfs:blake3";
const POOL_FEATURE_FOR_READ_BLOCK_CLONING: &str = "com.fudosecurity:block_cloning";
const POOL_FEATURE_FOR_READ_BOOKMARK_V2: &str = "com.datto:bookmark_v2";
const POOL_FEATURE_FOR_READ_BOOKMARK_WRITTEN: &str = "com.delphix:bookmark_written";
const POOL_FEATURE_FOR_READ_BOOKMARKS: &str = "com.delphix:bookmarks";
const POOL_FEATURE_FOR_READ_DEVICE_REBUILD: &str = "org.openzfs:device_rebuild";
const POOL_FEATURE_FOR_READ_DEVICE_REMOVAL: &str = "com.delphix:device_removal";
const POOL_FEATURE_FOR_READ_DRAID: &str = "org.openzfs:draid";
const POOL_FEATURE_FOR_READ_EDONR: &str = "org.illumos:edonr";
const POOL_FEATURE_FOR_READ_EMBEDDED_DATA: &str = "com.delphix:embedded_data";
const POOL_FEATURE_FOR_READ_EMPTY_BLOCK_POINTER_OBJECT: &str = "com.delphix:empty_bpobj";
const POOL_FEATURE_FOR_READ_ENABLED_TXG: &str = "com.delphix:enabled_txg";
const POOL_FEATURE_FOR_READ_ENCRYPTION: &str = "com.datto:encryption";
const POOL_FEATURE_FOR_READ_EXTENSIBLE_DATASET: &str = "com.delphix:extensible_dataset";
const POOL_FEATURE_FOR_READ_FILESYSTEM_LIMITS: &str = "com.joyent:filesystem_limits";
const POOL_FEATURE_FOR_READ_HEAD_ERROR_LOG: &str = "com.delphix:head_errlog";
const POOL_FEATURE_FOR_READ_HOLE_BIRTH: &str = "com.delphix:hole_birth";
const POOL_FEATURE_FOR_READ_LARGE_BLOCKS: &str = "org.open-zfs:large_blocks";
const POOL_FEATURE_FOR_READ_LARGE_DNODE: &str = "org.zfsonlinux:large_dnode";
const POOL_FEATURE_FOR_READ_LIVE_LIST: &str = "com.delphix:livelist";
const POOL_FEATURE_FOR_READ_LOG_SPACE_MAP: &str = "com.delphix:log_spacemap";
const POOL_FEATURE_FOR_READ_LZ4_COMPRESS: &str = "org.illumos:lz4_compress";
const POOL_FEATURE_FOR_READ_MULTI_VDEV_CRASH_DUMP: &str = "com.joyent:multi_vdev_crash_dump";
const POOL_FEATURE_FOR_READ_OBSOLETE_COUNTS: &str = "com.delphix:obsolete_counts";
const POOL_FEATURE_FOR_READ_PROJECT_QUOTA: &str = "org.zfsonlinux:project_quota";
const POOL_FEATURE_FOR_READ_REDACTED_DATASETS: &str = "com.delphix:redacted_datasets";
const POOL_FEATURE_FOR_READ_REDACTION_BOOKMARKS: &str = "com.delphix:redaction_bookmarks";
const POOL_FEATURE_FOR_READ_RESILVER_DEFER: &str = "com.datto:resilver_defer";
const POOL_FEATURE_FOR_READ_SHA_512: &str = "org.illumos:sha512";
const POOL_FEATURE_FOR_READ_SKEIN: &str = "org.illumos:skein";
const POOL_FEATURE_FOR_READ_SPACEMAP_HISTORGRAM: &str = "com.delphix:spacemap_histogram";
const POOL_FEATURE_FOR_READ_SPACEMAP_V2: &str = "com.delphix:spacemap_v2";
const POOL_FEATURE_FOR_READ_USER_OBJECT_ACCOUNTING: &str = "org.zfsonlinux:userobj_accounting";
const POOL_FEATURE_FOR_READ_ZIL_SA_XATTR: &str = "org.openzfs:zilsaxattr";
const POOL_FEATURE_FOR_READ_ZPOOL_CHECKPOINT: &str = "com.delphix:zpool_checkpoint";
const POOL_FEATURE_FOR_READ_ZSTD_COMPRESS: &str = "org.freebsd:zstd_compress";

/** Pool features.
 */
#[derive(Debug)]
pub struct PoolFeaturesForRead {
    pub allocation_classes: bool,
    pub async_destroy: bool,
    pub blake_3: bool,
    pub block_cloning: bool,
    pub bookmark_v2: bool,
    pub bookmark_written: bool,
    pub bookmarks: bool,
    pub device_rebuild: bool,
    pub device_removal: bool,
    pub draid: bool,
    pub edonr: bool,
    pub embedded_data: bool,
    pub empty_block_pointer_object: bool,
    pub enabled_txg: bool,
    pub encryption: bool,
    pub extensible_dataset: bool,
    pub filesystem_limits: bool,
    pub head_error_log: bool,
    pub hole_birth: bool,
    pub large_blocks: bool,
    pub large_dnode: bool,
    pub live_list: bool,
    pub log_space_map: bool,
    pub lz4_compress: bool,
    pub multi_vdev_crash_dump: bool,
    pub obsolete_counts: bool,
    pub project_quota: bool,
    pub redacted_datasets: bool,
    pub redaction_bookmarks: bool,
    pub resilver_defer: bool,
    pub sha_512: bool,
    pub skein: bool,
    pub spacemap_historgram: bool,
    pub spacemap_v2: bool,
    pub user_object_accounting: bool,
    pub zil_sa_xattr: bool,
    pub zpool_checkpoint: bool,
    pub zstd_compress: bool,
}

impl PoolFeaturesForRead {
    /** Decodes a [`PoolFeaturesForRead`] from the decoder.
     *
     * # Errors
     *
     * Returns [`PoolDecodeError`] in case of an error.
     */
    pub fn from_decoder(
        decoder: &nv::Decoder,
    ) -> Result<Option<PoolFeaturesForRead>, PoolDecodeError> {
        ////////////////////////////////
        // Find features_for_read.
        let feature_decoder = match nv::find_option!(
            decoder,
            POOL_CONFIG_FEATURES_FOR_READ,
            NvList,
            PoolDecodeError
        )? {
            Some(v) => v,
            None => return Ok(None),
        };

        ////////////////////////////////
        // Use macro for cleaner code.
        macro_rules! find {
            ($name:expr) => {
                nv::find_option_bool!(feature_decoder, $name, PoolDecodeError)?
            };
        }

        ////////////////////////////////
        // Loop through all the pairs, and check for unknown names.
        let known = [
            POOL_FEATURE_FOR_READ_ALLOCATION_CLASSES,
            POOL_FEATURE_FOR_READ_ASYNC_DESTROY,
            POOL_FEATURE_FOR_READ_BLAKE_3,
            POOL_FEATURE_FOR_READ_BLOCK_CLONING,
            POOL_FEATURE_FOR_READ_BOOKMARK_V2,
            POOL_FEATURE_FOR_READ_BOOKMARK_WRITTEN,
            POOL_FEATURE_FOR_READ_BOOKMARKS,
            POOL_FEATURE_FOR_READ_DEVICE_REBUILD,
            POOL_FEATURE_FOR_READ_DEVICE_REMOVAL,
            POOL_FEATURE_FOR_READ_DRAID,
            POOL_FEATURE_FOR_READ_EDONR,
            POOL_FEATURE_FOR_READ_EMBEDDED_DATA,
            POOL_FEATURE_FOR_READ_EMPTY_BLOCK_POINTER_OBJECT,
            POOL_FEATURE_FOR_READ_ENABLED_TXG,
            POOL_FEATURE_FOR_READ_ENCRYPTION,
            POOL_FEATURE_FOR_READ_EXTENSIBLE_DATASET,
            POOL_FEATURE_FOR_READ_FILESYSTEM_LIMITS,
            POOL_FEATURE_FOR_READ_HEAD_ERROR_LOG,
            POOL_FEATURE_FOR_READ_HOLE_BIRTH,
            POOL_FEATURE_FOR_READ_LARGE_BLOCKS,
            POOL_FEATURE_FOR_READ_LARGE_DNODE,
            POOL_FEATURE_FOR_READ_LIVE_LIST,
            POOL_FEATURE_FOR_READ_LOG_SPACE_MAP,
            POOL_FEATURE_FOR_READ_LZ4_COMPRESS,
            POOL_FEATURE_FOR_READ_MULTI_VDEV_CRASH_DUMP,
            POOL_FEATURE_FOR_READ_OBSOLETE_COUNTS,
            POOL_FEATURE_FOR_READ_PROJECT_QUOTA,
            POOL_FEATURE_FOR_READ_REDACTED_DATASETS,
            POOL_FEATURE_FOR_READ_REDACTION_BOOKMARKS,
            POOL_FEATURE_FOR_READ_RESILVER_DEFER,
            POOL_FEATURE_FOR_READ_SHA_512,
            POOL_FEATURE_FOR_READ_SKEIN,
            POOL_FEATURE_FOR_READ_SPACEMAP_HISTORGRAM,
            POOL_FEATURE_FOR_READ_SPACEMAP_V2,
            POOL_FEATURE_FOR_READ_USER_OBJECT_ACCOUNTING,
            POOL_FEATURE_FOR_READ_ZIL_SA_XATTR,
            POOL_FEATURE_FOR_READ_ZPOOL_CHECKPOINT,
            POOL_FEATURE_FOR_READ_ZSTD_COMPRESS,
        ];

        loop {
            // Get next pair.
            let pair = feature_decoder.next_pair()?;

            // Check if its the end of the list.
            let pair = match pair {
                Some(v) => v,
                None => break,
            };

            // Check if name is known.
            let feature = &pair.name;

            if !known.contains(feature) {
                // Feature is unknown.
                return Err(PoolDecodeError::UnknownFeature {
                    feature: feature.into(),
                    full_length: feature.len(),
                });
            }
        }

        ////////////////////////////////
        // Fill in all known features for read.
        Ok(Some(PoolFeaturesForRead {
            allocation_classes: find!(POOL_FEATURE_FOR_READ_ALLOCATION_CLASSES),
            async_destroy: find!(POOL_FEATURE_FOR_READ_ASYNC_DESTROY),
            blake_3: find!(POOL_FEATURE_FOR_READ_BLAKE_3),
            block_cloning: find!(POOL_FEATURE_FOR_READ_BLOCK_CLONING),
            bookmark_v2: find!(POOL_FEATURE_FOR_READ_BOOKMARK_V2),
            bookmark_written: find!(POOL_FEATURE_FOR_READ_BOOKMARK_WRITTEN),
            bookmarks: find!(POOL_FEATURE_FOR_READ_BOOKMARKS),
            device_rebuild: find!(POOL_FEATURE_FOR_READ_DEVICE_REBUILD),
            device_removal: find!(POOL_FEATURE_FOR_READ_DEVICE_REMOVAL),
            draid: find!(POOL_FEATURE_FOR_READ_DRAID),
            edonr: find!(POOL_FEATURE_FOR_READ_EDONR),
            embedded_data: find!(POOL_FEATURE_FOR_READ_EMBEDDED_DATA),
            empty_block_pointer_object: find!(POOL_FEATURE_FOR_READ_EMPTY_BLOCK_POINTER_OBJECT),
            enabled_txg: find!(POOL_FEATURE_FOR_READ_ENABLED_TXG),
            encryption: find!(POOL_FEATURE_FOR_READ_ENCRYPTION),
            extensible_dataset: find!(POOL_FEATURE_FOR_READ_EXTENSIBLE_DATASET),
            filesystem_limits: find!(POOL_FEATURE_FOR_READ_FILESYSTEM_LIMITS),
            head_error_log: find!(POOL_FEATURE_FOR_READ_HEAD_ERROR_LOG),
            hole_birth: find!(POOL_FEATURE_FOR_READ_HOLE_BIRTH),
            large_blocks: find!(POOL_FEATURE_FOR_READ_LARGE_BLOCKS),
            large_dnode: find!(POOL_FEATURE_FOR_READ_LARGE_DNODE),
            live_list: find!(POOL_FEATURE_FOR_READ_LIVE_LIST),
            log_space_map: find!(POOL_FEATURE_FOR_READ_LOG_SPACE_MAP),
            lz4_compress: find!(POOL_FEATURE_FOR_READ_LZ4_COMPRESS),
            multi_vdev_crash_dump: find!(POOL_FEATURE_FOR_READ_MULTI_VDEV_CRASH_DUMP),
            obsolete_counts: find!(POOL_FEATURE_FOR_READ_OBSOLETE_COUNTS),
            project_quota: find!(POOL_FEATURE_FOR_READ_PROJECT_QUOTA),
            redacted_datasets: find!(POOL_FEATURE_FOR_READ_REDACTED_DATASETS),
            redaction_bookmarks: find!(POOL_FEATURE_FOR_READ_REDACTION_BOOKMARKS),
            resilver_defer: find!(POOL_FEATURE_FOR_READ_RESILVER_DEFER),
            sha_512: find!(POOL_FEATURE_FOR_READ_SHA_512),
            skein: find!(POOL_FEATURE_FOR_READ_SKEIN),
            spacemap_historgram: find!(POOL_FEATURE_FOR_READ_SPACEMAP_HISTORGRAM),
            spacemap_v2: find!(POOL_FEATURE_FOR_READ_SPACEMAP_V2),
            user_object_accounting: find!(POOL_FEATURE_FOR_READ_USER_OBJECT_ACCOUNTING),
            zil_sa_xattr: find!(POOL_FEATURE_FOR_READ_ZIL_SA_XATTR),
            zpool_checkpoint: find!(POOL_FEATURE_FOR_READ_ZPOOL_CHECKPOINT),
            zstd_compress: find!(POOL_FEATURE_FOR_READ_ZSTD_COMPRESS),
        }))
    }
}

////////////////////////////////////////////////////////////////////////////////

/// Pool 'hostid' and 'hostname'.
#[derive(Debug)]
pub struct PoolHost<'a> {
    pub id: u64,
    pub name: &'a str,
}

impl PoolHost<'_> {
    /** Decodes a [`PoolHost`] from the decoder.
     *
     * # Errors
     *
     * Returns [`PoolDecodeError`] in case of an error.
     */
    pub fn from_decoder<'a>(
        decoder: &'a nv::Decoder<'a>,
    ) -> Result<Option<PoolHost<'a>>, PoolDecodeError> {
        // Find hostid.
        match nv::find_option!(decoder, POOL_CONFIG_HOST_ID, Uint64, PoolDecodeError)? {
            Some(host_id) => {
                // Check that if hostid is set, then so is hostname.
                let host_name = nv::find!(decoder, POOL_CONFIG_HOST_NAME, String, PoolDecodeError)?;
                Ok(Some(PoolHost {
                    id: host_id,
                    name: host_name,
                }))
            }
            None => {
                // Error if hostid is not set, but hostname is.
                let host_name =
                    nv::find_option!(decoder, POOL_CONFIG_HOST_NAME, String, PoolDecodeError)?;
                if !host_name.is_none() {
                    return Err(PoolDecodeError::InvalidConfiguration {
                        reason: "'hostname' is set, but 'hostid' is not",
                    });
                }
                Ok(None)
            }
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

// V1
const POOL_CONFIG_GUID: &str = "guid";
const POOL_CONFIG_NAME: &str = "name";
const POOL_CONFIG_POOL_GUID: &str = "pool_guid";
const POOL_CONFIG_STATE: &str = "state";
const POOL_CONFIG_TOP_GUID: &str = "top_guid";
const POOL_CONFIG_TXG: &str = "txg";
const POOL_CONFIG_VDEV_TREE: &str = "vdev_tree";
const POOL_CONFIG_VERSION: &str = "version";

// V1: Deprecated in V3.
const POOL_CONFIG_POOL_HEALTH: &str = "pool_health";

// V6
const POOL_CONFIG_HOST_ID: &str = "hostid";
const POOL_CONFIG_HOST_NAME: &str = "hostname";

// V19
const POOL_CONFIG_VDEV_CHILDREN: &str = "vdev_children";

// V5000
const POOL_CONFIG_ERRATA: &str = "errata";
const POOL_CONFIG_FEATURES_FOR_READ: &str = "features_for_read";

////////////////////////////////////////////////////////////////////////////////

/**
 * Pool configuration extracted from label NV pair list.
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

    // V1: Deprecated in V3.
    pub pool_health: Option<PoolHealth>,

    // V6
    pub host: Option<PoolHost<'a>>,

    // V19
    pub vdev_children: Option<u64>,

    // V5000
    pub errata: Option<u64>,
    pub features_for_read: Option<PoolFeaturesForRead>,
}

impl Pool<'_> {
    /** Decodes a [`Pool`] NV pair list.
     *
     * # Errors
     *
     * Returns [`PoolDecodeError`] in case of an error.
     */
    pub fn from_decoder<'a>(decoder: &'a nv::Decoder<'a>) -> Result<Pool<'a>, PoolDecodeError> {
        decoder.reset();

        ////////////////////////////////
        // Loop through all the pairs, and check for unknown names.
        let known = [
            // V1
            POOL_CONFIG_GUID,
            POOL_CONFIG_NAME,
            POOL_CONFIG_POOL_GUID,
            POOL_CONFIG_STATE,
            POOL_CONFIG_TOP_GUID,
            POOL_CONFIG_TXG,
            POOL_CONFIG_VDEV_TREE, // TODO(cybojanek): Implement.
            POOL_CONFIG_VERSION,
            // V1: Deprecated in V3.
            POOL_CONFIG_POOL_HEALTH,
            // V6
            POOL_CONFIG_HOST_ID,
            POOL_CONFIG_HOST_NAME,
            // V19
            POOL_CONFIG_VDEV_CHILDREN,
            // V5000
            POOL_CONFIG_ERRATA,
            POOL_CONFIG_FEATURES_FOR_READ,
        ];

        loop {
            // Get next pair.
            let pair = decoder.next_pair()?;

            // Check if its the end of the list.
            let pair = match pair {
                Some(v) => v,
                None => break,
            };

            if !known.contains(&pair.name) {
                // Name is unknown.
                return Err(PoolDecodeError::UnknownName {
                    name: pair.name.into(),
                    full_length: pair.name.len(),
                });
            }
        }

        ////////////////////////////////
        // Use macros for cleaner code.
        macro_rules! find_string {
            ($name:expr) => {
                nv::find!(decoder, $name, String, PoolDecodeError)?
            };
        }

        macro_rules! find_u64 {
            ($name:expr) => {
                nv::find!(decoder, $name, Uint64, PoolDecodeError)?
            };
        }

        macro_rules! find_option_string {
            ($name:expr) => {
                nv::find_option!(decoder, $name, String, PoolDecodeError)?
            };
        }

        macro_rules! find_option_u64 {
            ($name:expr) => {
                nv::find_option!(decoder, $name, Uint64, PoolDecodeError)?
            };
        }

        ////////////////////////////////
        // Success!
        Ok(Pool {
            // V1
            guid: find_u64!(POOL_CONFIG_GUID),
            name: find_string!(POOL_CONFIG_NAME),
            pool_guid: find_u64!(POOL_CONFIG_POOL_GUID),
            state: {
                let state_number = find_u64!(POOL_CONFIG_STATE);
                num::FromPrimitive::from_u64(state_number).ok_or(PoolDecodeError::InvalidState {
                    state: state_number,
                })?
            },
            top_guid: find_u64!(POOL_CONFIG_TOP_GUID),
            txg: find_u64!(POOL_CONFIG_TXG),
            version: {
                let version_number = find_u64!(POOL_CONFIG_VERSION);
                num::FromPrimitive::from_u64(version_number).ok_or(
                    PoolDecodeError::UnsupportedVersion {
                        version: version_number,
                    },
                )?
            },

            // V1: Deprecated in V3.
            pool_health: {
                let pool_health_opt = find_option_string!(POOL_CONFIG_POOL_HEALTH);
                match pool_health_opt {
                    Some(pool_health_str) => Some(pool_health_from_str(pool_health_str)?),
                    None => None,
                }
            },

            // V6
            host: PoolHost::from_decoder(decoder)?,

            // V19
            vdev_children: find_option_u64!(POOL_CONFIG_VDEV_CHILDREN),

            // V5000
            errata: find_option_u64!(POOL_CONFIG_ERRATA),
            features_for_read: PoolFeaturesForRead::from_decoder(decoder)?,
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

    /** Invalid pool health value.
     *
     * - `pool_health` - Truncated string of unknown pool health.
     * - `full_length` - The full length of the unknown pool health.
     */
    InvalidPoolHealth {
        pool_health: str16,
        full_length: usize,
    },

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

    /** Unknown feature error.
     *
     * - `feature`     - Truncated string of unknown feature.
     * - `full_length` - The full length of the unknown feature.
     */
    UnknownFeature { feature: str32, full_length: usize },

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
            PoolDecodeError::InvalidPoolHealth {
                pool_health,
                full_length,
            } => {
                if *full_length > pool_health.len() {
                    write!(
                        f,
                        "Pool decode error: invalid pool_health of length {full_length}: '{pool_health}...'"
                    )
                } else {
                    write!(f, "Pool decode error: invalid pool_health: '{pool_health}'")
                }
            }
            PoolDecodeError::InvalidState { state } => {
                write!(f, "Pool decode error: invalid 'state' {state}")
            }
            PoolDecodeError::MissingValue { name } => {
                write!(f, "Pool decode error: missing '{name}'")
            }
            PoolDecodeError::NvDecodeError { err } => {
                write!(f, "Pool NV decode error: {err}")
            }
            PoolDecodeError::UnknownFeature {
                feature,
                full_length,
            } => {
                if *full_length > feature.len() {
                    write!(
                        f,
                        "Pool decode error: unknown feature of length {full_length}: '{feature}...'"
                    )
                } else {
                    write!(f, "Pool decode error: unknown feature: '{feature}'")
                }
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
