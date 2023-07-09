use core::convert::TryFrom;
use core::fmt;
use core::result::Result;

#[cfg(feature = "std")]
use std::error;

extern crate num;
extern crate strum;

////////////////////////////////////////////////////////////////////////////////

/** DMU type.
 *
 * - C reference: `enum dmu_object_type`
 */
#[derive(Clone, Copy, Debug, FromPrimitive, strum::Display)]
pub enum DmuType {
    None = 0,
    ObjectDirectory,
    ObjectArray,
    PackedNvList,
    PackedNvListSize,
    BpObject,
    BpObjectHeader,
    SpaceMapHeader,
    SpaceMap,
    IntentLog,
    Dnode,
    ObjectSet,
    DslDirectory,
    DslDirectoryChildMap,
    DslDsSnapshotMap,
    DslProperties,
    DslDataSet,
    Znode,
    OldAcl,
    PlainFileContents,
    DirectoryContents,
    MasterNode,
    UnlinkedSet,
    Zvol,
    ZvolProperty,
    PlainOther,
    Uint64Other,
    ZapOther,
    ErrorLog,
    SpaHistory,
    SpaHistoryOffsets,
    PoolProperties,
    DslPermissions,
    Acl,
    SysAcl,
    Fuid,
    FuidSize,
    NextClones,
    ScanQueue,
    UserGroupUsed,
    UserGroupQuota,
    UserRefs,
    DdtZap,
    DdtStats,
    SysAttr,
    SysAttrMasterNode,
    SysAttrRegistration,
    SysAttrLayouts,
    ScanXlate,
    Dedup,
    DeadList,
    DeadListHeader,
    Clones,
    BpObjectSubObject,
}

////////////////////////////////////////////////////////////////////////////////

impl Into<u8> for DmuType {
    fn into(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for DmuType {
    type Error = DmuTypeError;

    fn try_from(dmu: u8) -> Result<Self, Self::Error> {
        num::FromPrimitive::from_u8(dmu).ok_or(DmuTypeError::InvalidValue { value: dmu })
    }
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub enum DmuTypeError {
    /** Invalid dmu type value.
     *
     * - `value` - Invalid value.
     */
    InvalidValue { value: u8 },
}

impl fmt::Display for DmuTypeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DmuTypeError::InvalidValue { value } => {
                write!(f, "Checksum Type error: invalid value: {value}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for DmuTypeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}
