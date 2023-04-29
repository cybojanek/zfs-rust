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

impl DmuType {
    /** Converts a [`u8`] to a [`DmuType`], returning `None` if unknown. */
    pub fn from_u8(dmu: u8) -> Option<DmuType> {
        num::FromPrimitive::from_u8(dmu)
    }
}
