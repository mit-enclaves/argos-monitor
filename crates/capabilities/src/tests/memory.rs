//! # Tests for the memory capabilities

use utils::HostPhysAddr;

use crate::access::AccessRights;
use crate::memory::{MemoryAccess, MemoryRegion, ALL_RIGHTS, NO_SHARE_USER};

#[test]
fn valid_subset_same() {
    let orig = MemoryAccess {
        start: HostPhysAddr::new(0),
        end: HostPhysAddr::new(1000),
        flags: ALL_RIGHTS,
    };
    let same = MemoryAccess {
        start: HostPhysAddr::new(0),
        end: HostPhysAddr::new(1000),
        flags: ALL_RIGHTS,
    };
    assert_eq!(orig.is_subset(&same), true);
}
#[test]
fn invalid_subset_share() {
    let orig = MemoryAccess {
        start: HostPhysAddr::new(500),
        end: HostPhysAddr::new(1000),
        flags: NO_SHARE_USER,
    };
    assert_eq!(orig.is_subset(&orig), false);
}
#[test]
fn valid_subset_left() {
    let orig = MemoryAccess {
        start: HostPhysAddr::new(0),
        end: HostPhysAddr::new(1000),
        flags: ALL_RIGHTS,
    };
    let same = MemoryAccess {
        start: HostPhysAddr::new(0),
        end: HostPhysAddr::new(500),
        flags: ALL_RIGHTS,
    };
    assert_eq!(orig.is_subset(&same), true);
}
#[test]
fn valid_subset_right() {
    let orig = MemoryAccess {
        start: HostPhysAddr::new(0),
        end: HostPhysAddr::new(1000),
        flags: ALL_RIGHTS,
    };
    let same = MemoryAccess {
        start: HostPhysAddr::new(500),
        end: HostPhysAddr::new(1000),
        flags: ALL_RIGHTS,
    };
    assert_eq!(orig.is_subset(&same), true);
}
#[test]
fn valid_subset_middle() {
    let orig = MemoryAccess {
        start: HostPhysAddr::new(0),
        end: HostPhysAddr::new(1000),
        flags: ALL_RIGHTS,
    };
    let same = MemoryAccess {
        start: HostPhysAddr::new(250),
        end: HostPhysAddr::new(750),
        flags: ALL_RIGHTS,
    };
    assert_eq!(orig.is_subset(&same), true);
}
#[test]
fn valid_subset_rights() {
    let orig = MemoryAccess {
        start: HostPhysAddr::new(0),
        end: HostPhysAddr::new(1000),
        flags: ALL_RIGHTS,
    };
    let same = MemoryAccess {
        start: HostPhysAddr::new(0),
        end: HostPhysAddr::new(500),
        flags: NO_SHARE_USER,
    };
    assert_eq!(orig.is_subset(&same), true);
}
#[test]
fn valid_subset_rights2() {
    let orig = MemoryAccess {
        start: HostPhysAddr::new(0),
        end: HostPhysAddr::new(1000),
        flags: ALL_RIGHTS,
    };
    let same = MemoryAccess {
        start: HostPhysAddr::new(500),
        end: HostPhysAddr::new(1000),
        flags: NO_SHARE_USER,
    };
    assert_eq!(orig.is_subset(&same), true);
}
#[test]
fn non_valid_overlap() {
    let overl = MemoryRegion::overlap(
        HostPhysAddr::new(0),
        HostPhysAddr::new(500),
        HostPhysAddr::new(500),
        HostPhysAddr::new(1000),
    );
    assert_eq!(overl, false);
}

#[test]
fn valid_null() {
    let access = MemoryAccess {
        start: HostPhysAddr::new(0),
        end: HostPhysAddr::new(1000),
        flags: ALL_RIGHTS,
    };
    assert_eq!(access.is_subset(&MemoryAccess::get_null()), true);
}
