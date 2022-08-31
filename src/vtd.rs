//! Intel VT-d

use bitflags::bitflags;

use crate::vmx::HostVirtAddr;
use core::ptr;

/// A device identifier, in the form bus:device.function (BDF).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct DeviceId {
    bus: u8,
    dev_fun: u8,
}

// ———————————————————————————————— I/O MMU ————————————————————————————————— //

/// An helper for accessing I/O MMU configuration.
pub struct Iommu {
    addr: *mut u8,
}

macro_rules! ro_reg {
    ($t:ty, $addr:expr, $get:ident) => {
        pub fn $get(&self) -> $t {
            unsafe { ptr::read_volatile(self.addr.offset($addr) as *mut $t) }
        }
    };

    ($t:ty, $addr:expr, $get:ident, $bitflag:ident) => {
        pub fn $get(&self) -> $bitflag {
            unsafe {
                let raw = ptr::read_volatile(self.addr.offset($addr) as *mut $t);
                $bitflag::from_bits_unchecked(raw)
            }
        }
    };
}

macro_rules! wo_reg {
    ($t:ty, $addr:expr, $set:ident) => {
        pub fn $set(&self, val: $t) {
            unsafe { ptr::write_volatile(self.addr.offset($addr) as *mut $t, val) }
        }
    };
}

macro_rules! rw_reg {
    ($t:ty, $addr:expr, $get:ident, $set:ident) => {
        ro_reg!($t, $addr, $get);
        wo_reg!($t, $addr, $set);
    };
}

impl Iommu {
    pub unsafe fn new(addr: HostVirtAddr) -> Self {
        Self {
            addr: addr.as_usize() as *mut u8,
        }
    }

    ro_reg!(u32, 0x000, get_version);
    ro_reg!(u64, 0x008, get_capability, Capability);
    ro_reg!(u64, 0x010, get_extended_capability, ExtendedCapability);
    wo_reg!(u32, 0x018, set_global_command);
    ro_reg!(u32, 0x01C, get_global_status);
    rw_reg!(u64, 0x020, get_root_table_addr, set_root_table_addr);
    rw_reg!(u64, 0x028, get_context_command, set_context_command);
    rw_reg!(u32, 0x034, get_fault_status, set_fault_status);
    rw_reg!(u32, 0x038, get_fault_event_control, set_fault_event_control);
    rw_reg!(u32, 0x03C, get_fault_event_data, set_fault_event_data);
    rw_reg!(u32, 0x040, get_fault_event_addr, set_fault_event_addr);
    rw_reg!(
        u32,
        0x044,
        get_fault_event_upper_addr,
        set_fault_event_upper_addr
    );
    // TODO: u128, fault recording register
    rw_reg!(
        u32,
        0x064,
        get_protect_memory_enable,
        set_protect_memory_enable
    );
    rw_reg!(
        u32,
        0x068,
        get_protect_low_memory_base,
        set_protect_low_memory_base
    );
    rw_reg!(
        u32,
        0x06C,
        get_protect_low_memory_limit,
        set_protect_low_memory_limit
    );
    rw_reg!(
        u64,
        0x070,
        get_protect_high_memory_base,
        set_protect_high_memory_base
    );
    rw_reg!(
        u64,
        0x078,
        get_protect_high_memory_limit,
        set_protect_high_memory_limit
    );
    rw_reg!(
        u64,
        0x0B8,
        get_interrupt_remapping_table_addr,
        set_interrupt_remapping_table_addr
    );
    ro_reg!(u64, 0x100, get_mttr_capability);
}

bitflags! {
    pub struct Capability: u64 {
        /// Number of domains supported
        const NB_DOMAINS              = 0b111;
        /// Require write buffer flushing.
        const WRITE_BUFFER_FLUSH      = 1 << 4;
        const PROTECTED_LOW_MEMORY    = 1 << 5;
        const PROTECTED_HIGH_MEMORY   = 1 << 6;
        const CACHING_MODE            = 1 << 7;
        const SUPPORTED_GUEST_WIDTH   = 0b11111  << 8;
        const MAXIMUM_GUEST_WIDTH     = 0b111111 << 16;
        const ZERO_LENGTH_READ        = 1 << 22;
        const FAULT_RECORDING_REG     = 0b1111111111 << 24;
        const S_STAGE_LARGE_PAGE      = 0b1111 << 34;
        const PAGE_SELECTIVE_INVAL    = 1 << 39;
        const NB_FAULT_RECORDING_REG  = 0b11111111 << 40;
        const MAX_ADDR_MASK_VALUE     = 0b111111 << 48;
        const WRITE_DRAINING          = 1 << 54;
        const READ_DRAINING           = 1 << 55;
        const F_STAGE_1GB             = 1 << 56;
        const POSTED_INTERRUPT        = 1 << 59;
        const F_STAGE_5LVL            = 1 << 60;
        const ENHANCED_CMD_SUPPORT    = 1 << 61;
        const ENHANCED_SET8INT_REMAP  = 1 << 62;
        const ENHANCED_SET8ROOT_TABLE = 1 << 63;
    }

    pub struct ExtendedCapability: u64 {
        const PAGE_WALK_COHERENCY       = 1 << 0;
        const QUEUED_INVALIDATION       = 1 << 1;
        const DEVICE_TLB_SUPPORT        = 1 << 2;
        const INT_REMAP_SUPPORT         = 1 << 3;
        const EXTENDED_INT_MODE         = 1 << 4;
        const PASS_THROUGH              = 1 << 6;
        const SNOOP_CONTROL             = 1 << 7;
        const IOTLB_REG_OFFSET          = 0b1111111111 << 8;
        const MAX_HANDLE_MASK_VAL       = 0b1111 << 20;
        const MEMORY_TYPE_SUPPORT       = 1 << 25;
        const NESTED_TRANSLATION        = 1 << 26;
        const PAGE_REQUEST              = 1 << 29;
        const EXECUTE_REQUEST           = 1 << 30;
        const SUPERVISOR_REQUEST        = 1 << 31;
        const NO_WRITE_FLAG             = 1 << 33;
        const EXTENDED_ACCESS_FLAG      = 1 << 34;
        const PROCESS_ASID_SIZE         = 0b11111 << 35;
        const PROCESS_ASID              = 1 << 40;
        const DEVICE_TLB_INVAL_THROTTLE = 1 << 41;
        const PAGE_REQUEST_DRAIN        = 1 << 42;
        const SCALABLE_MODE_SUPPORT     = 1 << 43;
        const VIRTUAL_CMD_SUPPORT       = 1 << 44;
        const S_STAGE_ACCESS_DIRTY      = 1 << 45;
        const S_STAHE_TRANSLATION       = 1 << 46;
        const SCALABLE_MODE_COHERENCY   = 1 << 48;
        const RID_PASID                 = 1 << 49;
        const PERF_MONITORING           = 1 << 51;
        const ABORT_DMA_MODE            = 1 << 52;
        const RID_PRIV                  = 1 << 53;
        const STOP_MARKER_SUPPORT       = 1 << 58;
    }
}
