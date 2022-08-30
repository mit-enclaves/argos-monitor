//! Intel VT-d

use crate::vmx::HostVirtAddr;
use core::ptr;

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
    ro_reg!(u64, 0x008, get_capability);
    ro_reg!(u64, 0x010, get_extended_capability);
    wo_reg!(u32, 0x018, set_global_command);
    ro_reg!(u32, 0x01C, get_global_status);
    rw_reg!(u64, 0x020, get_root_table_addr, set_root_table_addr);
    rw_reg!(u64, 0x028, get_context_command, set_context_command);
    rw_reg!(u32, 0x034, get_fault_status, set_fault_status);
    rw_reg!(u32, 0x038, get_fault_event_control, set_fault_event_control);
    rw_reg!(u32, 0x03C, get_fault_event_data, set_fault_event_data);
    rw_reg!(u32, 0x040, get_fault_event_addr, set_fault_event_addr);
    rw_reg!(u32, 0x044, get_fault_event_upper_addr, set_fault_event_upper_addr);
    // TODO: u128, fault recording register
    rw_reg!(u32, 0x064, get_protect_memory_enable, set_protect_memory_enable);
    rw_reg!(u32, 0x068, get_protect_low_memory_base, set_protect_low_memory_base);
    rw_reg!(u32, 0x06C, get_protect_low_memory_limit, set_protect_low_memory_limit);
    rw_reg!(u64, 0x070, get_protect_high_memory_base, set_protect_high_memory_base);
    rw_reg!(u64, 0x078, get_protect_high_memory_limit, set_protect_high_memory_limit);
    rw_reg!(u64, 0x0B8, get_interrupt_remapping_table_addr, set_interrupt_remapping_table_addr);
    ro_reg!(u64, 0x100, get_mttr_capability);
}
