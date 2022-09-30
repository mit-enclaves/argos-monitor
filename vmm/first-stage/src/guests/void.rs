//! Empty guest
use stage_two_abi::GuestInfo;

use super::Guest;
use super::HandlerResult;
use crate::acpi::AcpiInfo;
use crate::mmu::MemoryMap;
use crate::vmx;
use mmu::FrameAllocator;

pub struct VoidGuest {}

pub const VOID_GUEST: VoidGuest = VoidGuest {};

impl Guest for VoidGuest {
    unsafe fn instantiate(
        &self,
        _acpi: &AcpiInfo,
        _host_allocator: &impl FrameAllocator,
        _guest_allocator: &impl FrameAllocator,
        _memory_map: MemoryMap,
    ) -> GuestInfo {
        GuestInfo::default_config()
    }

    unsafe fn vmcall_handler(
        &self,
        _vcpu: &mut vmx::ActiveVmcs,
    ) -> Result<HandlerResult, vmx::VmxError> {
        Ok(HandlerResult::Crash)
    }
}
