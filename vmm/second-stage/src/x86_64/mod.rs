//! x86_64 backend for stage 2

mod arch;
pub mod guest;

use crate::debug::ExitCode;
use crate::hypercalls::{Backend, ErrorCode, HypercallResult};
use crate::println;
use crate::statics;
use core::arch::asm;
use mmu::eptmapper::EPT_PRESENT;
use mmu::{EptMapper, FrameAllocator};
use stage_two_abi::Manifest;
use utils::{GuestPhysAddr, HostPhysAddr};
use vmx::bitmaps::EptEntryFlags;
use vmx::HostVirtAddr;
use vtd::Iommu;

pub struct Arch {
    iommu: Option<Iommu>,
}

impl Arch {
    pub fn new(iommu_addr: u64) -> Self {
        let iommu = if iommu_addr != 0 {
            unsafe { Some(Iommu::new(HostVirtAddr::new(iommu_addr as usize))) }
        } else {
            None
        };
        Self { iommu }
    }
}

impl Backend for Arch {
    fn debug_iommu(&mut self) -> HypercallResult {
        let iommu = match &mut self.iommu {
            Some(iommu) => iommu,
            None => {
                println!("Missing I/O MMU");
                return Err(ErrorCode::Failure);
            }
        };

        for fault in iommu.iter_fault() {
            println!(
                "I/O MMU fault:\n  addr:   0x{:x}\n  reason: 0x{:x}\n  record: {:?}",
                fault.addr,
                fault.record.reason(),
                fault.record
            );
        }

        Ok(Default::default())
    }

    fn identity_add(
        &mut self,
        allocator: &impl FrameAllocator,
        ept: usize,
        start: usize,
        end: usize,
    ) -> Result<(), vmx::VmxError> {
        let mut mapper = EptMapper::new(
            allocator.get_physical_offset().as_usize(),
            HostPhysAddr::new(ept),
        );
        mapper.map_range(
            allocator,
            GuestPhysAddr::new(start),
            HostPhysAddr::new(start),
            end - start,
            EptEntryFlags::READ | EptEntryFlags::WRITE | EptEntryFlags::USER_EXECUTE | EPT_PRESENT,
        );
        Ok(())
    }

    fn identity_remove(
        &mut self,
        allocator: &impl FrameAllocator,
        ept: usize,
        start: usize,
        end: usize,
    ) -> Result<(), vmx::VmxError> {
        let root = HostPhysAddr::new(ept);
        let offset = allocator.get_physical_offset();
        let mut mapper = EptMapper::new(offset.as_usize(), root);
        mapper.unmap_range(
            allocator,
            GuestPhysAddr::new(start),
            end - start,
            root,
            offset.as_usize(),
        );
        Ok(())
    }
}

/// Architecture specific initialization.
pub fn init(manifest: &Manifest<statics::Statics>) {
    unsafe {
        asm!(
            "mov cr3, {}",
            in(reg) manifest.cr3,
            options(nomem, nostack, preserves_flags)
        );
        arch::init();
    }
}

/// Halt the CPU in a spinloop;
pub fn hlt() -> ! {
    loop {
        unsafe { core::arch::x86_64::_mm_pause() };
    }
}

pub fn exit_qemu(exit_code: ExitCode) {
    const QEMU_EXIT_PORT: u16 = 0xf4;

    unsafe {
        let exit_code = exit_code as u32;
        asm!(
            "out dx, eax",
            in("dx") QEMU_EXIT_PORT,
            in("eax") exit_code,
            options(nomem, nostack, preserves_flags)
        );
    }
}
