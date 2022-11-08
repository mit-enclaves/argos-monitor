//! x86_64 backend for stage 2

mod arch;
pub mod guest;

use crate::debug::ExitCode;
use crate::hypercalls::{Backend, ErrorCode, HypercallResult, Region, Registers};
use crate::println;
use crate::statics;
use core::arch::asm;
use mmu::eptmapper::{EPT_PRESENT, EPT_ROOT_FLAGS};
use mmu::{EptMapper, FrameAllocator};
use stage_two_abi::Manifest;
use utils::{GuestPhysAddr, HostPhysAddr, HostVirtAddr};
use vmx::bitmaps::EptEntryFlags;
use vmx::{ActiveVmcs, ControlRegister, Register};
use vtd::Iommu;

pub struct Arch {
    iommu: Option<Iommu>,
}

pub struct Store {
    ept: HostPhysAddr,
    cr3: GuestPhysAddr,
    entry: GuestPhysAddr,
    stack: GuestPhysAddr,
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
    type Vcpu<'a> = ActiveVmcs<'a, 'a>;

    type Store = Store;

    const EMPTY_STORE: Self::Store = Store {
        ept: HostPhysAddr::new(0),
        cr3: GuestPhysAddr::new(0),
        entry: GuestPhysAddr::new(0),
        stack: GuestPhysAddr::new(0),
    };

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

    fn add_region(
        &mut self,
        store: &mut Store,
        region: &Region,
        allocator: &impl FrameAllocator,
    ) -> Result<(), ErrorCode> {
        let mut mapper = EptMapper::new(allocator.get_physical_offset().as_usize(), store.ept);
        mapper.map_range(
            allocator,
            GuestPhysAddr::new(region.start),
            HostPhysAddr::new(region.start),
            region.end - region.start,
            EptEntryFlags::READ | EptEntryFlags::WRITE | EptEntryFlags::USER_EXECUTE | EPT_PRESENT,
        );
        Ok(())
    }

    fn remove_region(
        &mut self,
        store: &mut Store,
        region: &Region,
        allocator: &impl FrameAllocator,
    ) -> Result<(), ErrorCode> {
        let root = store.ept;
        let offset = allocator.get_physical_offset();
        let mut mapper = EptMapper::new(offset.as_usize(), root);
        mapper.unmap_range(
            allocator,
            GuestPhysAddr::new(region.start),
            region.end - region.start,
            root,
            allocator.get_physical_offset().as_usize(),
        );
        Ok(())
    }

    fn domain_create(
        &mut self,
        store: &mut Store,
        allocator: &impl FrameAllocator,
    ) -> Result<(), ErrorCode> {
        let ept = allocator.allocate_frame().ok_or(ErrorCode::OutOfMemory)?;
        store.ept = ept.phys_addr;
        Ok(())
    }

    fn domain_switch<'a>(&mut self, store: &Store, vcpu: &mut Self::Vcpu<'a>) -> HypercallResult {
        vcpu.set_cr(ControlRegister::Cr3, store.cr3.as_usize());
        vcpu.set(Register::Rip, store.entry.as_u64());
        vcpu.set(Register::Rsp, store.stack.as_u64());
        vcpu.set_ept_ptr(HostPhysAddr::new(store.ept.as_usize() | EPT_ROOT_FLAGS))
            .map_err(|_| ErrorCode::DomainSwitchFailed)?;
        Ok(Registers::default())
    }

    fn domain_seal(
        &mut self,
        store: &mut Self::Store,
        reg_1: usize,
        reg_2: usize,
        reg_3: usize,
    ) -> Result<(), ErrorCode> {
        store.cr3 = GuestPhysAddr::new(reg_1);
        store.entry = GuestPhysAddr::new(reg_2);
        store.stack = GuestPhysAddr::new(reg_3);
        Ok(())
    }
}

/// Architecture specific initialization.
pub fn init(manifest: &Manifest<statics::Statics<Arch>>) {
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
