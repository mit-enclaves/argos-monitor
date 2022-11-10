//! x86_64 backend for stage 2

mod arch;
pub mod guest;

use crate::debug::ExitCode;
use crate::hypercalls::Domain;
use crate::hypercalls::{Backend, ErrorCode, HypercallResult, Region, Registers};
use crate::println;
use crate::statics::{self};
use core::arch::asm;
use mmu::eptmapper::{EPT_PRESENT, EPT_ROOT_FLAGS};
use mmu::{EptMapper, FrameAllocator};
use stage_two_abi::Manifest;
use utils::{GuestPhysAddr, GuestVirtAddr, HostPhysAddr, HostVirtAddr};
use vmx::bitmaps::EptEntryFlags;
use vmx::{ActiveVmcs, ControlRegister, Register};
use vtd::Iommu;

pub struct Arch {
    iommu: Option<Iommu>,
}

pub struct Store {
    ept: HostPhysAddr,
    cr3: GuestPhysAddr,
    entry: GuestVirtAddr,
    stack: GuestVirtAddr,
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
        entry: GuestVirtAddr::new(0),
        stack: GuestVirtAddr::new(0),
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
        let ept = allocator
            .allocate_frame()
            .ok_or(ErrorCode::OutOfMemory)?
            .zeroed();
        store.ept = ept.phys_addr;
        Ok(())
    }

    fn domain_switch<'a>(
        &mut self,
        caller: usize,
        domain: &mut Domain<Self>,
        vcpu: &mut Self::Vcpu<'a>,
    ) -> HypercallResult {
        // Capture the passed argument and forward it in the result.
        let args = vcpu.get(Register::Rdx);
        let switch_handle = domain.switches.allocate()?;
        let switch = &mut domain.switches[switch_handle];
        switch.domain = caller;
        switch.store.ept = HostPhysAddr::new(0);
        switch.store.cr3 = GuestPhysAddr::new(vcpu.get_cr(ControlRegister::Cr3));
        switch.store.stack = GuestVirtAddr::new(vcpu.get(Register::Rsp) as usize);
        switch.store.entry = GuestVirtAddr::new(vcpu.get(Register::Rip) as usize);
        switch.is_valid = true;
        vcpu.set_cr(ControlRegister::Cr3, domain.store.cr3.as_usize());
        vcpu.set(Register::Rip, domain.store.entry.as_u64());
        vcpu.set(Register::Rsp, domain.store.stack.as_u64());
        vcpu.set_ept_ptr(HostPhysAddr::new(
            domain.store.ept.as_usize() | EPT_ROOT_FLAGS,
        ))
        .map_err(|_| ErrorCode::DomainSwitchFailed)?;
        Ok(Registers {
            value_1: switch_handle.into(),
            value_2: args as usize,
            value_3: 0,
            value_4: 0,
            next_instr: false,
        })
    }

    fn domain_return<'a>(
        &mut self,
        store: &Self::Store,
        switch: &crate::hypercalls::Switch<Self>,
        vcpu: &mut Self::Vcpu<'a>,
    ) -> HypercallResult {
        vcpu.set_ept_ptr(HostPhysAddr::new(store.ept.as_usize() | EPT_ROOT_FLAGS))
            .map_err(|_| ErrorCode::DomainSwitchFailed)?;
        vcpu.set(Register::Rip, switch.store.entry.as_u64());
        vcpu.set(Register::Rsp, switch.store.stack.as_u64());
        vcpu.set_cr(ControlRegister::Cr3, switch.store.cr3.as_usize());
        //TODO pass results in registers.
        Ok(Default::default())
    }

    fn domain_seal(
        &mut self,
        store: &mut Self::Store,
        reg_1: usize,
        reg_2: usize,
        reg_3: usize,
    ) -> Result<(), ErrorCode> {
        store.cr3 = GuestPhysAddr::new(reg_1);
        store.entry = GuestVirtAddr::new(reg_2);
        store.stack = GuestVirtAddr::new(reg_3);
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
