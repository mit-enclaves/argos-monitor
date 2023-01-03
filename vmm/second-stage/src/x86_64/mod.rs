//! x86_64 backend for stage 2

mod arch;
mod vcpu;
pub mod guest;

use crate::debug::qemu::ExitCode;
use crate::hypercalls::access;
use crate::hypercalls::{Backend, Domain, ErrorCode, HypercallResult, Region, Registers};
use crate::println;
use core::arch::asm;
use mmu::eptmapper::EPT_ROOT_FLAGS;
use mmu::{EptMapper, FrameAllocator};
use stage_two_abi::Manifest;
use utils::{GuestPhysAddr, GuestVirtAddr, HostPhysAddr, HostVirtAddr};
use vmx::bitmaps::EptEntryFlags;
use vmx::{ControlRegister, Register};
use vtd::Iommu;

// ————————————————————————————— Configuration —————————————————————————————— //

/// Maximum number of CPU supported.
const MAX_NB_CPU: usize = 16;

// —————————————————————————————— x86_64 Arch ——————————————————————————————— //

pub struct Arch {
    iommu: Option<Iommu>,
}

pub struct Context {
    cr3: GuestPhysAddr,
    entry: GuestVirtAddr,
    stack: GuestVirtAddr,
}

pub struct Store {
    ept: HostPhysAddr,
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

    pub fn convert_to_ept(&self, rights: usize) -> EptEntryFlags {
        let mut def = EptEntryFlags::READ;
        if (rights & access::WRITE) != 0 {
            def |= EptEntryFlags::WRITE;
        }
        if (rights & access::EXEC) != 0 {
            def |= EptEntryFlags::USER_EXECUTE | EptEntryFlags::SUPERVISOR_EXECUTE;
        }
        if (rights & access::WRITE) != 0 {
            def |= EptEntryFlags::WRITE;
        }
        def
    }
}

impl Backend for Arch {
    type Vcpu<'a> = vcpu::X86Vcpu<'a, 'a>;

    type Store = Store;

    type Context = Context;

    const EMPTY_STORE: Self::Store = Store {
        ept: HostPhysAddr::new(0),
    };

    const EMPTY_CONTEXT: Self::Context = Context {
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
        rights: usize,
        allocator: &impl FrameAllocator,
    ) -> Result<(), ErrorCode> {
        let mut mapper = EptMapper::new(allocator.get_physical_offset().as_usize(), store.ept);
        let flags: EptEntryFlags = self.convert_to_ept(rights);
        mapper.map_range(
            allocator,
            GuestPhysAddr::new(region.start),
            HostPhysAddr::new(region.start),
            region.end - region.start,
            flags,
            //EptEntryFlags::READ | EptEntryFlags::WRITE | EptEntryFlags::USER_EXECUTE | EPT_PRESENT,
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

    fn domain_save<'a>(
        &mut self,
        context: &mut Self::Context,
        vcpu: &mut Self::Vcpu<'a>,
    ) -> Result<(), ErrorCode> {
        let active_vmcs = vcpu.active_vmcs.as_mut().unwrap();

        active_vmcs.next_instruction()
            .expect("Failed to advance instruction");
        context.cr3 = GuestPhysAddr::new(active_vmcs.get_cr(ControlRegister::Cr3));
        context.entry = GuestVirtAddr::new(active_vmcs.get(Register::Rip) as usize);
        context.stack = GuestVirtAddr::new(active_vmcs.get(Register::Rsp) as usize);
        Ok(())
    }

    fn domain_restore<'a>(
        &mut self,
        store: &Self::Store,
        context: &Self::Context,
        vcpu: &mut Self::Vcpu<'a>,
    ) -> Result<(), ErrorCode> {
        let active_vmcs = vcpu.active_vmcs.as_mut().unwrap();

        active_vmcs.set_ept_ptr(HostPhysAddr::new(store.ept.as_usize() | EPT_ROOT_FLAGS))
            .map_err(|_| ErrorCode::DomainSwitchFailed)?;
        active_vmcs.set_cr(ControlRegister::Cr3, context.cr3.as_usize());
        active_vmcs.set(Register::Rip, context.entry.as_u64());
        active_vmcs.set(Register::Rsp, context.stack.as_u64());
        Ok(())
    }

    fn domain_seal(
        &mut self,
        target: usize,
        current: &mut Domain<Self>,
        reg_1: usize,
        reg_2: usize,
        reg_3: usize,
    ) -> HypercallResult {
        let switch_handle = current.switches.allocate()?;
        let switch = &mut current.switches[switch_handle];
        switch.domain = target;
        switch.context.cr3 = GuestPhysAddr::new(reg_1);
        switch.context.entry = GuestVirtAddr::new(reg_2);
        switch.context.stack = GuestVirtAddr::new(reg_3);
        switch.is_valid = true;
        Ok(Registers {
            value_1: switch_handle.into(),
            ..Default::default()
        })
    }
}

/// Architecture specific initialization.
pub fn init(manifest: &Manifest, cpuid: usize) {
    unsafe {
        asm!(
            "mov cr3, {}",
            in(reg) manifest.cr3,
            options(nomem, nostack, preserves_flags)
        );
        if cpuid == 0 {
            arch::init();
        }
        arch::setup(cpuid);
    }

    // In case we use VGA, setup the VGA driver
    #[cfg(feature = "vga")]
    if manifest.vga.is_valid {
        let framebuffer =
            unsafe { core::slice::from_raw_parts_mut(manifest.vga.framebuffer, manifest.vga.len) };
        let writer = vga::Writer::new(
            framebuffer,
            manifest.vga.h_rez,
            manifest.vga.v_rez,
            manifest.vga.stride,
            manifest.vga.bytes_per_pixel,
        );
        vga::init_print(writer);
    }
}

pub fn cpuid() -> usize {
    let cpuid = unsafe { core::arch::x86_64::__cpuid(0x01) };
    ((cpuid.ebx & 0xffffffff) >> 24) as usize
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
