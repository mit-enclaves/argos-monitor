#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(kernel::test_runner)]
#![reexport_test_harness_main = "test_main"]

use core::arch::asm;
use core::panic::PanicInfo;

use kernel::memory::SharedFrameAllocator;
use kernel::println;
use kernel::qemu;
use kernel::vmx;
use kernel::vmx::bitmaps::{
    EntryControls, EptEntryFlags, ExceptionBitmap, ExitControls, PinbasedControls, PrimaryControls,
    SecondaryControls, VmFuncControls,
};
use kernel::vmx::ept;
use kernel::vmx::fields;
use kernel::vmx::FrameAllocator;

use bootloader::{entry_point, BootInfo};
use kernel::vmx::fields::traits::*;
use x86_64::registers::control::{Cr0, Cr0Flags};
use x86_64::registers::model_specific::Efer;
use x86_64::VirtAddr;

use kernel::guests::rawc;

entry_point!(kernel_main);

fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    // Initialize display, if any
    if let Some(buffer) = boot_info.framebuffer.as_mut().take() {
        kernel::init_display(buffer);
    }
    println!("=========== Start QEMU ===========");

    // Initialize kernel structures
    kernel::init();

    // Run tests and exit in test configuration
    #[cfg(test)]
    {
        test_main();
    }

    // Initialize memory management
    let physical_memory_offset = VirtAddr::new(
        boot_info
            .physical_memory_offset
            .into_option()
            .expect("The bootloader must be configured with 'map-physical-memory'"),
    );

    let vma_allocator = unsafe {
        kernel::init_memory(physical_memory_offset, &mut boot_info.memory_regions)
            .expect("Failed to initialize memory")
    };

    if true {
        unsafe {
            create_rawc(physical_memory_offset.as_u64(), &vma_allocator);
        }
        kernel::qemu::exit(kernel::qemu::ExitCode::Success);
    }
    // Start doing VMX things
    unsafe {
        initialize_cpu();
        println!("VMX:    {:?}", vmx::vmx_available());
        println!("EPT:    {:?}", vmx::ept_capabilities());
        println!("VMFunc: {:?}", vmx::available_vmfuncs());
        println!("VMXON:  {:?}", vmx::vmxon(&vma_allocator));

        let mut vmcs = match vmx::VmcsRegion::new(&vma_allocator) {
            Err(err) => {
                println!("VMCS:   Err({:?})", err);
                qemu::exit(qemu::ExitCode::Failure);
            }
            Ok(vmcs) => {
                println!("VMCS:   Ok(())");
                vmcs
            }
        };

        println!("LOAD:   {:?}", vmcs.set_as_active());
        let err = vmcs
            .set_pin_based_ctrls(PinbasedControls::empty())
            .and_then(|_| {
                vmcs.set_vm_exit_ctrls(
                    ExitControls::HOST_ADDRESS_SPACE_SIZE
                        | ExitControls::LOAD_IA32_EFER
                        | ExitControls::SAVE_IA32_EFER,
                )
            })
            .and_then(|_| {
                vmcs.set_vm_entry_ctrls(
                    EntryControls::IA32E_MODE_GUEST | EntryControls::LOAD_IA32_EFER,
                )
            })
            .and_then(|_| vmcs.set_exception_bitmap(ExceptionBitmap::empty()))
            .and_then(|_| vmcs.save_host_state())
            .and_then(|_| setup_guest(&mut vmcs.vcpu));
        println!("Config: {:?}", err);
        println!("MSRs:   {:?}", configure_msr());

        let switching = vmx::available_vmfuncs().is_ok();
        println!(
            "1'Ctrl: {:?}",
            vmcs.set_primary_ctrls(PrimaryControls::SECONDARY_CONTROLS)
        );
        println!("Switching: {}", switching);
        let mut secondary_ctrls = SecondaryControls::ENABLE_RDTSCP | SecondaryControls::ENABLE_EPT;
        if switching {
            secondary_ctrls |= SecondaryControls::ENABLE_VM_FUNCTIONS
        }
        println!("2'Ctrl: {:?}", vmcs.set_secondary_ctrls(secondary_ctrls));
        let ept_mapper =
            setup_ept(physical_memory_offset, &vma_allocator).expect("Failed to setupt EPT 1");
        println!("EPTP:   {:?}", vmcs.set_ept_ptr(&ept_mapper));

        // Let's see if we can duplicate the EPTs, and register them both
        if switching {
            let ept_mapper2 =
                setup_ept(physical_memory_offset, &vma_allocator).expect("Failed to setup EPT 2");
            println!("EPT2:   {:?}", vmcs.set_ept_ptr(&ept_mapper2));
            let mut eptp_list =
                ept::EptpList::new(&vma_allocator).expect("Failed to allocate EPTP list");
            eptp_list.set_entry(0, &ept_mapper);
            eptp_list.set_entry(1, &ept_mapper2);
            println!("EPTP L: {:?}", vmcs.set_eptp_list(&eptp_list));
            println!(
                "Enable vmfunc: {:?}",
                vmcs.set_vmfunc_ctrls(VmFuncControls::EPTP_SWITCHING)
            );
        }

        println!("Check:  {:?}", vmx::check::check());
        println!("Launch: {:?}", launch_guest(&mut vmcs, switching));
        println!("Info:   {:?}", vmcs.vcpu.interrupt_info());
        println!(
            "Qualif: {:?}",
            vmcs.vcpu
                .exit_qualification()
                .map(|qualif| qualif.ept_violation())
        );
        println!("VMXOFF: {:?}", vmx::raw::vmxoff());
    }
    kernel::qemu::exit(kernel::qemu::ExitCode::Success);
}

fn initialize_cpu() {
    // Set CPU in a valid state for VMX operations.
    let cr0 = Cr0::read();
    unsafe { Cr0::write(cr0 | Cr0Flags::NUMERIC_ERROR) };
}

fn setup_ept(
    physical_memory_offset: VirtAddr,
    allocator: &SharedFrameAllocator,
) -> Result<vmx::ept::ExtendedPageTableMapper<impl vmx::ept::Mapper>, ()> {
    let translator = move |addr: vmx::HostPhysAddr| {
        vmx::HostVirtAddr::new(physical_memory_offset.as_u64() as usize + addr.as_usize())
    };
    let host_address_translator = unsafe { ept::HostAddressMapper::new(translator) };
    let mut ept_mapper = ept::ExtendedPageTableMapper::new(allocator, host_address_translator)
        .expect("Failed to build EPT mapper");
    let (start, end) = allocator.get_boundaries();
    let capabilities = vmx::ept_capabilities().map_err(|_| ())?;

    // Just common checks on the boundaries.
    assert!(start % 0x1000 == 0);
    assert!(end % 0x1000 == 0);
    assert!(start <= end);

    // Choose the mapping page sizes
    if capabilities.contains(vmx::bitmaps::EptCapability::PAGE_1GB) {
        unsafe {
            ept_mapper.map_range_giant_page(
                allocator,
                vmx::GuestPhysAddr::new(0),
                vmx::HostPhysAddr::new(0),
                end as usize,
                EptEntryFlags::READ | EptEntryFlags::WRITE | EptEntryFlags::SUPERVISOR_EXECUTE,
            )?
        };
    } else if capabilities.contains(vmx::bitmaps::EptCapability::PAGE_2MB) {
        unsafe {
            ept_mapper.map_range_huge_page(
                allocator,
                vmx::GuestPhysAddr::new(0),
                vmx::HostPhysAddr::new(0),
                end as usize,
                EptEntryFlags::READ | EptEntryFlags::WRITE | EptEntryFlags::SUPERVISOR_EXECUTE,
            )?
        };
    } else {
        unsafe {
            ept_mapper.map_range(
                allocator,
                vmx::GuestPhysAddr::new(0),
                vmx::HostPhysAddr::new(0),
                end as usize,
                EptEntryFlags::READ | EptEntryFlags::WRITE | EptEntryFlags::SUPERVISOR_EXECUTE,
            )?
        };
    }

    Ok(ept_mapper)
}

fn launch_guest(
    vmcs: &mut vmx::VmcsRegion,
    switching: bool,
) -> Result<vmx::VmxExitReason, vmx::VmxError> {
    const GUEST_STACK_SIZE: usize = 4096;
    let entry_point = if switching {
        guest_code_vmfunc as *const u8
    } else {
        guest_code as *const u8
    };

    let mut guest_stack = [0; GUEST_STACK_SIZE];
    let guest_rsp = guest_stack.as_mut_ptr() as usize + GUEST_STACK_SIZE;
    vmcs.vcpu
        .set_nat(fields::GuestStateNat::Rip, entry_point as usize)?;
    vmcs.vcpu.set_nat(fields::GuestStateNat::Rsp, guest_rsp)?;

    unsafe { vmcs.run() }
}
#[inline(always)]
unsafe fn rdtsc() -> u64 {
    let mut _hi: u64 = 0;
    let mut _lo: u64 = 0;
    asm!("rdtsc", "mov {_hi}, rdx", "mov {_lo}, rax",
                        _hi = out(reg) _hi,
                        _lo = out(reg) _lo, out("rdx") _, out("rax") _);
    _lo | (_hi << 32)
}

fn setup_guest(vcpu: &mut vmx::VCpu) -> Result<(), vmx::VmxError> {
    // Mostly copied from https://nixhacker.com/developing-hypervisor-from-scratch-part-4/

    // Control registers
    let cr0: usize;
    let cr3: usize;
    let cr4: usize;
    unsafe {
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        vcpu.set_nat(fields::GuestStateNat::Cr0, cr0)?;
        asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
        vcpu.set_nat(fields::GuestStateNat::Cr3, cr3)?;
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        vcpu.set_nat(fields::GuestStateNat::Cr4, cr4)?;
    }

    // Segments selectors
    let es: u16;
    let cs: u16;
    let ss: u16;
    let ds: u16;
    let fs: u16;
    let gs: u16;
    let tr: u16;
    unsafe {
        asm!("mov {:x}, es", out(reg) es, options(nomem, nostack, preserves_flags));
        vcpu.set16(fields::GuestState16::EsSelector, es)?;
        asm!("mov {:x}, cs", out(reg) cs, options(nomem, nostack, preserves_flags));
        vcpu.set16(fields::GuestState16::CsSelector, cs)?;
        asm!("mov {:x}, ss", out(reg) ss, options(nomem, nostack, preserves_flags));
        vcpu.set16(fields::GuestState16::SsSelector, ss)?;
        asm!("mov {:x}, ds", out(reg) ds, options(nomem, nostack, preserves_flags));
        vcpu.set16(fields::GuestState16::DsSelector, ds)?;
        asm!("mov {:x}, fs", out(reg) fs, options(nomem, nostack, preserves_flags));
        vcpu.set16(fields::GuestState16::FsSelector, fs)?;
        asm!("mov {:x}, gs", out(reg) gs, options(nomem, nostack, preserves_flags));
        vcpu.set16(fields::GuestState16::GsSelector, gs)?;
        asm!("str {:x}", out(reg) tr, options(nostack, preserves_flags));
        vcpu.set16(fields::GuestState16::TrSelector, tr)?;
        vcpu.set16(fields::GuestState16::LdtrSelector, 0)?;
    }
    // println!("es 0x{:04x}", es);
    // println!("cs 0x{:04x}", cs);
    // println!("ss 0x{:04x}", ss);
    // println!("ds 0x{:04x}", ds);
    // println!("fs 0x{:04x}", fs);
    // println!("gs 0x{:04x}", gs);
    // println!("tr 0x{:04x}", tr);

    vcpu.set32(fields::GuestState32::EsAccessRights, 0xC093)?;
    vcpu.set32(fields::GuestState32::CsAccessRights, 0xA09B)?;
    vcpu.set32(fields::GuestState32::SsAccessRights, 0x10000)?;
    vcpu.set32(fields::GuestState32::DsAccessRights, 0xC093)?;
    vcpu.set32(fields::GuestState32::FsAccessRights, 0x10000)?;
    vcpu.set32(fields::GuestState32::GsAccessRights, 0x10000)?;
    vcpu.set32(fields::GuestState32::LdtrAccessRights, 0x10000)?;
    vcpu.set32(fields::GuestState32::TrAccessRights, 0x8B)?;

    let limit = 0xFFFF;
    vcpu.set32(fields::GuestState32::EsLimit, limit)?;
    vcpu.set32(fields::GuestState32::CsLimit, limit)?;
    vcpu.set32(fields::GuestState32::SsLimit, limit)?;
    vcpu.set32(fields::GuestState32::DsLimit, limit)?;
    vcpu.set32(fields::GuestState32::FsLimit, limit)?;
    vcpu.set32(fields::GuestState32::GsLimit, limit)?;
    vcpu.set32(fields::GuestState32::LdtrLimit, limit)?;
    vcpu.set32(fields::GuestState32::TrLimit, 0xff)?; // At least 0x67
    vcpu.set32(fields::GuestState32::GdtrLimit, 0xffff)?;
    vcpu.set32(fields::GuestState32::IdtrLimit, 0xffff)?;

    unsafe {
        vcpu.set_nat(fields::GuestStateNat::EsBase, 0)?;
        vcpu.set_nat(fields::GuestStateNat::CsBase, 0)?;
        vcpu.set_nat(fields::GuestStateNat::SsBase, 0)?;
        vcpu.set_nat(fields::GuestStateNat::DsBase, 0)?;
        vcpu.set_nat(fields::GuestStateNat::FsBase, 0)?;
        vcpu.set_nat(fields::GuestStateNat::GsBase, 0)?;
        vcpu.set_nat(fields::GuestStateNat::LdtrBase, 0)?;
        vcpu.set_nat(
            fields::GuestStateNat::TrBase,
            fields::HostStateNat::TrBase.vmread()?,
        )?;
        vcpu.set_nat(
            fields::GuestStateNat::GdtrBase,
            fields::HostStateNat::GdtrBase.vmread()?,
        )?;
        vcpu.set_nat(
            fields::GuestStateNat::IdtrBase,
            fields::HostStateNat::IdtrBase.vmread()?,
        )?;

        // MSRs
        vcpu.set_nat(
            fields::GuestStateNat::Ia32SysenterEsp,
            fields::HostStateNat::Ia32SysenterEsp.vmread()?,
        )?;
        vcpu.set_nat(
            fields::GuestStateNat::Ia32SysenterEip,
            fields::HostStateNat::Ia32SysenterEip.vmread()?,
        )?;
        vcpu.set32(
            fields::GuestState32::Ia32SysenterCs,
            fields::HostState32::Ia32SysenterCs.vmread()?,
        )?;

        if fields::GuestState64::Ia32Efer.is_unsupported() {
            println!("Ia32Efer field is not supported");
        }
        // vcpu.set64(fields::GuestState64::Ia32Pat, fields::HostState64)
        // vcpu.set64(fields::GuestState64::Ia32Debugctl, 0)?;
        vcpu.set64(fields::GuestState64::Ia32Efer, Efer::read().bits())?;
        vcpu.set_nat(fields::GuestStateNat::Rflags, 0x2)?;
    }

    vcpu.set32(fields::GuestState32::ActivityState, 0)?;
    vcpu.set64(fields::GuestState64::VmcsLinkPtr, u64::max_value())?;
    vcpu.set16(fields::GuestState16::InterruptStatus, 0)?;
    // vcpu.set16(fields::GuestState16::PmlIndex, 0)?; // <- Not supported on dev server
    vcpu.set32(fields::GuestState32::VmxPreemptionTimerValue, 0)?;

    Ok(())
}

fn configure_msr() -> Result<(), vmx::VmxError> {
    unsafe {
        fields::Ctrl32::VmExitMsrLoadCount.vmwrite(0)?;
        fields::Ctrl32::VmExitMsrStoreCount.vmwrite(0)?;
        fields::Ctrl32::VmEntryMsrLoadCount.vmwrite(0)?;
    }

    Ok(())
}

#[no_mangle]
unsafe fn guest_code_vmfunc() {
    asm!("nop", "nop", "nop", "nop", "nop", "nop");
    asm!("nop", "nop", "nop", "nop", "nop", "nop");
    println!("Hello from guest!");
    for i in 0..5 {
        let start = rdtsc();
        if i % 2 == 0 {
            asm!("mov eax, 0", "mov ecx, 1", "vmfunc", out("rax") _, out("rcx") _);
        } else {
            asm!("mov eax, 0", "mov ecx, 0", "vmfunc", out("rax") _, out("rcx") _);
        }
        let end = rdtsc();
        println!("After the vmfunc {} - {} = {}", end, start, (end - start));
    }
    asm!("nop", "nop", "nop", "nop", "nop", "nop", "vmcall",);
}

unsafe fn guest_code() {
    asm!("nop", "nop", "nop", "nop", "nop", "nop");
    asm!("nop", "nop", "nop", "nop", "nop", "nop");
    println!("Hello from guest!");
    asm!("nop", "nop", "nop", "nop", "nop", "nop", "vmcall",);
}

unsafe fn create_rawc(virtoffset: u64, allocator: &SharedFrameAllocator) {
    // Strategy:
    // 1. Allocate the page tables.
    // We should be able to map the same physaddr in the EPT.
    // We allocate 2GB of space to host the program.
    //
    // 2. Copy the program rawc at the aligned address.
    // TODO we will need to give it a stack pointer (the end of the 2GB?);
    //
    // 3. Generate the EPTs with hpa == gpa.

    // 1. Page tables
    let mut pml4 = allocator
        .allocate_zeroed_frame()
        .expect("Unable to allocate the page tables");
    let root = pml4.as_array_page();
    let mut pl3 = allocator
        .allocate_zeroed_frame()
        .expect("Unable to allocate first entry");
    root[0] = pl3.phys_addr.as_u64() | 0x7;

    // 2. Allocate 2GB so that we can find a 1Gb aligned address;
    let gb = 1 << 30;
    let backed = allocator
        .allocate_range(2 * gb)
        .expect("Unable to allocate 2GB");
    let aligned = backed.start.as_u64() / gb + gb;
    assert!(aligned % gb == 0 && aligned > backed.start.as_u64() && aligned < backed.end.as_u64());
    let pde = pl3.as_array_page();
    pde[0] = aligned | 0x7 | (1 << 7);

    // Copying the program.
    let offset_aligned = aligned - backed.start.as_u64();
    let addr = backed.start.as_u64() + virtoffset + offset_aligned;
    let start = rawc::RAWC.offset as usize;
    if start >= rawc::RAWC.bytes.len() {
        panic!("The offset is too big");
    }
    let target = core::slice::from_raw_parts_mut(
        (addr + rawc::RAWC.start) as *mut u8,
        rawc::RAWC.bytes.len() - start,
    );
    target.copy_from_slice(&rawc::RAWC.bytes[start..]);

    // 3. Initialize the vcpu;
    initialize_cpu();
    println!("VMX:    {:?}", vmx::vmx_available());
    println!("EPT:    {:?}", vmx::ept_capabilities());
    println!("VMFunc: {:?}", vmx::available_vmfuncs());
    println!("VMXON:  {:?}", vmx::vmxon(allocator));

    let mut vmcs = match vmx::VmcsRegion::new(allocator) {
        Err(err) => {
            println!("VMCS:   Err({:?})", err);
            qemu::exit(qemu::ExitCode::Failure);
        }
        Ok(vmcs) => {
            println!("VMCS:   Ok(())");
            vmcs
        }
    };

    println!("LOAD:   {:?}", vmcs.set_as_active());
    let err = vmcs
        .set_pin_based_ctrls(PinbasedControls::empty())
        .and_then(|_| {
            vmcs.set_vm_exit_ctrls(
                ExitControls::HOST_ADDRESS_SPACE_SIZE
                    | ExitControls::LOAD_IA32_EFER
                    | ExitControls::SAVE_IA32_EFER,
            )
        })
        .and_then(|_| {
            vmcs.set_vm_entry_ctrls(EntryControls::IA32E_MODE_GUEST | EntryControls::LOAD_IA32_EFER)
        })
        .and_then(|_| vmcs.set_exception_bitmap(ExceptionBitmap::empty()))
        .and_then(|_| vmcs.save_host_state())
        .and_then(|_| setup_guest(&mut vmcs.vcpu));
    println!("Config: {:?}", err);
    println!("MSRs:   {:?}", configure_msr());
    println!(
        "1'Ctrl: {:?}",
        vmcs.set_primary_ctrls(PrimaryControls::SECONDARY_CONTROLS)
    );
    let secondary_ctrls = SecondaryControls::ENABLE_RDTSCP | SecondaryControls::ENABLE_EPT;
    println!("2'Ctrl: {:?}", vmcs.set_secondary_ctrls(secondary_ctrls));

    // Translate physical address on host to virtual address on host.

    let translator = move |addr: vmx::HostPhysAddr| {
        vmx::HostVirtAddr::new(virtoffset as usize + addr.as_usize())
    };
    let host_address_translator = ept::HostAddressMapper::new(translator);
    let mut ept_mapper = ept::ExtendedPageTableMapper::new(allocator, host_address_translator)
        .expect("Failed to build EPT mapper");

    // Let's map stuff
    ept_mapper
        .map_range(
            allocator,
            vmx::GuestPhysAddr::new(pml4.phys_addr.as_usize()),
            pml4.phys_addr,
            0x1000,
            EptEntryFlags::READ | EptEntryFlags::WRITE | EptEntryFlags::SUPERVISOR_EXECUTE,
        )
        .expect("Failed pml4");
    ept_mapper
        .map_range(
            allocator,
            vmx::GuestPhysAddr::new(pl3.phys_addr.as_usize()),
            pl3.phys_addr,
            0x1000,
            EptEntryFlags::READ | EptEntryFlags::WRITE | EptEntryFlags::SUPERVISOR_EXECUTE,
        )
        .expect("Failed pl3");
    ept_mapper
        .map_range(
            allocator,
            vmx::GuestPhysAddr::new(backed.start.as_u64() as usize),
            vmx::HostPhysAddr::new(backed.start.as_u64() as usize),
            backed.size(),
            EptEntryFlags::READ | EptEntryFlags::WRITE | EptEntryFlags::SUPERVISOR_EXECUTE,
        )
        .expect("Failed to map backed");
    println!("EPTP:   {:?}", vmcs.set_ept_ptr(&ept_mapper));
    println!("Check:  {:?}", vmx::check::check());
    //let entry_point = addr + 0x4;
    let entry_point = rawc::RAWC.start + 0x4;
    vmcs.vcpu
        .set_nat(fields::GuestStateNat::Rip, entry_point as usize)
        .ok();
    vmcs.vcpu
        .set_nat(fields::GuestStateNat::Cr3, pml4.phys_addr.as_usize())
        .ok();
    // Zero out the gdt and idt
    vmcs.vcpu.set_nat(fields::GuestStateNat::GdtrBase, 0x0).ok();
    vmcs.vcpu.set_nat(fields::GuestStateNat::IdtrBase, 0x0).ok();
    println!(
        "Launch: {:?} -> stopped at {:#x?} expected 0x401009, {:#x?}",
        vmcs.run(),
        fields::GuestStateNat::Rip.vmread(),
        vmcs.vcpu.regs[vmx::Register::Rax as usize],
    );
    println!("Info:   {:?}", vmcs.vcpu.interrupt_info());
    println!(
        "Qualif: {:?}",
        vmcs.vcpu
            .exit_qualification()
            .map(|qualif| qualif.ept_violation())
    );
    println!("VMXOFF: {:?}", vmx::raw::vmxoff());
}

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("{}", info);

    kernel::qemu::exit(kernel::qemu::ExitCode::Failure);
}

#[cfg(test)]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    kernel::test_panic_handler(info);
}
