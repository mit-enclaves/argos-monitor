use crate::guests;
use crate::mmu::SharedFrameAllocator;
use crate::println;
use crate::qemu;
use crate::vmx;
use crate::vmx::bitmaps::{
    EntryControls, EptEntryFlags, ExceptionBitmap, ExitControls, PinbasedControls, PrimaryControls,
    SecondaryControls, VmFuncControls,
};
use crate::vmx::ept;
use crate::vmx::fields;
use core::arch::asm;

use x86_64::VirtAddr;

use super::Guest;
/// Allows to map tyche itself inside a VM.
pub struct Identity {}

impl Guest for Identity {
    unsafe fn instantiate(&self, allocator: &SharedFrameAllocator) -> vmx::VmcsRegion {
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
                vmcs.set_vm_entry_ctrls(
                    EntryControls::IA32E_MODE_GUEST | EntryControls::LOAD_IA32_EFER,
                )
            })
            .and_then(|_| vmcs.set_exception_bitmap(ExceptionBitmap::empty()))
            .and_then(|_| vmcs.save_host_state())
            .and_then(|_| guests::setup_guest(&mut vmcs.vcpu));
        println!("Config: {:?}", err);
        println!("MSRs:   {:?}", guests::configure_msr());

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
            setup_ept(allocator.get_physical_offset(), allocator).expect("Failed to setupt EPT 1");
        println!("EPTP:   {:?}", vmcs.set_ept_ptr(&ept_mapper));

        // Let's see if we can duplicate the EPTs, and register them both
        if switching {
            let ept_mapper2 = setup_ept(allocator.get_physical_offset(), allocator)
                .expect("Failed to setup EPT 2");
            println!("EPT2:   {:?}", vmcs.set_ept_ptr(&ept_mapper2));
            let mut eptp_list =
                ept::EptpList::new(allocator).expect("Failed to allocate EPTP list");
            eptp_list.set_entry(0, &ept_mapper);
            eptp_list.set_entry(1, &ept_mapper2);
            println!("EPTP L: {:?}", vmcs.set_eptp_list(&eptp_list));
            println!(
                "Enable vmfunc: {:?}",
                vmcs.set_vmfunc_ctrls(VmFuncControls::EPTP_SWITCHING)
            );
        }
        const GUEST_STACK_SIZE: usize = 4096;
        let entry_point = if switching {
            guest_code_vmfunc as *const u8
        } else {
            guest_code as *const u8
        };

        let mut guest_stack = [0; GUEST_STACK_SIZE];
        let guest_rsp = guest_stack.as_mut_ptr() as usize + GUEST_STACK_SIZE;
        vmcs.vcpu
            .set_nat(fields::GuestStateNat::Rip, entry_point as usize)
            .expect("Unable to set rip");
        vmcs.vcpu
            .set_nat(fields::GuestStateNat::Rsp, guest_rsp)
            .expect("Unable to set rsp");

        vmcs
    }
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
    asm!(
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "mov eax, 0x666 ",
        "vmcall",
    );
}

unsafe fn guest_code() {
    asm!("nop", "nop", "nop", "nop", "nop", "nop");
    asm!("nop", "nop", "nop", "nop", "nop", "nop");
    println!("Hello from guest!");
    asm!(
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "mov eax, 0x666",
        "vmcall",
    );
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
