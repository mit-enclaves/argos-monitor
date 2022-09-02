use crate::acpi::AcpiInfo;
use crate::guests;
use crate::mmu::eptmapper::EptMapper;
use crate::mmu::FrameAllocator;
use crate::println;
use crate::qemu;
use crate::vmx;
use crate::vmx::bitmaps::{EptEntryFlags, VmFuncControls};
use crate::vmx::ept;
use crate::vmx::fields;
use core::arch::asm;

use super::Guest;
use super::HandlerResult;
/// Allows to map tyche itself inside a VM.
pub struct Identity {}

impl Guest for Identity {
    unsafe fn instantiate<'vmx>(
        &self,
        vmxon: &'vmx vmx::Vmxon,
        _acpi: &AcpiInfo,
        allocator: &impl FrameAllocator,
    ) -> vmx::VmcsRegion<'vmx> {
        let frame = allocator.allocate_frame().expect("Failed to allocate VMCS");
        let mut vmcs = match vmxon.create_vm(frame) {
            Err(err) => {
                println!("VMCS:   Err({:?})", err);
                qemu::exit(qemu::ExitCode::Failure);
            }
            Ok(vmcs) => {
                println!("VMCS:   Ok(())");
                vmcs
            }
        };

        {
            // VMCS is active in this block
            let mut vcpu = vmcs.set_as_active().expect("Failed to activate VMCS");
            let switching = vmx::available_vmfuncs().is_ok();
            guests::default_vmcs_config(&mut vcpu, switching);
            let ept_mapper = setup_ept(allocator).expect("Failed to setupt EPT 1");
            println!("EPTP:   {:?}", vcpu.set_ept_ptr(ept_mapper.get_root()));

            // Let's see if we can duplicate the EPTs, and register them both
            if switching {
                let ept_mapper2 = setup_ept(allocator).expect("Failed to setup EPT 2");
                println!("EPT2:   {:?}", vcpu.set_ept_ptr(ept_mapper2.get_root()));
                let mut eptp_list = ept::EptpList::new(
                    allocator
                        .allocate_frame()
                        .expect("Failed to allocate EPTP list"),
                );
                eptp_list.set_entry(0, ept_mapper.get_root());
                eptp_list.set_entry(1, ept_mapper2.get_root());
                println!("EPTP L: {:?}", vcpu.set_eptp_list(&eptp_list));
                println!(
                    "Enable vmfunc: {:?}",
                    vcpu.set_vmfunc_ctrls(VmFuncControls::EPTP_SWITCHING)
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
            vcpu.set_nat(fields::GuestStateNat::Rip, entry_point as usize)
                .expect("Unable to set rip");
            vcpu.set_nat(fields::GuestStateNat::Rsp, guest_rsp)
                .expect("Unable to set rsp");

            // Configure MSRs
            let frame = allocator
                .allocate_frame()
                .expect("Failed to allocate MSR bitmaps");
            let msr_bitmaps = vcpu
                .initialize_msr_bitmaps(frame)
                .expect("Failed to install MSR bitmap");
            msr_bitmaps.allow_all();
        }

        vmcs
    }

    unsafe fn vmcall_handler(
        &self,
        _vcpu: &mut vmx::ActiveVmcs,
    ) -> Result<HandlerResult, vmx::VmxError> {
        Ok(HandlerResult::Exit)
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

fn setup_ept(allocator: &impl FrameAllocator) -> Result<EptMapper, ()> {
    let root = allocator
        .allocate_frame()
        .expect("Unable to allocate root ept")
        .zeroed();
    let mut ept_mapper = EptMapper::new(
        allocator.get_physical_offset().as_u64() as usize,
        root.phys_addr,
    );
    let (start, end) = allocator.get_boundaries();

    // Just common checks on the boundaries.
    assert!(start % 0x1000 == 0);
    assert!(end % 0x1000 == 0);
    assert!(start <= end);

    // Choose the mapping page sizes

    ept_mapper.map_range(
        allocator,
        vmx::GuestPhysAddr::new(start),
        vmx::HostPhysAddr::new(start),
        end as usize,
        EptEntryFlags::READ | EptEntryFlags::WRITE | EptEntryFlags::SUPERVISOR_EXECUTE,
    );

    Ok(ept_mapper)
}
