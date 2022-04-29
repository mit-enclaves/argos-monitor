#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(kernel::test_runner)]
#![reexport_test_harness_main = "test_main"]

use core::arch::asm;
use core::panic::PanicInfo;

use kernel::println;
use kernel::qemu;
use kernel::vmx;
use kernel::vmx::bitmaps;
use kernel::vmx::fields;
use kernel::vmx::fields::traits::VmcsField32Ro;
use kernel::vmx::msr;

use bootloader::{entry_point, BootInfo};
use x86_64::instructions::tables::{sgdt, sidt};

entry_point!(kernel_main);

fn kernel_main(boot_info: &'static BootInfo) -> ! {
    println!("=========== Start QEMU ===========");

    kernel::init();
    let vma_allocator =
        unsafe { kernel::init_memory(boot_info).expect("Failed to initialize memory") };

    unsafe {
        println!("VMX:    {:?}", vmx::vmx_available());
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
        println!(
            "Ctrls1: {:?}",
            vmcs.set_pin_based_ctrls(bitmaps::PinbasedControls::empty())
        );
        println!(
            "Ctrls2: {:?}",
            vmcs.set_primary_ctrls(bitmaps::PrimaryControls::empty())
        );
        println!(
            "VMExit: {:?}",
            vmcs.set_vm_exit_ctrls(bitmaps::ExitControls::HOST_ADDRESS_SPACE_SIZE)
        );
        println!(
            "VMEntr: {:?}",
            vmcs.set_vm_entry_ctrls(bitmaps::EntryControls::IA32E_MODE_GUEST)
        );
        println!(
            "Bitmap: {:?}",
            vmcs.set_exception_bitmap(bitmaps::ExceptionBitmap::empty())
        );
        println!("Host:   {:?}", vmcs.save_host_state());
        println!("Guest:  {:?}", setup_guest(&mut vmcs.vcpu));
        println!("Launch: {:?}", launch_guest(&mut vmcs.vcpu));
        println!(
            "Err {:?}",
            fields::GuestState32Ro::VmInstructionError.vmread().unwrap()
        );
        println!("Exit:   {:?}", vmcs.vcpu.exit_reason());
        println!("VMXOFF: {:?}", vmx::raw::vmxoff());
    }

    #[cfg(test)]
    test_main();

    kernel::qemu::exit(kernel::qemu::ExitCode::Success);
}

fn launch_guest(vcpu: &mut vmx::VCpu) -> Result<(), vmx::VmxError> {
    let entry_point = guest_code as *const u8;
    let mut guest_stack = [0; 128];
    let stack_ptr = guest_stack.as_mut_ptr();
    vcpu.set_nat(fields::GuestStateNat::Rip, entry_point as usize)?;
    vcpu.set_nat(fields::GuestStateNat::Rsp, stack_ptr as usize)?;

    unsafe {
        asm!("vmlaunch");
    }

    Ok(())
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
        asm!("str {:x}", out(reg) tr, options(nomem, nostack, preserves_flags));
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
    vcpu.set32(fields::GuestState32::CsAccessRights, 0xC09B)?;
    vcpu.set32(fields::GuestState32::SsAccessRights, 0x10000)?;
    vcpu.set32(fields::GuestState32::DsAccessRights, 0xC093)?;
    vcpu.set32(fields::GuestState32::FsAccessRights, 0x10000)?;
    vcpu.set32(fields::GuestState32::GsAccessRights, 0x10000)?;
    vcpu.set32(fields::GuestState32::LdtrAccessRights, 0x10000)?;
    vcpu.set32(fields::GuestState32::TrAccessRights, 0x8B)?;

    let limit = u32::max_value();
    vcpu.set32(fields::GuestState32::EsLimit, limit)?;
    vcpu.set32(fields::GuestState32::CsLimit, limit)?;
    vcpu.set32(fields::GuestState32::SsLimit, limit)?;
    vcpu.set32(fields::GuestState32::DsLimit, limit)?;
    vcpu.set32(fields::GuestState32::FsLimit, limit)?;
    vcpu.set32(fields::GuestState32::GsLimit, limit)?;
    vcpu.set32(fields::GuestState32::LdtrLimit, limit)?;
    vcpu.set32(fields::GuestState32::TrLimit, 0x67)?;
    vcpu.set32(fields::GuestState32::GdtrLimit, 0xffff)?;
    vcpu.set32(fields::GuestState32::IdtrLimit, 0xffff)?;

    vcpu.set_nat(fields::GuestStateNat::EsBase, 0)?;
    vcpu.set_nat(fields::GuestStateNat::CsBase, 0)?;
    vcpu.set_nat(fields::GuestStateNat::SsBase, 0)?;
    vcpu.set_nat(fields::GuestStateNat::DsBase, 0)?;
    // vcpu.set_nat(fields::GuestStateNat::FsBase, 0)?; // TODO: is it supported by cpu?
    // vcpu.set_nat(fields::GuestStateNat::GsBase, 0)?; // TODO: is it supported by cpu?
    vcpu.set_nat(fields::GuestStateNat::LdtrBase, 0)?;
    // vcpu.set_nat(fields::GuestStateNat::TrBase, 0)?; // TODO
    vcpu.set_nat(
        fields::GuestStateNat::GdtrBase,
        sgdt().base.as_u64() as usize,
    )?;
    vcpu.set_nat(
        fields::GuestStateNat::IdtrBase,
        sidt().base.as_u64() as usize,
    )?;

    // MSRs
    unsafe {
        vcpu.set_nat(
            fields::GuestStateNat::Ia32SysenterEsp,
            msr::SYSENTER_ESP.read() as usize,
        )?;
        vcpu.set_nat(
            fields::GuestStateNat::Ia32SysenterEip,
            msr::SYSENTER_EIP.read() as usize,
        )?;
        vcpu.set32(
            fields::GuestState32::Ia32SysenterCs,
            msr::SYSENTER_CS.read() as u32,
        )?;

        // TODO: more MSRs?
    }

    vcpu.set32(fields::GuestState32::ActivityState, 0)?;
    vcpu.set64(fields::GuestState64::VmcsLinkPtr, u64::max_value())?;
    vcpu.set16(fields::GuestState16::InterruptStatus, 0)?;
    vcpu.set16(fields::GuestState16::PmlIndex, 0)?;
    // TODO: VMX preemption timer?

    Ok(())
}

unsafe fn guest_code() {
    asm!("vmcall");
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
