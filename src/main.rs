#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(kernel::test_runner)]
#![reexport_test_harness_main = "test_main"]

extern crate alloc;

use bootloader::{entry_point, BootInfo};
use core::panic::PanicInfo;
use kernel::guests::Guest;
use kernel::mmu::FrameAllocator;
use kernel::println;
use kernel::vmx;
use x86_64::registers::control::{Cr0, Cr0Flags};
use x86_64::VirtAddr;

use kernel::guests;

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

    let frame_allocator = unsafe {
        kernel::init_memory(physical_memory_offset, &mut boot_info.memory_regions)
            .expect("Failed to initialize memory")
    };

    if true {
        launch_guest(&guests::rawc::RAWC, &frame_allocator)
    } else {
        launch_guest(&guests::identity::Identity {}, &frame_allocator)
    };
}

fn launch_guest(guest: &impl Guest, vma_allocator: &impl FrameAllocator) -> ! {
    initialize_cpu();
    print_vmx_info();

    unsafe {
        println!("VMXON:  {:?}", vmx::vmxon(vma_allocator));

        let mut vmcs = guest.instantiate(vma_allocator);

        println!(
            "Launch: {:?} -> {:#x?}",
            vmcs.run(),
            vmcs.vcpu.regs[vmx::Register::Rax as usize],
        );
        println!("Info:   {:?}", vmcs.vcpu.interrupt_info());
        println!(
            "Qualif: {:?}",
            vmcs.vcpu
                .exit_qualification()
                .map(|qualif| qualif.ept_violation())
        );
    }
    kernel::qemu::exit(kernel::qemu::ExitCode::Success);
}

fn initialize_cpu() {
    // Set CPU in a valid state for VMX operations.
    let cr0 = Cr0::read();
    unsafe { Cr0::write(cr0 | Cr0Flags::NUMERIC_ERROR) };
}

fn print_vmx_info() {
    println!("VMX:    {:?}", vmx::vmx_available());
    println!("EPT:    {:?}", vmx::ept_capabilities());
    println!("VMFunc: {:?}", vmx::available_vmfuncs());
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
