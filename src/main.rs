#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(kernel::test_runner)]
#![reexport_test_harness_main = "test_main"]

extern crate alloc;

use bootloader::{entry_point, BootInfo};
use core::panic::PanicInfo;
use kernel::debug::info;
use kernel::guests::Guest;
use kernel::mmu::FrameAllocator;
use kernel::println;
use kernel::vmx;
use kernel::vmx::Register;
use kernel::HostVirtAddr;
use x86_64::registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags};

use kernel::guests;
use kernel::qemu;

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
    if cfg!(test) {
        run_tests();
    }

    // Initialize memory management
    let physical_memory_offset = HostVirtAddr::new(
        boot_info
            .physical_memory_offset
            .into_option()
            .expect("The bootloader must be configured with 'map-physical-memory'")
            as usize,
    );

    let frame_allocator = unsafe {
        kernel::init_memory(physical_memory_offset, &mut boot_info.memory_regions)
            .expect("Failed to initialize memory")
    };

    // Parse RSDP tables
    let rsdp = boot_info
        .rsdp_addr
        .into_option()
        .expect("Missing RSDP address");
    let acpi_info = unsafe { kernel::acpi::AcpiInfo::from_rsdp(rsdp, physical_memory_offset) };

    // Check I/O MMU support
    if let Some(iommus) = acpi_info.iommu {
        let iommu_addr = HostVirtAddr::new(
            iommus[0].base_address.as_usize() + physical_memory_offset.as_usize(),
        );
        let iommu = unsafe { kernel::vtd::Iommu::new(iommu_addr) };
        println!("IO MMU: capabilities {:?}", iommu.get_capability(),);
        println!("        extended {:?}", iommu.get_extended_capability());
        iommu.set_global_command(1 << 31); // Enable translation
        println!("IO MMU: status 0b{:b}", iommu.get_global_status());
    } else {
        println!("IO MMU: None");
    }

    // Select appropriate guest depending on selected features
    if cfg!(feature = "guest_linux") {
        launch_guest(&guests::linux::LINUX, &frame_allocator)
    } else if cfg!(feature = "guest_rawc") {
        launch_guest(&guests::rawc::RAWC, &frame_allocator)
    } else {
        launch_guest(&guests::identity::Identity {}, &frame_allocator)
    }
}

fn launch_guest(guest: &impl Guest, allocator: &impl FrameAllocator) -> ! {
    initialize_cpu();
    print_vmx_info();

    unsafe {
        let frame = allocator
            .allocate_frame()
            .expect("Failed to allocate VMXON");
        let vmxon = match vmx::vmxon(frame) {
            Ok(vmxon) => {
                println!("VMXON:  Ok(vmxon)");
                vmxon
            }
            Err(err) => {
                println!("VMXON:  {:?}", err);
                qemu::exit(qemu::ExitCode::Failure);
            }
        };

        let mut vmcs = guest.instantiate(&vmxon, allocator);

        // Debugging hook post initialization.
        info::tyche_hook_done(1);

        let mut vcpu = vmcs.set_as_active().expect("Failed to activate VMCS");

        let mut result = vcpu.launch();
        let mut launch = "Launch";
        let mut counter = 0;
        loop {
            let rip = vcpu.get(Register::Rip);
            let rax = vcpu.get(Register::Rax);
            let rcx = vcpu.get(Register::Rcx);
            let rbp = vcpu.get(Register::Rbp);
            println!(
                "{}: {} {:?} - rip: 0x{:x} - rbp: 0x{:x} - rax: 0x{:x} - rcx: 0x{:x}",
                launch,
                counter,
                vcpu.exit_reason(),
                rip,
                rbp,
                rax,
                rcx
            );

            let exit_reason = if let Ok(exit_reason) = result {
                guest
                    .handle_exit(&mut vcpu, exit_reason)
                    .expect("Failed to handle VM exit")
            } else {
                println!("VMXerror {:?}", result);
                guests::HandlerResult::Crash
            };

            if exit_reason != guests::HandlerResult::Resume {
                break;
            }

            // Shutdown after too many VM exits
            counter += 1;
            if counter >= 200 {
                println!("Too many iterations: stoping guest");
                break;
            }

            // Resume VM
            launch = "Resume";
            result = vcpu.resume();
        }

        println!("Info:   {:?}", vcpu.interrupt_info());
        println!(
            "Qualif: {:?}",
            vcpu.exit_qualification()
                .map(|qualif| qualif.ept_violation())
        );
    }
    qemu::exit(qemu::ExitCode::Success);
}

fn initialize_cpu() {
    // Set CPU in a valid state for VMX operations.
    let cr0 = Cr0::read();
    let cr4 = Cr4::read();
    unsafe {
        Cr0::write(cr0 | Cr0Flags::NUMERIC_ERROR);
        Cr4::write(cr4 | Cr4Flags::OSXSAVE);
    };
}

fn print_vmx_info() {
    println!("VMX:    {:?}", vmx::vmx_available());
    println!("EPT:    {:?}", vmx::ept_capabilities());
    println!("VMFunc: {:?}", vmx::available_vmfuncs());
}

fn run_tests() {
    #[cfg(test)]
    test_main();
    qemu::exit(qemu::ExitCode::Success);
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
