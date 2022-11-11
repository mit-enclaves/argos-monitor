#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(first_stage::test_runner)]
#![reexport_test_harness_main = "test_main"]

extern crate alloc;

use bootloader::{entry_point, BootInfo};
use core::panic::PanicInfo;
use first_stage::acpi::AcpiInfo;
use first_stage::guests;
use first_stage::guests::Guest;
use first_stage::mmu::MemoryMap;
use first_stage::println;
use first_stage::second_stage;
use first_stage::{HostPhysAddr, HostVirtAddr};
use mmu::{FrameAllocator, PtMapper};
use qemu;
use vmx;
use vtd;
use x86_64::registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags};

entry_point!(kernel_main);

fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    // Initialize display, if any
    if let Some(buffer) = boot_info.framebuffer.as_mut().take() {
        first_stage::init_display(buffer);
    }
    println!("============= First Stage =============");

    // Initialize kernel structures
    first_stage::init();

    println!("CR4: {:?}", Cr4::read());
    println!("SMX support: {:?}", first_stage::smx::smx_is_available());
    unsafe {
        let rax: u64;
        let rbx: u64;
        let rcx: u64;
        use core::arch::asm;
        asm! {
            "push rbx",
            "mov rax, 1",
            "mov rbx, 2",
            "mov rcx, 3",
            "getsec",
            "mov rdx, rbx",
            "pop rbx",
            out("rax") rax,
            out("rdx") rbx,
            out("rcx") rcx,
        };

        println!(
            "GETSEC  rax: 0x{:x} - rbx: 0x{:x} - rcx: 0x{:x}",
            rax, rbx, rcx
        );
    }

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

    let (host_allocator, guest_allocator, memory_map, pt_mapper) = unsafe {
        first_stage::init_memory(physical_memory_offset, &mut boot_info.memory_regions)
            .expect("Failed to initialize memory")
    };

    // Parse RSDP tables
    let rsdp = boot_info
        .rsdp_addr
        .into_option()
        .expect("Missing RSDP address");
    let acpi_info = unsafe { first_stage::acpi::AcpiInfo::from_rsdp(rsdp, physical_memory_offset) };

    // Check I/O MMU support
    if let Some(iommus) = &acpi_info.iommu {
        let iommu_addr = HostVirtAddr::new(
            iommus[0].base_address.as_usize() + physical_memory_offset.as_usize(),
        );
        let iommu = unsafe { vtd::Iommu::new(iommu_addr) };
        println!("IO MMU: capabilities {:?}", iommu.get_capability(),);
        println!("        extended {:?}", iommu.get_extended_capability());
    } else {
        println!("IO MMU: None");
    }

    // Select appropriate guest depending on selected features
    if cfg!(feature = "guest_linux") {
        launch_guest(
            &guests::linux::LINUX,
            &acpi_info,
            &host_allocator,
            &guest_allocator,
            memory_map,
            pt_mapper,
        )
    } else if cfg!(feature = "guest_rawc") {
        launch_guest(
            &guests::rawc::RAWC,
            &acpi_info,
            &host_allocator,
            &guest_allocator,
            memory_map,
            pt_mapper,
        )
    } else if cfg!(feature = "no_guest") {
        launch_guest(
            &guests::void::VOID_GUEST,
            &acpi_info,
            &host_allocator,
            &guest_allocator,
            memory_map,
            pt_mapper,
        )
    } else {
        panic!("Unrecognized guest");
    }
}

fn launch_guest(
    guest: &impl Guest,
    acpi: &AcpiInfo,
    stage1_allocator: &impl FrameAllocator,
    guest_allocator: &impl FrameAllocator,
    memory_map: MemoryMap,
    mut pt_mapper: PtMapper<HostPhysAddr, HostVirtAddr>,
) -> ! {
    initialize_cpu();
    print_vmx_info();

    let mut stage2_allocator = second_stage::second_stage_allocator(stage1_allocator);
    unsafe {
        let mut info = guest.instantiate(acpi, &mut stage2_allocator, guest_allocator, memory_map);
        guests::vmx::save_host_info(&mut info.guest_info);
        second_stage::load(
            &info,
            stage1_allocator,
            &mut stage2_allocator,
            &mut pt_mapper,
        );
    }
    qemu::exit(qemu::ExitCode::Failure);
    first_stage::hlt_loop();
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

    qemu::exit(qemu::ExitCode::Failure);
    first_stage::hlt_loop();
}

#[cfg(test)]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    first_stage::test_panic_handler(info);
    first_stage::hlt_loop();
}
