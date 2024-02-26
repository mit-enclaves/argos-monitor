#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(first_stage::test_runner)]
#![reexport_test_harness_main = "test_main"]

extern crate alloc;

use acpi::AcpiTables;
use bootloader::{entry_point, BootInfo};
use core::panic::PanicInfo;
use core::sync::atomic::*;
use first_stage::acpi::AcpiInfo;
use first_stage::getsec::configure_getsec;
use first_stage::acpi_handler::TycheACPIHandler;
use first_stage::guests;
use first_stage::guests::Guest;
use first_stage::mmu::MemoryMap;
use first_stage::println;
use first_stage::second_stage;
use first_stage::smp;
use first_stage::smx::senter;
use first_stage::{HostPhysAddr, HostVirtAddr};
use mmu::{PtMapper, RangeAllocator};
use qemu;
use stage_two_abi::VgaInfo;
use vmx;
use vtd;
use x86_64::registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags};

entry_point!(kernel_main);

fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    // Initialize display, if any
    let mut vga_info = VgaInfo::no_vga();
    if let Some(buffer) = boot_info.framebuffer.as_mut().take() {
        vga_info = first_stage::init_display(buffer);
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
        let rdx: u64;
        use core::arch::asm;
        asm! {
            "push rbx",
            "mov rax, 0",
            "mov rbx, 0",
            "mov rcx, 3",
            "mov rdx, 4",
            "getsec",
            "mov r10, rbx",
            "pop rbx",
            out("rax") rax,
            out("r10") rbx,
            out("rcx") rcx,
            out("rdx") rdx,
        };

        println!(
            "GETSEC  rax: 0x{:x} - rbx: 0x{:x} - rcx: 0x{:x} - rdx: 0x{:x}",
            rax, rbx, rcx, rdx
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

    let (host_allocator, guest_allocator, memory_map, mut pt_mapper) = unsafe {
        first_stage::init_memory(physical_memory_offset, &mut boot_info.memory_regions)
            .expect("Failed to initialize memory")
    };

    // Parse RSDP tables
    let rsdp = boot_info
        .rsdp_addr
        .into_option()
        .expect("Missing RSDP address");

    let acpi_tables = match unsafe { AcpiTables::from_rsdp(TycheACPIHandler, rsdp as usize) } {
        Ok(acpi_tables) => acpi_tables,
        Err(err) => panic!("Failed to parse the ACPI table: {:?}", err),
    };

    let acpi_platform_info = match acpi_tables.platform_info() {
        Ok(platform_info) => platform_info,
        Err(err) => panic!("Unable to get platform info from the ACPI table: {:?}", err),
    };

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

    // Initiates the SMP boot process
    unsafe {
        smp::boot(
            acpi_platform_info,
            &host_allocator,
            &mut pt_mapper,
        );
    }

    // Enable interrupts
    x86_64::instructions::interrupts::disable();

    // Select appropriate guest depending on selected features
    if cfg!(feature = "guest_linux") {
        launch_guest(
            &guests::linux::LINUX,
            &acpi_info,
            &host_allocator,
            &guest_allocator,
            vga_info,
            memory_map,
            pt_mapper,
            rsdp as u64,
        )
    } else if cfg!(feature = "guest_rawc") {
        launch_guest(
            &guests::rawc::RAWC,
            &acpi_info,
            &host_allocator,
            &guest_allocator,
            vga_info,
            memory_map,
            pt_mapper,
            rsdp as u64,
        )
    } else if cfg!(feature = "no_guest") {
        launch_guest(
            &guests::void::VOID_GUEST,
            &acpi_info,
            &host_allocator,
            &guest_allocator,
            vga_info,
            memory_map,
            pt_mapper,
            rsdp as u64,
        )
    } else {
        panic!("Unrecognized guest");
    }
}

fn launch_guest(
    guest: &impl Guest,
    acpi: &AcpiInfo,
    stage1_allocator: &impl RangeAllocator,
    guest_allocator: &impl RangeAllocator,
    vga_info: VgaInfo,
    memory_map: MemoryMap,
    mut pt_mapper: PtMapper<HostPhysAddr, HostVirtAddr>,
    rsdp: u64,
) -> ! {
    let mut stage2_allocator = second_stage::second_stage_allocator(stage1_allocator);
    unsafe {
        println!("Loading guest");
        let mut info = guest.instantiate(
            acpi,
            &mut stage2_allocator,
            guest_allocator,
            memory_map,
            rsdp,
        );
        info.vga_info = vga_info;
        println!("Saving host state");
        guests::vmx::save_host_info(&mut info.guest_info);
        println!("Loading stage 2");
        let stage2 = second_stage::load(
            &info,
            stage1_allocator,
            &mut stage2_allocator,
            &mut pt_mapper,
        );
        println!("Jumping into stage 2");
        configure_getsec(stage2.as_slice());
        smp::BSP_READY.store(true, Ordering::SeqCst);
        senter();
    }

    println!("Failed to jump into stage 2");
    qemu::exit(qemu::ExitCode::Failure);
    first_stage::hlt_loop();
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
