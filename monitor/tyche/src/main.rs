#![no_std]
#![no_main]

use core::panic::PanicInfo;

use log::LevelFilter;
#[cfg(target_arch = "riscv64")]
use riscv_tyche::RVManifest;
use stage_two_abi::entry_point;
use tyche;
use tyche::debug::qemu;
use tyche::{arch, println};

use core::arch::asm; 

entry_point!(tyche_entry_point);

const LOG_LEVEL: LevelFilter = LevelFilter::Info;

#[cfg(target_arch = "x86_64")]
fn tyche_entry_point() -> ! {
    arch::arch_entry_point(LOG_LEVEL);
}

#[cfg(all(target_arch = "riscv64"), not(feature = "visionfive2"))]
fn tyche_entry_point(hartid: usize, manifest: RVManifest) -> ! {
    arch::arch_entry_point(hartid, manifest, LOG_LEVEL);
}

#[cfg(all(target_arch = "riscv64"), feature = "visionfive2")]
fn tyche_entry_point(hartid: u64, arg1: u64, next_addr: u64, next_mode: u64) -> ! {
    //use riscv_utils::SERIAL_PORT_BASE_ADDRESS;
    //use riscv_utils::{SERIAL_PORT_BASE_ADDRESS, RV_VF2_UART_BAUD_RATE};
    //use tyche::riscv::launch_guest;
   
    //let writer = riscv_serial::Writer::new(SERIAL_PORT_BASE_ADDRESS);
    //riscv_serial::init_print(writer);


    //riscv_serial::_print(core::format_args!("Hello my name is Neelu!"));

    //use uart8250::MmioUart8250; 

    //static mut SERIAL_PORT: Option<MmioUart8250> = None; 

    /*unsafe { 
        let serial_port = MmioUart8250::new(SERIAL_PORT_BASE_ADDRESS);
        serial_port.init(24000000, RV_VF2_UART_BAUD_RATE);
        serial_port.write_byte(0x41);
        serial_port.write_byte(0x42);
    }*/

    /* unsafe {
        asm!(
            "li t0, 0x10000000",
            "li t1, 0x41",
            "sb t1, 0(t0)",
            "li t1, 0x42",
            "sb t1, 0(t0)",
            "li t1, 0x43",
            "sb t1, 0(t0)",
            "li t1, 0x44",
            "sb t1, 0(t0)",
            "li t1, 0x45",
            "sb t1, 0(t0)",
            "li t1, 0x46",
            "sb t1, 0(t0)",
            "li t1, 0x47",
            "sb t1, 0(t0)",
            "li t1, 0x48",
            "sb t1, 0(t0)",
            "li t1, 0x49",
            "sb t1, 0(t0)",
            "li t1, 0x4a",
            "sb t1, 0(t0)",
            "li t1, 0x4b",
            "sb t1, 0(t0)",
            "li t1, 0x4c",
            "sb t1, 0(t0)",
        );
    } */

    //riscv_serial::_print(core::format_args!("hello meri maata - \r\n"));

    //println!("HELLO_WORLD");

    //println!("============== HELLO FROM TYCHE ===============");

    //println!("***********************************************");

    //println!("neverhaveieverseenthiskindofthingman!");

    //logger::init(LOG_LEVEL);
    arch::arch_entry_point(hartid, arg1, next_addr, next_mode, LOG_LEVEL);
    //launch_guest(hartid, arg1, next_addr, next_mode);
    qemu::exit(qemu::ExitCode::Success); 
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("CPU {}: Panicked", arch::cpuid());
    println!("{:#?}", info);
    qemu::exit(qemu::ExitCode::Failure);
}
