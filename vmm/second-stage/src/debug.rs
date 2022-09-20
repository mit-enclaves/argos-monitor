//! Debug Module
//!
//! This module is used for debugging, but is excluded from the TCB when compiling on release mode
//! (it is instead replaced by a stub module wity no-ops).

// ———————————————————————————— Print Facilities ———————————————————————————— //

pub mod serial {
    use core::fmt;
    use core::fmt::Write;
    use uart_16550::SerialPort;

    /// Serial port used to log to stdout when running in Qemu.
    //  TODO: wrap port in mutex
    static mut SERIAL_PORT: SerialPort = unsafe { SerialPort::new(0x3F8) };

    /// Internal function used to print to stdout when running in Qemu.
    pub fn _print(args: fmt::Arguments) {
        // SAFETY:
        //
        // For now we are running in single-threaded mode, and the interrupts are disabled within the
        // VMM.
        unsafe {
            SERIAL_PORT
                .write_fmt(args)
                .expect("Printing to serial failed");
        }
    }
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        $crate::debug::serial::_print(core::format_args!($($arg)*));
    };
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", core::format_args!($($arg)*)));
}

// —————————————————————————————————— Qemu —————————————————————————————————— //

#[derive(Clone, Copy)]
#[repr(u32)]
pub enum ExitCode {
    Success = 0x10,
    Failure = 0x11,
}

impl ExitCode {
    pub fn to_str(self) -> &'static str {
        match self {
            ExitCode::Success => "Success",
            ExitCode::Failure => "Failure",
        }
    }
}

pub mod qemu {
    pub use super::ExitCode;
    use crate::hlt;
    use core::arch::asm;

    const QEMU_EXIT_PORT: u16 = 0xf4;

    pub fn exit(exit_code: ExitCode) -> ! {
        println!("========= Exiting Second Stage =========");
        println!("{}", exit_code.to_str());
        println!("========================================");

        unsafe {
            let exit_code = exit_code as u32;
            asm!(
                "out dx, eax",
                in("dx") QEMU_EXIT_PORT,
                in("eax") exit_code,
                options(nomem, nostack, preserves_flags)
            );
        }

        hlt();
    }
}
