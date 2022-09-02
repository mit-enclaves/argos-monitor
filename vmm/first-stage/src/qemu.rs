use crate::println;
use x86_64::instructions::port::Port;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
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

pub fn exit(exit_code: ExitCode) -> ! {
    println!("========== Exiting QEMU ==========");
    println!("{}", exit_code.to_str());
    println!("==================================");
    unsafe {
        // Port defined in Cargo.toml under `package.metadata.bootimage.tast-args`
        let mut port = Port::new(0xf4);
        port.write(exit_code as u32);
    }
    crate::hlt_loop();
}
