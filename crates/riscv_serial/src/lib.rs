#![no_std]

use core::fmt::Write;
use core::{fmt, ptr}; 
use spin::Mutex;
use core::arch::asm;

pub static WRITER: Mutex<Option<Writer>> = Mutex::new(None);

pub fn init_print(mut writer: Writer) {
    let mut static_writer = WRITER.lock(); 
    static_writer.replace(writer);
}

pub struct Writer { 
    serial_port_base_addr: usize,
}

impl Writer {
    pub fn new(serial_port_base_addr: usize) -> Self { 
        Writer {
            serial_port_base_addr,
        }
    }
    
    fn write_char(&mut self, c: char) {
        unsafe {
            ptr::write_volatile(self.serial_port_base_addr as *mut char, c);
            for n in 1..100001 { 
                asm!("nop");
            }
        }
        /* asm!("li t0, {}", in(reg) self.serial_port_base_addr);
        asm!("li t1, {}", in(reg) c);
        asm!("sb t1, 0(t0)"); */
    }
}

impl fmt::Write for Writer { 
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for c in s.chars() { 
            self.write_char(c);
        }
        Ok(())
    }
}

//#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    //disable interrupts     
    let mut writer = WRITER.lock();
    if let Some(writer) = writer.as_mut() { 
        writer.write_fmt(args).unwrap();
    }
    //enable interrupts 
}
