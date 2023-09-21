use capa_engine::Handle;
use spin::Mutex;
use vmx::msr::IA32_LSTAR;
use vmx::{ActiveVmcs, ControlRegister, Register, REGFILE_CONTEXT_SIZE, REGFILE_SIZE};

use crate::rcframe::{RCFrame, RCFramePool};

pub struct ContextData {
    // VCPU for this core.
    pub vmcs: Handle<RCFrame>,
    // All register values for the context.
    pub regs: [u64; REGFILE_CONTEXT_SIZE],
}

impl ContextData {
    pub fn save_partial(&mut self, vcpu: &ActiveVmcs<'static>) {
        self.regs[Register::Cr3.as_usize()] = vcpu.get_cr(ControlRegister::Cr3) as u64;
        self.regs[Register::Rip.as_usize()] = vcpu.get(Register::Rip);
        self.regs[Register::Rsp.as_usize()] = vcpu.get(Register::Rsp);
    }

    pub fn save(&mut self, vcpu: &mut ActiveVmcs<'static>) {
        self.save_partial(vcpu);
        vcpu.dump_regs(&mut self.regs[0..REGFILE_SIZE]);
        self.regs[Register::Lstar.as_usize()] = unsafe { IA32_LSTAR.read() };
        vcpu.flush();
    }

    pub fn restore_partial(&self, vcpu: &mut ActiveVmcs<'static>) {
        vcpu.set_cr(
            ControlRegister::Cr3,
            self.regs[Register::Cr3.as_usize()] as usize,
        );
        vcpu.set(Register::Rip, self.regs[Register::Rip.as_usize()]);
        vcpu.set(Register::Rsp, self.regs[Register::Rsp.as_usize()]);
    }

    pub fn set_register(&mut self, reg: Register, value: u64) {
        self.regs[reg.as_usize()] = value;
    }

    pub fn restore(&self, rc_vmcs: &Mutex<RCFramePool>, vcpu: &mut ActiveVmcs<'static>) {
        let locked = rc_vmcs.lock();
        let rc_frame = locked.get(self.vmcs).unwrap();
        vcpu.load_regs(&self.regs[0..REGFILE_SIZE]);
        unsafe {
            vmx::msr::Msr::new(IA32_LSTAR.address()).write(self.regs[Register::Lstar.as_usize()])
        };
        vcpu.switch_frame(rc_frame.frame).unwrap();
        // Restore partial must be called AFTER we set a valid frame.
        self.restore_partial(vcpu);
    }
}
