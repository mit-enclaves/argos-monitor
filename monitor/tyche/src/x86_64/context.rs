use capa_engine::Handle;
use spin::Mutex;
use vmx::fields::{GeneralPurposeField as GPF, VmcsField, REGFILE_SIZE};
use vmx::msr::IA32_LSTAR;
use vmx::ActiveVmcs;

use crate::rcframe::{RCFrame, RCFramePool};

pub struct ContextData {
    // VCPU for this core.
    pub vmcs: Handle<RCFrame>,
    // General purpose registers values for the context.
    pub regs: [usize; REGFILE_SIZE],
    // Extra registers stored in the context.
    // This is necessary due to shared VMCS.
    pub cr3: usize,
    pub rip: usize,
    pub rsp: usize,
}

impl ContextData {
    pub fn save_partial(&mut self, vcpu: &ActiveVmcs<'static>) {
        self.cr3 = vcpu.get(VmcsField::GuestCr3).unwrap();
        self.rip = vcpu.get(VmcsField::GuestRip).unwrap();
        self.rsp = vcpu.get(VmcsField::GuestRsp).unwrap();
    }

    pub fn save(&mut self, vcpu: &mut ActiveVmcs<'static>) {
        self.save_partial(vcpu);
        vcpu.dump_regs(&mut self.regs[0..REGFILE_SIZE]);
        self.regs[GPF::Lstar as usize] = unsafe { IA32_LSTAR.read() } as usize;
        vcpu.flush();
    }

    pub fn restore_partial(&self, vcpu: &mut ActiveVmcs<'static>) {
        vcpu.set(VmcsField::GuestCr3, self.cr3).unwrap();
        vcpu.set(VmcsField::GuestRip, self.rip).unwrap();
        vcpu.set(VmcsField::GuestRsp, self.rsp).unwrap();
    }

    pub fn restore(&self, rc_vmcs: &Mutex<RCFramePool>, vcpu: &mut ActiveVmcs<'static>) {
        let locked = rc_vmcs.lock();
        let rc_frame = locked.get(self.vmcs).unwrap();
        vcpu.load_regs(&self.regs[0..REGFILE_SIZE]);
        unsafe {
            vmx::msr::Msr::new(IA32_LSTAR.address()).write(self.regs[GPF::Lstar as usize] as u64)
        };
        vcpu.switch_frame(rc_frame.frame).unwrap();
        // Restore partial must be called AFTER we set a valid frame.
        self.restore_partial(vcpu);
    }
}
