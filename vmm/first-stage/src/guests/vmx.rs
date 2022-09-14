//! Guest VMX utils

use core::arch::asm;

use vmx::fields;
use vmx::fields::traits::*;
use vmx::msr;
use vmx::{ActiveVmcs, VmxError};
use crate::gdt;

use x86_64::instructions::tables::{sgdt, sidt};
use x86_64::registers::model_specific::Efer;
use x86_64::registers::segmentation;
use x86_64::registers::segmentation::Segment;

/// Saves the host state (control registers, segments...), so that they are restored on VM Exit.
pub fn save_host_state<'active, 'vmx>(_vmcs: &mut ActiveVmcs<'active, 'vmx>) -> Result<(), VmxError> {
    // NOTE: See section 24.5 of volume 3C.

    // Segments
    let cs = segmentation::CS::get_reg();
    let ds = segmentation::DS::get_reg();
    let es = segmentation::ES::get_reg();
    let fs = segmentation::FS::get_reg();
    let gs = segmentation::GS::get_reg();
    let ss = segmentation::SS::get_reg();
    let tr: u16;
    let gdt = sgdt();
    let idt = sidt();

    unsafe {
        // There is no nice wrapper to read `tr` in the x86_64 crate.
        asm!("str {0:x}",
                out(reg) tr,
                options(att_syntax, nostack, nomem, preserves_flags));
    }

    unsafe {
        fields::HostState16::CsSelector.vmwrite(cs.0)?;
        fields::HostState16::DsSelector.vmwrite(ds.0)?;
        fields::HostState16::EsSelector.vmwrite(es.0)?;
        fields::HostState16::FsSelector.vmwrite(fs.0)?;
        fields::HostState16::GsSelector.vmwrite(gs.0)?;
        fields::HostState16::SsSelector.vmwrite(ss.0)?;
        fields::HostState16::TrSelector.vmwrite(tr)?;

        // NOTE: those might throw an exception depending on the CPU features, let's just
        // ignore them for now.
        // VmcsHostStateNat::FsBase.vmwrite(FS::read_base().as_u64() as usize)?;
        // VmcsHostStateNat::GsBase.vmwrite(GS::read_base().as_u64() as usize)?;

        fields::HostStateNat::IdtrBase.vmwrite(idt.base.as_u64() as usize)?;
        fields::HostStateNat::GdtrBase.vmwrite(gdt.base.as_u64() as usize)?;

        // Save TR base
        let tr_offset = (tr >> 3) as usize;
        let gdt = gdt::gdt().as_raw_slice();
        let low = gdt[tr_offset];
        let high = gdt[tr_offset + 1];
        let tr_base = get_tr_base(high, low);
        fields::HostStateNat::TrBase.vmwrite(tr_base as usize)?;
    }

    // MSRs
    unsafe {
        fields::HostStateNat::Ia32SysenterEsp.vmwrite(msr::SYSENTER_ESP.read() as usize)?;
        fields::HostStateNat::Ia32SysenterEip.vmwrite(msr::SYSENTER_EIP.read() as usize)?;
        fields::HostState32::Ia32SysenterCs.vmwrite(msr::SYSENTER_CS.read() as u32)?;
        fields::HostState64::Ia32Efer.vmwrite(Efer::read().bits())?;
    }

    // Control registers
    let cr0: usize;
    let cr3: usize;
    let cr4: usize;
    unsafe {
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        fields::HostStateNat::Cr0.vmwrite(cr0)?;
        fields::HostStateNat::Cr3.vmwrite(cr3)?;
        fields::HostStateNat::Cr4.vmwrite(cr4)
    }
}

// ———————————————————————————— Helper Functions ———————————————————————————— //

/// Construct the TR base from its system segment descriptor.
///
/// See Intel manual 7.2.3.
fn get_tr_base(desc_high: u64, desc_low: u64) -> u64 {
    const BASE_2_MASK: u64 = ((1 << 8) - 1) << 24;
    const BASE_1_MASK: u64 = ((1 << 24) - 1) << 16;
    const LOW_32_BITS_MASK: u64 = (1 << 32) - 1;

    let mut ptr = 0;
    ptr |= (desc_high & LOW_32_BITS_MASK) << 32;
    ptr |= (desc_low & BASE_2_MASK) >> 32;
    ptr |= (desc_low & BASE_1_MASK) >> 16;
    ptr
}
