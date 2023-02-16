use core::arch::asm;

use mmu::RangeAllocator;
use stage_two_abi::{GuestInfo, VgaInfo};

use crate::acpi::AcpiInfo;
use crate::mmu::MemoryMap;
use crate::println;
use crate::vmx::bitmaps::{exit_qualification, ExceptionBitmap};
use crate::vmx::{ActiveVmcs, ControlRegister, Register, VmxError, VmxExitReason};

pub mod boot_params;
pub mod common;
pub mod linux;
pub mod rawc;
pub mod vmx;
pub mod void;

#[derive(PartialEq, Debug)]
pub enum HandlerResult {
    Resume,
    Exit,
    Crash,
}

pub struct ManifestInfo {
    pub guest_info: GuestInfo,
    pub vga_info: VgaInfo,
    pub iommu: u64,
}

impl Default for ManifestInfo {
    fn default() -> Self {
        Self {
            guest_info: Default::default(),
            vga_info: VgaInfo::no_vga(),
            iommu: Default::default(),
        }
    }
}

pub trait Guest {
    unsafe fn instantiate(
        &self,
        acpi: &AcpiInfo,
        host_allocator: &impl RangeAllocator,
        guest_allocator: &impl RangeAllocator,
        memory_map: MemoryMap,
        rsdp: u64,
    ) -> ManifestInfo;

    unsafe fn vmcall_handler(&self, vcpu: &mut ActiveVmcs) -> Result<HandlerResult, VmxError>;

    /// Enables exception interposition in the host.
    ///
    /// @msg: Add whatever exceptions you want to catch to the bitmap.
    fn enable_exceptions(&self, vcpu: &mut ActiveVmcs) -> Result<(), VmxError> {
        vcpu.set_exception_bitmap(
            ExceptionBitmap::INVALID_OPCODE | ExceptionBitmap::DEVICE_NOT_AVAILABLE,
        )
    }

    fn handle_exit(
        &self,
        vcpu: &mut ActiveVmcs,
        reason: VmxExitReason,
    ) -> Result<HandlerResult, VmxError> {
        match reason {
            VmxExitReason::Vmcall => unsafe { self.vmcall_handler(vcpu) },
            VmxExitReason::Cpuid => {
                let input_eax = vcpu.get(Register::Rax);
                let input_ecx = vcpu.get(Register::Rcx);
                let eax: u64;
                let ebx: u64;
                let ecx: u64;
                let edx: u64;

                unsafe {
                    // Note: LLVM reserves %rbx for its internal use, so we need to use a scratch
                    // register for %rbx here.
                    asm!(
                        "mov rbx, {tmp}",
                        "cpuid",
                        "mov {tmp}, rbx",
                        tmp = out(reg) ebx ,
                        inout("rax") input_eax => eax,
                        inout("rcx") input_ecx => ecx,
                        out("rdx") edx,
                    )
                }

                vcpu.set(Register::Rax, eax);
                vcpu.set(Register::Rbx, ebx);
                vcpu.set(Register::Rcx, ecx);
                vcpu.set(Register::Rdx, edx);

                vcpu.next_instruction()?;
                Ok(HandlerResult::Resume)
            }
            VmxExitReason::ControlRegisterAccesses => {
                let qualification = vcpu.exit_qualification()?.control_register_accesses();
                match qualification {
                    exit_qualification::ControlRegisterAccesses::MovToCr(cr, reg) => {
                        if cr != ControlRegister::Cr4 {
                            todo!("Handle {:?}", cr);
                        }
                        let value = vcpu.get(reg) as usize;
                        vcpu.set_cr4_shadow(value)?;
                        let real_value = value | (1 << 13); // VMXE
                        vcpu.set_cr(cr, real_value);

                        vcpu.next_instruction()?;
                    }
                    _ => todo!("Emulation not yet implemented for {:?}", qualification),
                };
                Ok(HandlerResult::Resume)
            }
            VmxExitReason::EptViolation => {
                let addr = vcpu.guest_linear_addr()?;
                println!("EPT Violation: 0x{:x}", addr.as_u64());
                Ok(HandlerResult::Crash)
            }
            VmxExitReason::Xsetbv => {
                let ecx = vcpu.get(Register::Rcx);
                let eax = vcpu.get(Register::Rax);
                let edx = vcpu.get(Register::Rdx);

                let xrc_id = ecx & 0xFFFFFFFF; // Ignore 32 high-order bits
                if xrc_id != 0 {
                    println!("Xsetbv: invalid rcx 0x{:x}", ecx);
                    return Ok(HandlerResult::Crash);
                }

                unsafe {
                    asm!(
                        "xsetbv",
                        in("ecx") ecx,
                        in("eax") eax,
                        in("edx") edx,
                    );
                }

                vcpu.next_instruction()?;
                Ok(HandlerResult::Resume)
            }
            VmxExitReason::Wrmsr => {
                let ecx = vcpu.get(Register::Rcx);
                if ecx >= 0x4B564D00 && ecx <= 0x4B564DFF {
                    // Custom MSR range, used by KVM
                    // See https://docs.kernel.org/virt/kvm/x86/msr.html
                    // TODO: just ignore them for now, should add support in the future
                    vcpu.next_instruction()?;
                    Ok(HandlerResult::Resume)
                } else {
                    println!("Unknown MSR: 0x{:x}", ecx);
                    Ok(HandlerResult::Crash)
                }
            }
            VmxExitReason::Exception => {
                match vcpu.interrupt_info() {
                    Ok(Some(exit)) => {
                        println!("Exception: {:?}", vcpu.interrupt_info());
                        // Inject the fault back into the guest.
                        let injection = exit.as_injectable_u32();
                        vcpu.set_vm_entry_interruption_information(injection)?;
                        Ok(HandlerResult::Resume)
                    }
                    _ => {
                        println!("VM received an exception");
                        println!("{:?}", vcpu);
                        Ok(HandlerResult::Crash)
                    }
                }
            }
            _ => {
                println!(
                    "Emulation is not yet implemented for exit reason: {:?}",
                    reason
                );
                println!("{:?}", vcpu);
                Ok(HandlerResult::Crash)
            }
        }
    }
}
