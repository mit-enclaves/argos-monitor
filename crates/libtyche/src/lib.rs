use core::arch::asm;

// ——————————————————————————————— Hypercalls ——————————————————————————————— //

#[derive(Debug)]
#[repr(usize)]
#[rustfmt::skip]
pub enum VmCalls {
    DomainGetOwnId = 0x100,
    DomainCreate   = 0x101,
    DomainSeal     = 0x102,
    RegionSplit    = 0x200,
    Exit           = 0x500,
}

// —————————————————————————————— Error Codes ——————————————————————————————— //

#[derive(Debug, Clone, Copy)]
#[repr(usize)]
pub enum ErrorCode {
    Success = 0,
    Failure = 1,
    UnknownVmCall = 2,
    OutOfMemory = 3,
    DomainOutOfBound = 4,
    RegionOutOfBound = 5,
    RegionCapaOutOfBound = 6,
    InvalidRegionCapa = 7,
    RegionNotExclusive = 8,
    InvalidAddress = 9,
}

// ————————————————————————————————— Calls —————————————————————————————————— //

#[derive(Debug)]
pub struct DomainId(pub usize);

pub fn domain_get_own_id() -> Result<DomainId, ErrorCode> {
    do_vmcall(VmCalls::DomainGetOwnId, 0, 0, 0).map(|(id, _, _)| DomainId(id))
}

pub fn domain_create() -> Result<DomainId, ErrorCode> {
    do_vmcall(VmCalls::DomainCreate, 0, 0, 0).map(|(id, _, _)| DomainId(id))
}

pub fn exit() -> Result<(), ErrorCode> {
    do_vmcall(VmCalls::Exit, 0, 0, 0).map(|_| ())
}

fn do_vmcall(
    vmcall: VmCalls,
    arg_1: usize,
    arg_2: usize,
    arg_3: usize,
) -> Result<(usize, usize, usize), ErrorCode> {
    let result: ErrorCode;
    let val_1: usize;
    let val_2: usize;
    let val_3: usize;
    unsafe {
        let res: usize;
        asm!(
            "vmcall",
            inout("eax") vmcall as usize => res,
            inout("ecx") arg_1 => val_1,
            inout("edx") arg_2 => val_2,
            inout("esi") arg_3 => val_3,
        );
        result = match res {
            0..=9 => core::mem::transmute(res),
            _ => ErrorCode::Failure,
        };
    }
    match result {
        ErrorCode::Success => Ok((val_1, val_2, val_3)),
        _ => Err(result),
    }
}
