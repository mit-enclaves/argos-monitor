use core::arch::asm;

use capa_engine::CapaInfo;

// ——————————————————————————————— Hypercalls ——————————————————————————————— //

#[derive(Debug)]
#[repr(usize)]
#[rustfmt::skip]
pub enum VmCalls {
    DomainCreate      = 0x1,
    SealDomain        = 0x2,
    Share             = 0x3,
    Send             = 0x4,
    SegmentRegion     = 0x5,
    Revoke            = 0x6,
    Duplicate         = 0x7,
    Enumerate         = 0x8,
    Switch            = 0x9,
    Exit              = 0xA,
    Debug             = 0xB,
    IpiTest           = 0xF,
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
    RegionNotOwned = 8,
    InvalidAddress = 9,
    InvalidDomain = 10,
    DomainIsSealed = 11,
    StoreAccessOutOfBound = 12,
    BadParameters = 13,
    RegionIsShared = 14,
}

// ———————————————————————————— Data Structures ————————————————————————————— //

pub struct RegionInfo {
    pub start: usize,
    pub end: usize,
    pub flags: usize,
}

// ————————————————————————————————— Calls —————————————————————————————————— //

#[derive(Debug)]
pub struct DomainId(pub usize);

#[derive(Debug)]
pub struct RevokHandle(pub usize);

pub struct RegionHandle(pub usize);

pub fn domain_create() -> Result<usize, ErrorCode> {
    do_vmcall(VmCalls::DomainCreate, 0, 0, 0, 0, 0, 0, 0)
        .map(|(managment, _, _, _, _, _, _)| managment)
}

pub fn seal_domain(
    domain: usize,
    core_map: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
) -> Result<DomainId, ErrorCode> {
    do_vmcall(
        VmCalls::SealDomain,
        domain,
        core_map,
        arg1,
        arg2,
        arg3,
        0,
        0,
    )
    .map(|(domain, _, _, _, _, _, _)| DomainId(domain))
}

// pub fn share(
//     target: usize,
//     capa: usize,
//     arg1: usize,
//     arg2: usize,
//     arg3: usize,
// ) -> Result<usize, ErrorCode> {
//     do_vmcall(VmCalls::Share, target, capa, arg1, arg2, arg3, 0, 0)
//         .map(|(left, _, _, _, _, _, _)| left)
// }

pub fn send(target: usize, capa: usize) -> Result<(), ErrorCode> {
    do_vmcall(VmCalls::Send, capa, target, 0, 0, 0, 0, 0).map(|_| ())
}

pub fn segment_region(
    capa: usize,
    start_1: usize,
    end_1: usize,
    prot_1: usize,
    start_2: usize,
    end_2: usize,
    prot_2: usize,
) -> Result<(usize, usize), ErrorCode> {
    do_vmcall(
        VmCalls::SegmentRegion,
        capa,
        start_1,
        end_1,
        prot_1,
        start_2,
        end_2,
        prot_2,
    )
    .map(|(left, right, _, _, _, _, _)| (left, right))
}

pub fn revoke(capa: usize) -> Result<(), ErrorCode> {
    do_vmcall(VmCalls::Revoke, capa, 0, 0, 0, 0, 0, 0).map(|(_, _, _, _, _, _, _)| ())
}

pub fn duplicate(capa: usize) -> Result<usize, ErrorCode> {
    do_vmcall(VmCalls::Duplicate, capa, 0, 0, 0, 0, 0, 0).map(|(capa, _, _, _, _, _, _)| capa)
}

pub fn enumerate(next_token: usize) -> Result<Option<(CapaInfo, usize)>, ErrorCode> {
    let (v1, v2, v3, next, _, _, _) = do_vmcall(VmCalls::Enumerate, next_token, 0, 0, 0, 0, 0, 0)?;
    let info = CapaInfo::deserialize(v1, v2, v3 as u16).expect("Deserialization should not fail");
    Ok(Some((info, next)))
}

pub fn switch(handle: usize, cpu: usize) -> Result<usize, ErrorCode> {
    do_vmcall(VmCalls::Switch, handle, cpu, 0, 0, 0, 0, 0)
        .map(|(return_handle, _, _, _, _, _, _)| return_handle)
}

pub fn send_ipi(cpu: usize) -> Result<(), ErrorCode> {
    do_vmcall(VmCalls::IpiTest, cpu, 0, 0, 0, 0, 0, 0).map(|(_, _, _, _, _, _, _)| ())
}

pub fn exit() -> Result<(), ErrorCode> {
    do_vmcall(VmCalls::Exit, 0, 0, 0, 0, 0, 0, 0).map(|_| ())
}

pub fn debug() -> Result<(), ErrorCode> {
    do_vmcall(VmCalls::Debug, 0, 0, 0, 0, 0, 0, 0).map(|_| ())
}

fn do_vmcall(
    vmcall: VmCalls,
    arg_1: usize,
    arg_2: usize,
    arg_3: usize,
    arg_4: usize,
    arg_5: usize,
    arg_6: usize,
    arg_7: usize,
) -> Result<(usize, usize, usize, usize, usize, usize, usize), ErrorCode> {
    let result: ErrorCode;
    let val_1: usize;
    let val_2: usize;
    let val_3: usize;
    let val_4: usize;
    let val_5: usize;
    let val_6: usize;
    let val_7: usize;
    unsafe {
        let res: usize;
        asm!(
            "vmcall",
            inout("eax") vmcall as usize => res,
            inout("edi") arg_1 => val_1,
            inout("esi") arg_2 => val_2,
            inout("edx") arg_3 => val_3,
            inout("ecx") arg_4 => val_4,
            inout("r8") arg_5 => val_5,
            inout("r9") arg_6 => val_6,
            inout("r10") arg_7 => val_7,
        );
        result = match res {
            0..=14 => core::mem::transmute(res),
            _ => ErrorCode::Failure,
        };
    }
    match result {
        ErrorCode::Success => Ok((val_1, val_2, val_3, val_4, val_5, val_6, val_7)),
        _ => Err(result),
    }
}
