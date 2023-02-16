//! Risc-V backend

pub mod guest;

use crate::allocator::Allocator;
use crate::debug::qemu::ExitCode;
use crate::hypercalls::{Backend, Domain, ErrorCode, HypercallResult, Hypercalls, Region};
use crate::statics::{
    allocator as get_allocator, domains_arena as get_domains_arena,
    regions_arena as get_regions_arena,
};
use core::arch::asm;
use mmu::FrameAllocator;
use stage_two_abi::Manifest;

pub struct Arch {}

impl Arch {
    pub fn new() -> Self {
        Self {}
    }
}

pub struct Vcpu {}
pub struct Store {}
pub struct Context {}

impl Backend for Arch {
    type Vcpu<'a> = Vcpu;
    type Store = Store;
    type Context = Context;

    const EMPTY_STORE: Self::Store = Store {};
    const EMPTY_CONTEXT: Self::Context = Context {};

    fn debug_iommu(&mut self) -> HypercallResult {
        // No I/O MMU with Risc-V backend
        Ok(Default::default())
    }

    fn domain_seal(
        &mut self,
        _target: usize,
        _current: &mut Domain<Self>,
        _reg_1: usize,
        _reg_2: usize,
        _reg_3: usize,
    ) -> HypercallResult {
        todo!();
    }

    fn domain_create(
        &mut self,
        _store: &mut Self::Store,
        _allocator: &impl FrameAllocator,
    ) -> Result<(), ErrorCode> {
        todo!();
    }

    fn domain_restore<'a>(
        &mut self,
        _store: &Self::Store,
        _context: &Self::Context,
        _vcpu: &mut Self::Vcpu<'a>,
    ) -> Result<(), ErrorCode> {
        todo!();
    }

    fn domain_save<'a>(
        &mut self,
        _context: &mut Self::Context,
        _vcpu: &mut Self::Vcpu<'a>,
    ) -> Result<(), ErrorCode> {
        todo!();
    }

    fn add_region(
        &mut self,
        _store: &mut Self::Store,
        _region: &Region,
        _access: usize,
        _allocator: &impl FrameAllocator,
    ) -> Result<(), ErrorCode> {
        todo!();
    }

    fn remove_region(
        &mut self,
        _store: &mut Self::Store,
        _region: &Region,
        _allocator: &impl FrameAllocator,
    ) -> Result<(), ErrorCode> {
        todo!();
    }
}

/// Halt the CPU in a spinloop;
pub fn hlt() -> ! {
    loop {
        // See core::arch::asm::riscv64:
        //
        // The PAUSE instruction is a HINT that indicates the current hart's rate of instruction retirement
        // should be temporarily reduced or paused. The duration of its effect must be bounded and may be zero.
        unsafe { asm!(".insn i 0x0F, 0, x0, x0, 0x010", options(nomem, nostack)) }
    }
}

pub fn exit_qemu(exit_code: ExitCode) {
    // TODO: find exit address
    const RISCV_EXIT_ADDR: u64 = 0xdeadbeef;

    unsafe {
        let exit_code = exit_code as u32;
        asm!(
            "sw {0}, 0({1})",
            in(reg) exit_code,
            in(reg) RISCV_EXIT_ADDR
        );
    }
}

/// Architecture specific initialization.
pub fn init(manifest: &Manifest, _cpuid: usize) {
    let mut allocator = Allocator::new(
        get_allocator(),
        (manifest.voffset - manifest.poffset) as usize,
    );
    let domains_arena = get_domains_arena();
    let regions_arena = get_regions_arena();
    let _hypercalls = Hypercalls::new(
        &manifest,
        Arch::new(),
        &mut [Some(Vcpu {})],
        &mut allocator,
        domains_arena,
        regions_arena,
    );
    // TODO
}

pub fn cpuid() -> usize {
    todo!();
}
