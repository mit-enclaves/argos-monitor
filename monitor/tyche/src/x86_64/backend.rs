use core::cell::RefCell;

use arena::{Handle, TypedArena};
use capabilities::backend::{Backend, BackendContext};
use capabilities::context::Context;
use capabilities::cpu::{CPUAccess, CPUFlags, CPU};
use capabilities::domain::{
    Domain, DomainAccess, OwnedCapability, SealedStatus, CAPAS_PER_DOMAIN, CONTEXT_PER_DOMAIN,
};
use capabilities::error::{Error, ErrorCode};
use capabilities::memory::{MemoryAccess, MemoryFlags, MemoryRegion};
use capabilities::{Capability, CapabilityType, Ownership, Pool, State};
use mmu::eptmapper::EPT_ROOT_FLAGS;
use mmu::{EptMapper, FrameAllocator};
//use qemu::_print;
use stage_two_abi::GuestInfo;
use utils::{GuestPhysAddr, HostPhysAddr, HostVirtAddr};
use vmx::bitmaps::EptEntryFlags;
use vmx::ActiveVmcs;
use vtd::Iommu;

use super::cpuid;
use crate::allocator::Allocator;
use crate::println;
use crate::statics::{NB_CORES, NB_PAGES};

/// Backend for Intel VT-x x86_64
pub struct BackendX86 {
    pub allocator: Allocator<NB_PAGES>,
    pub guest_info: GuestInfo,
    pub iommu: Option<Iommu>,
    pub locals: [LocalState; NB_CORES],
}

#[derive(Copy, Clone, Debug)]
pub struct LocalState {
    pub current_cpu: Handle<Capability<CPU<BackendX86>>>,
    pub current_domain: Handle<Capability<Domain<BackendX86>>>,
}

pub struct BackendC86Context {
    cr3: usize,
    rip: u64,
    rsp: u64,
}

impl BackendContext for BackendC86Context {
    fn init(&mut self, cr3: usize, rip: usize, rsp: usize) {
        self.cr3 = cr3;
        self.rip = rip as u64;
        self.rsp = rsp as u64;
    }
}

pub struct BackendX86State {
    pub ept: HostPhysAddr,
}

pub enum BackendX86Core {
    Uninitialized,
    // Inactive(VmcsRegion<'static>),
    // Active(ActiveVmcs<'static>),
}

impl BackendX86Core {
    // pub fn initialize(&mut self, frame: Frame, vmxon: &vmx::Vmxon) -> Result<(), TycheError> {
    //     match self {
    //         BackendX86Core::Uninitialized => unsafe {
    //             let vmcs = vmxon.create_vm_unsafe(frame)?;
    //             *self = BackendX86Core::Inactive(vmcs);
    //             Ok(())
    //         },
    //         _ => todo!("Initializing already initialized core"),
    //     }
    // }

    // pub fn activate(&mut self) -> Result<(), TycheError> {
    //     let old_self = replace(self, BackendX86Core::Uninitialized);
    //     let BackendX86Core::Inactive(region) = old_self  else {
    //         todo!("Trying to activate a core that is not inactive");
    //     };
    //     let active = region.set_as_active()?;
    //     *self = BackendX86Core::Active(active);
    //     Ok(())
    // }

    // pub fn deactivate(&mut self) -> Result<(), TycheError> {
    //     let old_self = replace(self, BackendX86Core::Uninitialized);
    //     let BackendX86Core::Active(vcpu) = old_self else {
    //         todo!("Trying to deactivate a core that is active");
    //     };
    //     let inactive = vcpu.deactivate()?;
    //     *self = BackendX86Core::Inactive(inactive);
    //     Ok(())
    // }

    //     pub fn get_active(&self) -> Result<&ActiveVmcs<'static>, TycheError> {
    //         match self {
    //             BackendX86Core::Active(active) => Ok(active),
    //             _ => ErrorCode::WrongCPUState.as_err(),
    //         }
    //     }

    //     pub fn get_active_mut(&mut self) -> Result<&mut ActiveVmcs<'static>, TycheError> {
    //         match self {
    //             BackendX86Core::Active(ref mut active) => Ok(active),
    //             _ => ErrorCode::WrongCPUState.as_err(),
    //         }
    //     }
}

impl BackendX86 {
    pub fn init(&mut self) {}

    pub fn set_iommu(&mut self, iommu_addr: u64) {
        if iommu_addr != 0 {
            unsafe {
                self.iommu = Some(Iommu::new(HostVirtAddr::new(iommu_addr as usize)));
            }
        } else {
            self.iommu = None;
        }
    }

    fn cpu_id(&self) -> usize {
        cpuid()
    }
}

impl Backend for BackendX86 {
    type DomainState = BackendX86State;
    type Core = ActiveVmcs<'static>;
    type CoreState = BackendX86Core;
    type Context = BackendC86Context;
    type Error = vmx::VmxError;

    fn install_region(
        &self,
        pool: &State<'_, Self>,
        capa: &Capability<MemoryRegion>,
    ) -> Result<(), Error<Self::Error>>
    where
        Self: Sized,
    {
        let owner = capa.get_owner()?;
        let domain = pool.get_mut(owner);

        let state = &domain.state;
        let access = capa.access;
        let mut mapper = EptMapper::new(self.allocator.get_physical_offset().as_usize(), state.ept);
        let flags = mem_access_to_ept(access);
        /*println!("In install region for {:?}", owner.idx());
        println!(
            "Mapping {:x?} -- {:x?} [{:x?}]\n",
            access.start, access.end, flags
        );*/
        mapper.map_range(
            &self.allocator,
            GuestPhysAddr::new(access.start.as_usize()),
            access.start,
            access.end.as_usize() - access.start.as_usize(),
            flags,
        );
        /*if owner.idx() == 1 {
            mapper.debug_range(
                GuestPhysAddr::new(access.start.as_usize()),
                access.end.as_usize() - access.start.as_usize(),
                |args| _print(args),
            );
        }*/
        Ok(())
    }

    fn uninstall_region(
        &self,
        _pool: &State<'_, Self>,
        capa: &Capability<MemoryRegion>,
    ) -> Result<(), Error<Self::Error>>
    where
        Self: Sized,
    {
        let owner: Handle<Domain<BackendX86>> = capa.get_owner()?;
        println!("In uninstall region! {:?}", owner.idx());
        Ok(())
    }

    fn create_domain(
        &self,
        pool: &State<'_, Self>,
        capa: &Capability<Domain<Self>>,
    ) -> Result<(), Error<Self::Error>>
    where
        Self: Sized,
    {
        let ept = self
            .allocator
            .allocate_frame()
            .ok_or(ErrorCode::AllocationError.wrap())?
            .zeroed();
        let mut domain = pool.get_mut(capa.handle);
        domain.state.ept = ept.phys_addr;
        Ok(())
    }

    fn install_domain(
        &self,
        _pool: &State<'_, Self>,
        _capa: &Capability<Domain<Self>>,
    ) -> Result<(), Error<Self::Error>>
    where
        Self: Sized,
    {
        // TODO: install EPT on cpu
        // let domain = pool.get_mut(capa.handle);
        // let cpu_capa = self.get_current_cpu(pool);
        // let mut cpu = pool.get_mut(cpu_capa.handle);
        // let vcpu = cpu.core.get_active_mut()?;
        // vcpu.set_ept_ptr(HostPhysAddr::new(
        //     domain.state.ept.as_usize() | EPT_ROOT_FLAGS,
        // ))?;
        Ok(())
    }

    fn uninstall_domain(
        &self,
        _pool: &State<'_, Self>,
        _capa: &Capability<Domain<Self>>,
    ) -> Result<(), Error<Self::Error>>
    where
        Self: Sized,
    {
        //todo!()
        //SHOULD IMPLEMENT
        Ok(())
    }

    fn create_cpu(
        &self,
        _pool: &State<'_, Self>,
        _capa: &Capability<capabilities::cpu::CPU<Self>>,
    ) -> Result<(), Error<Self::Error>>
    where
        Self: Sized,
    {
        Ok(())
    }

    fn install_cpu(
        &self,
        _pool: &State<'_, Self>,
        _capa: &Capability<capabilities::cpu::CPU<Self>>,
        _cpu: &mut Self::Core,
    ) -> Result<(), Error<Self::Error>>
    where
        Self: Sized,
    {
        //todo!()
        Ok(())
    }

    fn uninstall_cpu(
        &self,
        _pool: &State<'_, Self>,
        _capa: &Capability<capabilities::cpu::CPU<Self>>,
        _cpu: &mut Self::Core,
    ) -> Result<(), Error<Self::Error>>
    where
        Self: Sized,
    {
        //todo!()
        //TODO
        Ok(())
    }

    fn init_cpu(
        &self,
        pool: &State<'_, Self>,
        cpu: &mut Self::Core,
        _cpu_handle: Handle<CPU<Self>>,
        domain_handle: Handle<Domain<Self>>,
    ) -> Result<(), Error<Self::Error>> {
        let domain = pool.get(domain_handle);
        cpu.set_ept_ptr(HostPhysAddr::new(
            domain.state.ept.as_usize() | EPT_ROOT_FLAGS,
        ))?;
        Ok(())
    }

    fn switch_context(
        &self,
        pool: &State<'_, Self>,
        caller: Handle<Domain<Self>>,
        callee: Handle<Domain<Self>>,
        to_save: Handle<Capability<Domain<Self>>>,
        to_restore: Handle<Capability<Domain<Self>>>,
        target_cpu: Handle<Capability<CPU<Self>>>,
        cpu: &mut Self::Core,
    ) -> Result<(), Error<Self::Error>> {
        // Save the current CPU state into the caller's to_save context.
        {
            //TODO here we could check stuff for the capa, like having to clear
            //some registers etc.
            let capa = pool.get_capa(to_save);
            let mut dom = pool.get_mut(capa.handle);
            #[allow(unused_assignments)]
            let mut ept_save: u64 = 0;
            {
                match capa.access {
                    DomainAccess::Transition(x) => {
                        // TODO(@aghosn) is it the callee or the caller?
                        if capa.handle != caller {
                            return Err(ErrorCode::InvalidTransition.wrap());
                        }
                        if !dom.contexts.is_allocated(x) {
                            return Err(ErrorCode::OutOfBound.wrap());
                        }
                        let mut to_save_context = dom.contexts.get_mut(Handle::new_unchecked(x));
                        cpu.next_instruction()?;
                        to_save_context.state.cr3 = cpu.get_cr(vmx::ControlRegister::Cr3);
                        to_save_context.state.rip = cpu.get(vmx::Register::Rip);
                        to_save_context.state.rsp = cpu.get(vmx::Register::Rsp);
                        ept_save = cpu.get_ept_ptr()?;
                        if self.get_current_cpu_handle() != target_cpu {
                            println!("We are deactivating?");
                            // TODO
                            // cpu.core.deactivate()?;
                        }
                    }
                    _ => {
                        return Err(ErrorCode::WrongAccessType.wrap());
                    }
                }
            }
            dom.state.ept = HostPhysAddr::new(ept_save as usize);
            println!("Saved the ept {:?}", dom.state.ept);
        }

        // Restore the other state.
        {
            let capa = pool.get_capa(to_restore);
            let dom = pool.get(capa.handle);
            let to_restore_context = {
                match capa.access {
                    DomainAccess::Transition(x) => {
                        //TODO(@aghosn) this should be caller right?
                        if capa.handle != callee {
                            return Err(ErrorCode::InvalidTransition.wrap());
                        }
                        if !dom.contexts.is_allocated(x) {
                            return Err(ErrorCode::OutOfBound.wrap());
                        }
                        dom.contexts.get_mut(Handle::new_unchecked(x))
                    }
                    _ => {
                        return Err(ErrorCode::WrongAccessType.wrap());
                    }
                }
            };

            println!("About to overwrite the values");
            cpu.set_cr(vmx::ControlRegister::Cr3, to_restore_context.state.cr3);
            cpu.set(vmx::Register::Rip, to_restore_context.state.rip);
            cpu.set(vmx::Register::Rsp, to_restore_context.state.rsp);
            println!(
                "We have rip {:x?}, rsp {:#?}, cr3: {:#?}",
                to_restore_context.state.rip,
                to_restore_context.state.rsp,
                to_restore_context.state.cr3
            );
            cpu.set_ept_ptr(HostPhysAddr::new(dom.state.ept.as_usize() | EPT_ROOT_FLAGS))?;
        }
        Ok(())
    }

    fn set_current_domain(&mut self, current: Handle<Capability<Domain<Self>>>) {
        self.locals[self.cpu_id()].current_domain = current;
    }

    fn get_current_domain_handle(&self) -> Handle<Capability<Domain<Self>>> {
        self.locals[self.cpu_id()].current_domain
    }

    fn get_current_cpu_handle(&self) -> Handle<Capability<CPU<Self>>> {
        self.locals[self.cpu_id()].current_cpu
    }

    fn set_current_cpu(&mut self, current: Handle<Capability<CPU<Self>>>) {
        self.locals[self.cpu_id()].current_cpu = current;
    }
}

// ———————————————————————————————— Helpers ————————————————————————————————— //

pub fn mem_access_to_ept(rights: MemoryAccess) -> EptEntryFlags {
    let rights = rights.flags;
    let mut def = EptEntryFlags::READ;
    if rights.contains(MemoryFlags::EXEC) {
        def |= EptEntryFlags::USER_EXECUTE | EptEntryFlags::SUPERVISOR_EXECUTE;
    }
    if rights.contains(MemoryFlags::WRITE) {
        def |= EptEntryFlags::WRITE;
    }
    def
}

// —————————————————— Empty Structures For Initialization ——————————————————— //

pub const EMPTY_OWNED_CAPABILITY: RefCell<OwnedCapability<BackendX86>> =
    RefCell::new(OwnedCapability::Empty);

pub const EMPTY_CONTEXT: RefCell<Context<BackendX86>> = RefCell::new(Context {
    return_context: None,
    state: BackendC86Context {
        cr3: 0,
        rip: 0,
        rsp: 0,
    },
});

pub const EMPTY_DOMAIN: RefCell<Domain<BackendX86>> = RefCell::new(Domain::<BackendX86> {
    sealed: SealedStatus::Unsealed,
    state: BackendX86State {
        ept: HostPhysAddr::new(0),
    },
    allowed_cores: 0,
    ref_count: usize::MAX,
    owned: TypedArena::new([EMPTY_OWNED_CAPABILITY; CAPAS_PER_DOMAIN]),
    contexts: TypedArena::new([EMPTY_CONTEXT; CONTEXT_PER_DOMAIN]),
});

pub const EMPTY_DOMAIN_CAPA: RefCell<Capability<Domain<BackendX86>>> = RefCell::new(Capability {
    owner: Ownership::Empty,
    capa_type: CapabilityType::Resource,
    access: DomainAccess::NONE,
    handle: Handle::null(),
    left: Handle::null(),
    right: Handle::null(),
});

pub const EMPTY_CPU: RefCell<CPU<BackendX86>> = RefCell::new(CPU::<BackendX86> {
    id: usize::MAX,
    ref_count: usize::MAX,
    core: BackendX86Core::Uninitialized,
});

pub const EMPTY_CPU_CAPA: RefCell<Capability<CPU<BackendX86>>> = RefCell::new(Capability {
    owner: Ownership::Empty,
    capa_type: CapabilityType::Resource,
    access: CPUAccess {
        flags: CPUFlags::NONE,
    },
    handle: Handle::null(),
    left: Handle::null(),
    right: Handle::null(),
});
