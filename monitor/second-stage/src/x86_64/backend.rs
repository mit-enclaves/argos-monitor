use core::cell::RefCell;
use core::mem::replace;

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
use mmu::{EptMapper, FrameAllocator};
use stage_two_abi::GuestInfo;
use utils::{Frame, GuestPhysAddr, HostPhysAddr, HostVirtAddr};
use vmx::bitmaps::EptEntryFlags;
use vmx::{ActiveVmcs, VmcsRegion};
use vtd::Iommu;

use super::init_vcpu;
use crate::allocator::Allocator;
use crate::error::TycheError;
use crate::println;
use crate::statics::NB_PAGES;

/// Backend for Intel VT-x x86_64
pub struct BackendX86 {
    pub allocator: Allocator<NB_PAGES>,
    pub guest_info: GuestInfo,
    pub iommu: Option<Iommu>,
    pub vmxon: Option<vmx::Vmxon>,
}

pub struct BackendC86Context {}

impl BackendContext for BackendC86Context {
    fn init(&mut self, _arg1: usize, _arg2: usize, _arg3: usize) {
        // TODO
    }
}

pub struct BackendX86State {
    pub ept: HostPhysAddr,
}

pub enum BackendX86Core {
    Uninitialized,
    Inactive(VmcsRegion<'static>),
    Active(ActiveVmcs<'static>),
}

impl BackendX86Core {
    pub fn initialize(&mut self, frame: Frame, vmxon: &vmx::Vmxon) -> Result<(), TycheError> {
        match self {
            BackendX86Core::Uninitialized => unsafe {
                let vmcs = vmxon.create_vm_unsafe(frame)?;
                *self = BackendX86Core::Inactive(vmcs);
                Ok(())
            },
            _ => todo!("Initializing already initialized core"),
        }
    }

    pub fn activate(&mut self) -> Result<(), TycheError> {
        let old_self = replace(self, BackendX86Core::Uninitialized);
        let BackendX86Core::Inactive(region) = old_self  else {
            todo!("Trying to activate a core that is not inactive");
        };
        let active = region.set_as_active()?;
        *self = BackendX86Core::Active(active);
        Ok(())
    }

    pub fn get_active(&self) -> Result<&ActiveVmcs<'static>, TycheError> {
        match self {
            BackendX86Core::Active(active) => Ok(active),
            _ => ErrorCode::WrongCPUState.as_err(),
        }
    }

    pub fn get_active_mut(&mut self) -> Result<&mut ActiveVmcs<'static>, TycheError> {
        match self {
            BackendX86Core::Active(ref mut active) => Ok(active),
            _ => ErrorCode::WrongCPUState.as_err(),
        }
    }
}

impl BackendX86 {
    pub fn init(&mut self) {
        // Create vmxon.
        let frame = self
            .allocator
            .allocate_frame()
            .expect("Failed to allocate VMXON")
            .zeroed();
        unsafe {
            println!("Init the guest");
            self.vmxon = match vmx::vmxon(frame) {
                Ok(vmxon) => {
                    println!("VMXON: ok(vmxon)");
                    Some(vmxon)
                }
                Err(err) => {
                    println!("VMXON: {:?}", err);
                    qemu::exit(qemu::ExitCode::Failure);
                    None
                }
            }
        }
    }

    pub fn set_iommu(&mut self, iommu_addr: u64) {
        if iommu_addr != 0 {
            unsafe {
                self.iommu = Some(Iommu::new(HostVirtAddr::new(iommu_addr as usize)));
            }
        } else {
            self.iommu = None;
        }
    }
}

impl Backend for BackendX86 {
    type DomainState = BackendX86State;
    type Core = BackendX86Core;
    type Error = vmx::VmxError;
    type Context = BackendC86Context;

    fn install_domain(
        &self,
        _pool: &State<'_, Self>,
        _capa: &Capability<Domain<Self>>,
    ) -> Result<(), Error<Self::Error>>
    where
        Self: Sized,
    {
        todo!()
    }

    fn uninstall_domain(
        &self,
        _pool: &State<'_, Self>,
        _capa: &Capability<Domain<Self>>,
    ) -> Result<(), Error<Self::Error>>
    where
        Self: Sized,
    {
        todo!()
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

    fn install_region(
        &self,
        pool: &State<'_, Self>,
        capa: &Capability<MemoryRegion>,
    ) -> Result<(), Error<Self::Error>>
    where
        Self: Sized,
    {
        println!("#### Setup EPT ####");
        let owner = capa.get_owner()?;
        let domain = pool.get_mut(owner);
        let state = &domain.state;
        let access = capa.access;
        let mut mapper = EptMapper::new(self.allocator.get_physical_offset().as_usize(), state.ept);
        let flags = mem_access_to_ept(access);
        mapper.map_range(
            &self.allocator,
            GuestPhysAddr::new(access.start.as_usize()),
            access.start,
            access.end.as_usize() - access.start.as_usize(),
            flags,
        );
        Ok(())
    }

    fn uninstall_region(
        &self,
        _pool: &State<'_, Self>,
        _capa: &Capability<MemoryRegion>,
    ) -> Result<(), Error<Self::Error>>
    where
        Self: Sized,
    {
        todo!()
    }

    fn create_cpu(
        &self,
        pool: &State<'_, Self>,
        capa: &Capability<capabilities::cpu::CPU<Self>>,
    ) -> Result<(), Error<Self::Error>>
    where
        Self: Sized,
    {
        // Get the CPU object.
        let mut cpu = pool.get_mut(capa.handle);
        // Create a VMCS.
        let frame = self
            .allocator
            .allocate_frame()
            .expect("Failed to allocate VMCS")
            .zeroed();

        let Some(ref vmxon) = self.vmxon else {panic!("VMXON is None");};
        cpu.core.initialize(frame, vmxon)?;
        cpu.core.activate()?;
        //TODO init vcpu
        let BackendX86Core::Active(ref mut active) = cpu.core else { return ErrorCode::WrongCPUState.as_err();};
        unsafe {
            init_vcpu(active, &self.guest_info, &self.allocator);
        }
        Ok(())
    }

    fn install_cpu(
        &self,
        _pool: &State<'_, Self>,
        _capa: &Capability<capabilities::cpu::CPU<Self>>,
    ) -> Result<(), Error<Self::Error>>
    where
        Self: Sized,
    {
        todo!()
    }

    fn uninstall_cpu(
        &self,
        _pool: &State<'_, Self>,
        _capa: &Capability<capabilities::cpu::CPU<Self>>,
    ) -> Result<(), Error<Self::Error>>
    where
        Self: Sized,
    {
        todo!()
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
    in_use: false,
    state: BackendC86Context {},
});

pub const EMPTY_DOMAIN: RefCell<Domain<BackendX86>> = RefCell::new(Domain::<BackendX86> {
    state: BackendX86State {
        ept: HostPhysAddr::new(0),
    },
    ref_count: usize::MAX,
    owned: TypedArena::new([EMPTY_OWNED_CAPABILITY; CAPAS_PER_DOMAIN]),
    sealed: SealedStatus::Unsealed,
    allowed_cores: 0,
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
