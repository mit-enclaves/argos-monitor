//! CPU object implementation.

use arena::{ArenaItem, Handle};
use bitflags::bitflags;

use crate::access::AccessRights;
use crate::error::ErrorCode;
use crate::{Backend, Capability, CapabilityType, Object, Ownership, Pool};

bitflags! {
    pub struct CPUFlags: u64 {
        /// Nothing can be scheduled.
        const NONE = 0;
        // TODO figure out what to do afterwards.
    }
}

//TODO fix
pub const ALL_RIGHTS: CPUFlags = CPUFlags::NONE;

/// CPUAccess rights.
/// TODO: figure out what to put in there.
#[derive(Copy, Clone, Debug)]
pub struct CPUAccess {
    pub flags: CPUFlags,
}

impl AccessRights for CPUAccess {
    fn is_null(&self) -> bool {
        self.flags == CPUFlags::NONE
    }

    fn is_subset(&self, other: &Self) -> bool {
        ((self.flags ^ other.flags) & other.flags) == CPUFlags::NONE
    }

    fn is_valid_dup(&self, op1: &Self, op2: &Self) -> bool {
        return self.is_subset(op1) && self.is_subset(op2);
    }
    fn get_null() -> Self {
        CPUAccess {
            flags: CPUFlags::NONE,
        }
    }
    fn as_bits(&self) -> (usize, usize, usize) {
        (0, 0, self.flags.bits() as usize)
    }
}

/// CPU object.
/// TODO: figure out what to put in there.
pub struct CPU<B: Backend> {
    pub id: usize,
    pub ref_count: usize,
    pub core: B::CoreState,
}

impl<B: Backend> CPU<B> {
    pub fn new(pool: &impl Pool<Self>, id: usize) -> Result<Handle<Self>, ErrorCode> {
        let cpu_handle = pool.allocate()?;
        let mut cpu = pool.get_mut(cpu_handle);
        cpu.id = id;
        cpu.ref_count = 1;
        Ok(cpu_handle)
    }
}

impl<B: Backend> Capability<CPU<B>> {
    pub fn new(
        pool: &impl Pool<CPU<B>>,
        id: usize,
        flags: CPUFlags,
    ) -> Result<Handle<Self>, ErrorCode> {
        let cpu_handle = CPU::<B>::new(pool, id)?;
        let capa_handle = pool.allocate_capa()?;
        let mut capa = pool.get_capa_mut(capa_handle);
        capa.capa_type = CapabilityType::Resource;
        capa.access = CPUAccess { flags };
        capa.handle = cpu_handle;
        capa.left = Handle::null();
        capa.right = Handle::null();
        Ok(capa_handle)
    }
}

impl<B: Backend> Object for CPU<B> {
    type Access = CPUAccess;

    fn from_bits(arg1: usize, _: usize, _: usize) -> Self::Access {
        CPUAccess {
            flags: CPUFlags::from_bits_truncate(arg1 as u64),
        }
    }
    fn incr_ref(&mut self, _pool: &impl Pool<Self>, _capa: &Capability<Self>) {
        self.ref_count += 1;
    }

    fn decr_ref(&mut self, _pool: &impl Pool<Self>, _capa: &Capability<Self>) {
        self.ref_count -= 1;
    }

    fn get_ref(&self, _pool: &impl Pool<Self>, _capa: &Capability<Self>) -> usize {
        self.ref_count
    }

    fn create_from(
        pool: &impl Pool<Self>,
        capa: &Capability<Self>,
        op: &Self::Access,
    ) -> Result<Handle<Capability<Self>>, ErrorCode> {
        if capa.owner == Ownership::Empty {
            return Err(ErrorCode::NotOwnedCapability);
        }
        // Easy case, no need to do anything.
        if op.is_null() {
            return Ok(Handle::null());
        }
        // Check again the access rights is subset.
        if !op.is_subset(&capa.access) {
            return Err(ErrorCode::IncreasingAccessRights);
        }

        let new_handle = pool.allocate_capa()?;
        {
            let mut new_capa = pool.get_capa_mut(new_handle);
            new_capa.access = *op;
            new_capa.handle = capa.handle;
            // Increment references.
            let mut obj = pool.get_mut(capa.handle);
            obj.incr_ref(pool, &new_capa);
        }
        // Handle ownership.
        if let Ownership::Domain(dom, _) = capa.owner {
            pool.set_owner_capa(new_handle, Handle::new_unchecked(dom))?;
        }
        return Ok(new_handle);
    }

    /*   fn install(
           &mut self,
           pool: &impl Pool<Self>,
           capa: &Capability<Self>,
       ) -> Result<(), ErrorCode> {
           pool.apply(capa)
       }

       fn uninstall(
           &mut self,
           pool: &impl Pool<Self>,
           capa: &Capability<Self>,
       ) -> Result<(), ErrorCode> {
           pool.unapply(capa)
       }
    */
}

// ——————————————————————— Arena Trait Implementation ——————————————————————— //
impl<B: Backend> ArenaItem for CPU<B> {
    type Error = ErrorCode;
    const OUT_OF_BOUND_ERROR: Self::Error = ErrorCode::OutOfBound;
    const ALLOCATION_ERROR: Self::Error = ErrorCode::AllocationError;
}
