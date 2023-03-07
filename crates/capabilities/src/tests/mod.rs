//! # Tests for the capabiity crate.

mod domain;
mod memory;
use core::cell::{Ref, RefMut};

use arena::{Handle, TypedArena};
use utils::HostPhysAddr;

use crate::backend::{NoBackend, EMPTY_CPU, EMPTY_CPU_CAPA, EMPTY_DOMAIN, EMPTY_DOMAIN_CAPA};
use crate::domain::{Domain, OwnedCapability};
use crate::memory::{
    MemoryAccess, MemoryFlags, MemoryRegion, EMPTY_MEMORY_REGION, EMPTY_MEMORY_REGION_CAPA,
    SHARE_USER,
};
use crate::{
    memory as mem, Capability, CapabilityType, OPool, Object, Ownership, Pool, State,
    CAPA_POOL_SIZE, CPU_POOL_SIZE, DOMAIN_POOL_SIZE, MEMORY_POOL_SIZE,
};

#[test]
fn main_test() {
    let mut pools = OPool {
        domains: TypedArena::new([EMPTY_DOMAIN; DOMAIN_POOL_SIZE]),
        domain_capas: TypedArena::new([EMPTY_DOMAIN_CAPA; CAPA_POOL_SIZE]),
        regions: TypedArena::new([EMPTY_MEMORY_REGION; MEMORY_POOL_SIZE]),
        region_capas: TypedArena::new([EMPTY_MEMORY_REGION_CAPA; CAPA_POOL_SIZE]),
        cpus: TypedArena::new([EMPTY_CPU; CPU_POOL_SIZE]),
        cpu_capas: TypedArena::new([EMPTY_CPU_CAPA; CAPA_POOL_SIZE]),
    };
    let pool = State::<NoBackend> {
        backend: NoBackend {},
        pools: &mut pools,
    };
    // Create an original domain.
    let default_domain_handle: Handle<Domain<NoBackend>> = match pool.allocate() {
        Ok(handle) => handle,
        Err(e) => panic!("Unable to allocate default domain: {:?}", e),
    };

    // Create the original memory region.
    // [0:1000]
    let full_memory_handle = match MemoryRegion::new(&pool, 0, 1000) {
        Ok(handle) => handle,
        Err(e) => panic!("Unable to allocate the full_memory handle: {:?}", e),
    };

    // Create the original memory capability too.
    let full_memory_capa_handle = match pool.pools.region_capas.allocate() {
        Ok(handle) => handle,
        Err(e) => panic!("Unable to allocate the full memory capability {:?}", e),
    };
    {
        let mut capa = pool.pools.region_capas.get_mut(full_memory_capa_handle);
        capa.capa_type = CapabilityType::Resource;
        capa.handle = full_memory_handle;
        capa.access = MemoryAccess {
            start: HostPhysAddr::new(0),
            end: HostPhysAddr::new(1000),
            flags: mem::ALL_RIGHTS,
        };
        capa.left = Handle::null();
        capa.right = Handle::null();
    }

    // Register the capa with the default domain.
    match pool.set_owner_capa(full_memory_capa_handle, default_domain_handle) {
        Err(e) => panic!("Cannot set owner for the capability {:?}", e),
        _ => {}
    }

    let mut capa = pool.get_capa_mut(full_memory_capa_handle);

    // Attempt a split.
    // [0:500] -- [500:1000]
    let (left, right) = match capa.duplicate(
        MemoryAccess {
            start: HostPhysAddr::new(0),
            end: HostPhysAddr::new(500),
            flags: mem::SHARE_USER,
        },
        MemoryAccess {
            start: HostPhysAddr::new(500),
            end: HostPhysAddr::new(1000),
            flags: mem::SHARE_USER,
        },
        &pool,
    ) {
        Ok((left, right)) => (left, right),
        Err(e) => panic!("Failed to duplicate {:?}", e),
    };
    assert_eq!(capa.capa_type, CapabilityType::Revocation);
    assert_ne!(capa.left, Handle::null());
    assert_ne!(capa.right, Handle::null());
    assert_eq!(capa.left, left);
    assert_eq!(capa.right, right);

    // Check they are correct.
    {
        let left_handle = left;
        let left = pool
            .pools
            .region_capas
            .get(Handle::new_unchecked(left.idx()));
        assert_eq!(left.access.start, HostPhysAddr::new(0));
        assert_eq!(left.access.end, HostPhysAddr::new(500));
        assert_eq!(left.access.flags, SHARE_USER);
        assert_eq!(left.left, Handle::null());
        assert_eq!(left.right, Handle::null());
        let region = pool.pools.regions.get(left.handle);
        assert_eq!(region.start, left.access.start);
        assert_eq!(region.ref_count, 1);
        assert_eq!(region.get_ref(&pool, &left), 1);
        // Check ownership
        match left.owner {
            Ownership::Domain(dom, idx) => {
                assert_eq!(dom, default_domain_handle.idx());
                let domain: Ref<Domain<NoBackend>> = pool.get(Handle::new_unchecked(dom));
                let forward = domain.owned.get(Handle::new_unchecked(idx));
                match *forward {
                    OwnedCapability::Region(r) => {
                        assert_eq!(r.idx(), left_handle.idx());
                    }
                    _ => panic!("Left forward edge is incorrect."),
                }
            }
            Ownership::Zombie => panic!("Zombie capability."),
            Ownership::Empty => panic!("Empty left capability owner."),
        }
    }
    {
        let right_handle = right;
        let right = pool
            .pools
            .region_capas
            .get(Handle::new_unchecked(right.idx()));
        assert_eq!(right.access.start, HostPhysAddr::new(500));
        assert_eq!(right.access.end, HostPhysAddr::new(1000));
        assert_eq!(right.access.flags, SHARE_USER);
        assert_eq!(right.left, Handle::null());
        assert_eq!(right.right, Handle::null());
        let region = pool.pools.regions.get(right.handle);
        assert_eq!(region.start, right.access.start);
        assert_eq!(region.ref_count, 1);
        assert_eq!(region.get_ref(&pool, &right), 1);
        // Check ownership
        match right.owner {
            Ownership::Domain(dom, idx) => {
                assert_eq!(dom, default_domain_handle.idx());
                let domain: Ref<Domain<NoBackend>> = pool.get(Handle::new_unchecked(dom));
                let forward = domain.owned.get(Handle::new_unchecked(idx));
                match *forward {
                    OwnedCapability::Region(r) => {
                        assert_eq!(r.idx(), right_handle.idx());
                    }
                    _ => panic!("Left forward edge is incorrect."),
                }
            }
            Ownership::Zombie => panic!("Zombie capability."),
            Ownership::Empty => panic!("Empty left capability owner."),
        }
    }

    // Do a subsplit on the left
    // From: [0:500]
    // To: [0:400] -- [300: 500];
    {
        let mut capa: RefMut<Capability<MemoryRegion>> =
            pool.get_capa_mut(Handle::new_unchecked(left.idx()));
        let (left, right) = match capa.duplicate(
            MemoryAccess {
                start: HostPhysAddr::new(0),
                end: HostPhysAddr::new(400),
                flags: SHARE_USER,
            },
            MemoryAccess {
                start: HostPhysAddr::new(300),
                end: HostPhysAddr::new(500),
                flags: SHARE_USER,
            },
            &pool,
        ) {
            Ok((l, r)) => (l, r),
            Err(e) => panic!("Second duplicate failed {:?}", e),
        };

        {
            let left_handle = left;
            let left: Ref<Capability<MemoryRegion>> =
                pool.get_capa(Handle::new_unchecked(left.idx()));
            let region: Ref<MemoryRegion> = pool.get(left.handle);
            assert_eq!(left.access.start, HostPhysAddr::new(0));
            assert_eq!(left.access.end, HostPhysAddr::new(400));
            assert_eq!(left.left, Handle::null());
            assert_eq!(left.right, Handle::null());
            assert_eq!(region.start, left.access.start);
            assert_eq!(region.ref_count, 1);
            assert_eq!(region.get_ref(&pool, &left), 2);
            // Check ownership
            match left.owner {
                Ownership::Domain(dom, idx) => {
                    assert_eq!(dom, default_domain_handle.idx());
                    let domain: Ref<Domain<NoBackend>> = pool.get(Handle::new_unchecked(dom));
                    let forward = domain.owned.get(Handle::new_unchecked(idx));
                    match *forward {
                        OwnedCapability::Region(r) => {
                            assert_eq!(r.idx(), left_handle.idx());
                        }
                        _ => panic!("Left forward edge is incorrect."),
                    }
                }
                Ownership::Zombie => panic!("Zombie capability."),
                Ownership::Empty => panic!("Empty left capability owner."),
            }
        }
        {
            let right_handle = right;
            let right: Ref<Capability<MemoryRegion>> =
                pool.get_capa(Handle::new_unchecked(right.idx()));
            let region: Ref<MemoryRegion> = pool.get(right.handle);
            assert_eq!(right.access.start, HostPhysAddr::new(300));
            assert_eq!(right.access.end, HostPhysAddr::new(500));
            assert_eq!(right.left, Handle::null());
            assert_eq!(right.right, Handle::null());
            assert_eq!(region.start, right.access.start);
            assert_eq!(region.ref_count, 2);
            assert_eq!(region.get_ref(&pool, &right), 2);
            // Check ownership
            match right.owner {
                Ownership::Domain(dom, idx) => {
                    assert_eq!(dom, default_domain_handle.idx());
                    let domain: Ref<Domain<NoBackend>> = pool.get(Handle::new_unchecked(dom));
                    let forward = domain.owned.get(Handle::new_unchecked(idx));
                    match *forward {
                        OwnedCapability::Region(r) => {
                            assert_eq!(r.idx(), right_handle.idx());
                        }
                        _ => panic!("Left forward edge is incorrect."),
                    }
                }
                Ownership::Zombie => panic!("Zombie capability."),
                Ownership::Empty => panic!("Empty left capability owner."),
            }
        }

        // Do another split
        // From: [0:400]
        // to: [0:300] [300:400] with the first one being null.
        {
            let mut capa: RefMut<Capability<MemoryRegion>> =
                pool.get_capa_mut(Handle::new_unchecked(left.idx()));
            let (left, right) = match capa.duplicate(
                MemoryAccess {
                    start: HostPhysAddr::new(0),
                    end: HostPhysAddr::new(300),
                    flags: MemoryFlags::NONE,
                },
                MemoryAccess {
                    start: HostPhysAddr::new(300),
                    end: HostPhysAddr::new(400),
                    flags: SHARE_USER,
                },
                &pool,
            ) {
                Ok((l, r)) => (l, r),
                Err(e) => panic!("Third duplicate failed {:?}", e),
            };

            // Check the results.
            assert_eq!(left, Handle::null());
            assert_ne!(right, Handle::null());
            {
                let right: Ref<Capability<MemoryRegion>> =
                    pool.get_capa(Handle::new_unchecked(right.idx()));
                let region: Ref<MemoryRegion> = pool.get(right.handle);
                assert_eq!(right.access.start, HostPhysAddr::new(300));
                assert_eq!(right.access.end, HostPhysAddr::new(400));
                assert_eq!(right.access.start, region.start);
                assert_eq!(region.ref_count, 2);
                assert_eq!(region.get_ref(&pool, &right), 2);
            }
        }
    }

    // Now revoke the original left.
    // This should do a cascading revocation.
    // We can also check if it merges things back together.
    {
        let left_handle = left;
        let mut left: RefMut<Capability<MemoryRegion>> =
            pool.get_capa_mut(Handle::new_unchecked(left.idx()));
        assert_eq!(left.capa_type, CapabilityType::Revocation);
        match left.revoke(&pool) {
            Err(e) => panic!("Error during revocation {:?}", e),
            _ => {}
        }
        assert_eq!(left.capa_type, CapabilityType::Resource);
        let region: Ref<MemoryRegion> = pool.get(left.handle);
        assert_eq!(left.access.start, HostPhysAddr::new(0));
        assert_eq!(left.access.end, HostPhysAddr::new(500));
        assert_eq!(left.access.start, region.start);
        // This proves the regions have been re-merged.
        assert_eq!(region.end, left.access.end);
        assert_eq!(region.ref_count, 1);
        assert_eq!(region.get_ref(&pool, &left), 1);
        // Check ownership
        match left.owner {
            Ownership::Domain(dom, idx) => {
                assert_eq!(dom, default_domain_handle.idx());
                let domain: Ref<Domain<NoBackend>> = pool.get(Handle::new_unchecked(dom));
                let forward = domain.owned.get(Handle::new_unchecked(idx));
                match *forward {
                    OwnedCapability::Region(r) => {
                        assert_eq!(r.idx(), left_handle.idx());
                    }
                    _ => panic!("Left forward edge is incorrect."),
                }
            }
            Ownership::Zombie => panic!("Zombie capability."),
            Ownership::Empty => panic!("Empty left capability owner."),
        }
    }
    // Check the state of the domain's pool.
    {
        let domain = pool.get(default_domain_handle);
        let mut counter: usize = 0;
        domain.enumerate(|_idx, _own| {
            counter += 1;
        });
        // The revok (original), left, and right.
        assert_eq!(counter, 3);
    }
    // Check the state of the memory region pool.
    {
        let mut counter: usize = 0;
        for i in 0..MEMORY_POOL_SIZE {
            if pool.pools.regions.is_allocated(i) {
                counter += 1;
            }
        }
        assert_eq!(counter, 2);
    }

    // Check the state of the regions capa.
    {
        let mut counter: usize = 0;
        for i in 0..CAPA_POOL_SIZE {
            if pool.pools.region_capas.is_allocated(i) {
                counter += 1;
            }
        }
        assert_eq!(counter, 3);
    }
    // Now do a duplicate on the right for share.
    // From: [500:1000]
    // To: [500:1000] [500:1000]
    // To: [500:1000] - {[500:1000]}
    // And test that the left one has a ref_count of 3.
    {
        let mut left: RefMut<Capability<MemoryRegion>> =
            pool.get_capa_mut(Handle::new_unchecked(right.idx()));
        let op = MemoryAccess {
            start: HostPhysAddr::new(500),
            end: HostPhysAddr::new(1000),
            flags: mem::SHARE_USER,
        };
        let (l, r) = match left.duplicate(op, op, &pool) {
            Ok((l, r)) => (l, r),
            Err(e) => panic!("Duplicate share failed: {:?}", e),
        };
        // The second split.
        {
            let mut right: RefMut<Capability<MemoryRegion>> =
                pool.get_capa_mut(Handle::new_unchecked(r.idx()));
            let (_l, r) = match right.duplicate(op, op, &pool) {
                Ok((l, r)) => (l, r),
                Err(e) => panic!("Unable to duplicate on the right: {:?}", e),
            };
            // Check the ref count
            {
                let right: Ref<Capability<MemoryRegion>> =
                    pool.get_capa(Handle::new_unchecked(r.idx()));
                let obj = pool.get(right.handle);
                assert_eq!(obj.start, HostPhysAddr::new(500));
                assert_eq!(obj.end, HostPhysAddr::new(1000));
                assert_eq!(obj.ref_count, 3);
                assert_eq!(obj.get_ref(&pool, &right), 3);
            }
        }
        // Check the previous left.
        {
            let left: Ref<Capability<MemoryRegion>> = pool.get_capa(Handle::new_unchecked(l.idx()));
            let obj = pool.get(left.handle);
            assert_eq!(obj.start, HostPhysAddr::new(500));
            assert_eq!(obj.end, HostPhysAddr::new(1000));
            assert_eq!(obj.ref_count, 3);
            assert_eq!(obj.get_ref(&pool, &left), 3);
        }
        // Check allocations in the region pool.
        {
            let mut counter = 0;
            for i in 0..MEMORY_POOL_SIZE {
                if pool.pools.regions.is_allocated(i) {
                    counter += 1;
                }
            }
            assert_eq!(counter, 2);
        }
    }
    // Revoke the right.
    {
        let mut revok: RefMut<Capability<MemoryRegion>> =
            pool.get_capa_mut(Handle::new_unchecked(right.idx()));
        match revok.revoke(&pool) {
            Err(e) => panic!("Right revocation failed: {:?}", e),
            _ => {}
        }
    }
}
