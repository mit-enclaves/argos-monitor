use arena::{Handle, TypedArena};
use capabilities::access::AccessRights;
use capabilities::backend::{
    NoBackend, EMPTY_CPU, EMPTY_CPU_CAPA, EMPTY_DOMAIN, EMPTY_DOMAIN_CAPA,
};
use capabilities::domain::DomainAccess::{self, Sealed};
use capabilities::domain::{Domain, OwnedCapability, ALL_CORES_ALLOWED, CAPAS_PER_DOMAIN};
use capabilities::error::ErrorCode;
use capabilities::memory::{self, MemoryRegion, EMPTY_MEMORY_REGION, EMPTY_MEMORY_REGION_CAPA};
use capabilities::{
    Capability, CapabilityType, OPool, Object, Ownership, Pool, State, CAPA_POOL_SIZE,
    CPU_POOL_SIZE, DOMAIN_POOL_SIZE, MEMORY_POOL_SIZE,
};
use utils::HostPhysAddr;

use crate::tyche::{Tyche, TYCHE_SWITCH};
use crate::{tyche, Monitor, MonitorState, Parameters};

macro_rules! declare_pool {
    ($pools:ident) => {
        let $pools = OPool {
            domains: TypedArena::new([EMPTY_DOMAIN; DOMAIN_POOL_SIZE]),
            domain_capas: TypedArena::new([EMPTY_DOMAIN_CAPA; CAPA_POOL_SIZE]),
            regions: TypedArena::new([EMPTY_MEMORY_REGION; MEMORY_POOL_SIZE]),
            region_capas: TypedArena::new([EMPTY_MEMORY_REGION_CAPA; CAPA_POOL_SIZE]),
            cpus: TypedArena::new([EMPTY_CPU; CPU_POOL_SIZE]),
            cpu_capas: TypedArena::new([EMPTY_CPU_CAPA; CAPA_POOL_SIZE]),
        };
    };
}

macro_rules! declare_state {
    ($state:ident, $pool:expr) => {
        let $state = State::<NoBackend> {
            backend: NoBackend {},
            pools: $pool,
        };
    };
}

macro_rules! declare_monitor_state {
    ($state:expr, $tyche_state:ident) => {
        #[allow(unused_mut)]
        let mut $tyche_state = match MonitorState::<NoBackend>::new(MEM_4GB, $state) {
            Ok(ts) => ts,
            Err(e) => {
                panic!("Unable to create the state: {:?}", e);
            }
        };
    };
}

macro_rules! full_init {
    ($tyche:ident) => {
        declare_pool!(pools);
        declare_state!(capas, &pools);
        declare_monitor_state!(capas, $tyche);
    };
}

pub const MEM_4GB: usize = 0x100000000;

#[test]
fn macros_init_test() {
    declare_pool!(pools);
    declare_state!(capas, &pools);
    declare_monitor_state!(capas, _tyche);
}

#[test]
fn init_test() {
    full_init!(tyche);
    // Check that there is a valid domain, memory region, and CPU.
    {
        let domain = tyche.resources.pools.domains.get(Handle::new_unchecked(0));
        assert_eq!(domain.is_sealed(), true);
        assert_eq!(domain.ref_count, 1);

        let region = tyche.resources.pools.regions.get(Handle::new_unchecked(0));
        assert_eq!(region.start, HostPhysAddr::new(0));
        assert_eq!(region.end, HostPhysAddr::new(MEM_4GB));
        assert_eq!(region.ref_count, 1);

        let cpu = tyche.resources.pools.cpus.get(Handle::new_unchecked(0));
        assert_eq!(cpu.ref_count, 1);
    }
    // Check the local domain and cpu.
    assert_eq!(tyche.locals[0].current_cpu, 0);
    assert_eq!(tyche.locals[0].current_domain, 0);

    // Check the result from get, that it is sealed, and that it is owned.
    {
        let domain_capa = tyche.get_current_domain();
        match domain_capa.access {
            Sealed(spawn, comm) => {
                assert_eq!(spawn, true);
                assert_eq!(comm, true);
            }
            _ => panic!("Default domain is not sealed"),
        }
        match domain_capa.get_owner::<(), NoBackend>() {
            Ok(id) => {
                assert_eq!(id.idx(), 0);
            }
            Err(e) => panic!("Unable to get the owner for default domain {:?}", e),
        }
    }

    // Enumerate the domain's capa and check their ownership.
    {
        let domain = {
            let domain_capa = tyche.get_current_domain();
            tyche.resources.get(domain_capa.handle)
        };
        // All the idx should be 0, all the own should be valid and to dom 0.
        let mut counter = 0;
        domain.enumerate(|idx, own| {
            assert_eq!(counter, idx);
            counter += 1;
            match *own {
                OwnedCapability::Empty => panic!("Capability {:?} is not owned.", idx),
                OwnedCapability::CPU(h) => {
                    assert_eq!(h.idx(), 0);
                    let idx = tyche
                        .resources
                        .get_capa(h)
                        .get_owner::<(), NoBackend>()
                        .expect("failed owner")
                        .idx();
                    assert_eq!(idx, 0);
                }
                OwnedCapability::Domain(h) => {
                    assert_eq!(h.idx(), 0);
                    let idx = tyche
                        .resources
                        .get_capa(h)
                        .get_owner::<(), NoBackend>()
                        .expect("failed owner")
                        .idx();
                    assert_eq!(idx, 0);
                }
                OwnedCapability::Region(h) => {
                    assert_eq!(h.idx(), 0);
                    let idx = tyche
                        .resources
                        .get_capa(h)
                        .get_owner::<(), NoBackend>()
                        .expect("failed owner")
                        .idx();
                    assert_eq!(idx, 0);
                }
            }
        });
        assert_eq!(counter, 3);
    }
}

fn create_helper(
    tyche: &Tyche,
    state: &mut MonitorState<NoBackend>,
    spawn: usize,
    comm: usize,
) -> (usize, usize, Handle<Capability<Domain<NoBackend>>>) {
    let create_call = Parameters {
        vmcall: tyche::TYCHE_CREATE_DOMAIN,
        arg_1: spawn,
        arg_2: comm,
        ..Default::default()
    };
    match tyche.dispatch(state, &create_call) {
        Ok(registers) => {
            let current = state.get_current_domain().handle;
            let capa = state
                .resources
                .get(current)
                .get_local_capa(registers.value_2)
                .expect("Unable to get local capa")
                .as_domain()
                .expect("Wrong owned capability");
            return (registers.value_3, registers.value_2, capa);
        }
        Err(e) => panic!("Unable to create domain: {:?}", e),
    }
}

fn create_domain_helper(spawn: usize, comm: usize) {
    full_init!(tyche_state);
    let monitor = Tyche {};
    let create_call = Parameters {
        vmcall: tyche::TYCHE_CREATE_DOMAIN,
        arg_1: spawn,
        arg_2: comm,
        ..Default::default()
    };
    match monitor.dispatch(&mut tyche_state, &create_call) {
        Ok(registers) => {
            // It should be three because it is the 4th local capability.
            assert_eq!(registers.value_1, 3); // Us
            assert_eq!(registers.value_2, 4); // The new domain.
            let current = tyche_state.get_current_domain().handle;
            let domain_handle = tyche_state
                .resources
                .get(current)
                .get_local_capa(registers.value_2)
                .expect("Error getting local capa")
                .as_domain()
                .expect("Could not get domain handle");
            let domain_capa = tyche_state.resources.get_capa(domain_handle);
            let domain = tyche_state.resources.get(domain_capa.handle);
            assert_eq!(domain.is_sealed(), false);
            assert_eq!(domain.ref_count, 1);
            match domain_capa.access {
                DomainAccess::Unsealed(s, c) => {
                    assert_eq!(s, spawn == 1);
                    assert_eq!(c, comm == 1);
                }
                _ => panic!("Wrong capability type after create"),
            }

            let domain_handle = tyche_state
                .resources
                .get(current)
                .get_local_capa(registers.value_1)
                .expect("Error getting lcoal capa")
                .as_domain()
                .expect("Could not get domain handle");
            // Check we are still the current domain.
            assert_eq!(domain_handle.idx(), tyche_state.locals[0].current_domain);
        }
        Err(e) => panic!("Failed create: {:?}", e),
    }
}

#[test]
fn create_domain_test() {
    create_domain_helper(1, 1);
    create_domain_helper(0, 1);
    create_domain_helper(1, 0);
    create_domain_helper(0, 0);
}

fn create_domain_on_unsealed_helper(s: usize, c: usize) {
    full_init!(tyche_state);
    let monitor = Tyche {};
    let create_call = Parameters {
        vmcall: tyche::TYCHE_CREATE_DOMAIN,
        arg_1: s,
        arg_2: c,
        ..Default::default()
    };
    let registers = monitor
        .dispatch(&mut tyche_state, &create_call)
        .expect("Create domain should not fail!");
    // Let's cheat and attempt to forcefully replace the local with a non-valid
    // capability, and then call create domain.
    let current = tyche_state.get_current_domain().handle;
    let new_domain_capa = tyche_state
        .resources
        .get(current)
        .get_local_capa(registers.value_2)
        .expect("Local capability should not fail either")
        .as_domain()
        .expect("Wrong owned capability");
    // HERE we install an illegal state.
    tyche_state.locals[0].current_domain = new_domain_capa.idx();
    match monitor.dispatch(&mut tyche_state, &create_call) {
        Err(e) => assert_eq!(e.code(), ErrorCode::IncreasingAccessRights),
        _ => panic!("We tricked the runtime into accepting a dup on unsealed domain!"),
    }
}
#[test]
fn create_domain_on_unsealed() {
    create_domain_on_unsealed_helper(1, 1);
    create_domain_on_unsealed_helper(0, 1);
    create_domain_on_unsealed_helper(1, 0);
    create_domain_on_unsealed_helper(0, 0);
}

#[test]
fn remove_local_capa() {
    full_init!(state);
    let region: Handle<Capability<MemoryRegion>> = Handle::new_unchecked(0);
    match state.resources.remove_owner(region) {
        Err(e) => panic!("Unable to remove  owner {:?}", e),
        _ => {}
    }
    // Check the capa is not owned anymore.
    let capa = state.resources.get_capa(region);
    match capa.owner {
        Ownership::Empty => {}
        Ownership::Zombie => panic!("The capability is zombied somehow..."),
        Ownership::Domain(dom, idx) => {
            panic!("The domain is still owned by {:?} at index {:?}", dom, idx);
        }
    }
    // Check the capa is no longer in the locals.
    let current_handle = state.get_current_domain().handle;
    let domain = state.resources.get(current_handle);
    let mut counter = 0;
    domain.enumerate(|_, dom| match *dom {
        OwnedCapability::Region(_) => {
            counter += 1;
        }
        _ => {}
    });
    assert_eq!(counter, 0);
}

#[test]
fn give_test() {
    full_init!(state);
    let monitor = Tyche {};
    let (_, local_idx, _) = create_helper(&monitor, &mut state, 1, 1);
    // Let's give the memory region.
    let mut mem_idx = usize::MAX;

    {
        let mut counter = 0;
        let current_handle = state.get_current_domain().handle;
        let current = state.resources.get(current_handle);
        current.enumerate(|idx, own| match *own {
            OwnedCapability::Region(_) => {
                mem_idx = idx;
                counter += 1;
            }
            _ => {}
        });
        assert_eq!(counter, 1);
    }
    let give_call = Parameters {
        vmcall: tyche::TYCHE_GIVE,
        arg_1: local_idx,
        arg_2: mem_idx,
        arg_3: 0,
        arg_4: MEM_4GB,
        arg_5: memory::SHARE_USER.bits() as usize,
    };

    match monitor.dispatch(&mut state, &give_call) {
        Ok(_) => {}
        Err(e) => panic!("Give call did not work: {:?}", e),
    }

    // Now let's check we do not have the region anymore.
    {
        let current_handle = state.get_current_domain().handle;
        let current = state.resources.get(current_handle);
        let mut counter = 0;
        current.enumerate(|_, own| match *own {
            OwnedCapability::Region(h) => {
                let region_capa = state.resources.get_capa(h);
                println!("The region capa we have: {:?}", region_capa.access);
                counter += 1;
            }
            _ => {}
        });
        assert_eq!(counter, 0);
    }
}

#[test]
fn seal_test() {
    full_init!(state);
    let monitor = Tyche {};
    let (_, id_new, _) = create_helper(&monitor, &mut state, 1, 1);
    // Try to seal the new domain.
    let seal_call = Parameters {
        vmcall: tyche::TYCHE_SEAL_DOMAIN,
        arg_1: id_new,
        ..Default::default()
    };
    match monitor.dispatch(&mut state, &seal_call) {
        Ok(registers) => {
            // We enumerate the local capabilities and ensure there is only
            // three domain capa left: self, revocation one, and transition.
            let curr_handle = state.get_current_domain().handle;
            let current = state.resources.get(curr_handle);
            let mut counter = 0;
            let mut revoke = 0;
            let mut trans = 0;
            current.enumerate(|i, own| match *own {
                OwnedCapability::Domain(h) => {
                    counter += 1;
                    let capa = state.resources.get_capa(h);
                    if capa.capa_type == CapabilityType::Revocation {
                        revoke += 1;
                    }
                    if let DomainAccess::Transition(_) = capa.access {
                        trans += 1;
                        // This should point to another domain.
                        assert_ne!(capa.handle, curr_handle);
                        assert_eq!(registers.value_1, i);
                    }
                }
                _ => {}
            });
            assert_eq!(counter, 3);
            assert_eq!(revoke, 1);
            assert_eq!(trans, 1);
        }
        Err(e) => panic!("Did not managed to seal domain: {:?}", e),
    }
}

#[test]
fn share_unsealed_test() {
    full_init!(state);
    let tyche = Tyche {};
    let (_, local_idx, dom_handle) = create_helper(&tyche, &mut state, 1, 1);

    // Let's share the memory region.
    let mut mem_idx = usize::MAX;
    let mut counter = 0;
    let current_handle = state.get_current_domain().handle;
    {
        let current = state.resources.get(current_handle);
        current.enumerate(|idx, own| match *own {
            OwnedCapability::Region(_) => {
                mem_idx = idx;
                counter += 1;
            }
            _ => {}
        });
    }
    assert_eq!(counter, 1);
    let share_call = Parameters {
        vmcall: tyche::TYCHE_SHARE,
        arg_1: local_idx,
        arg_2: mem_idx,
        arg_3: 0,
        arg_4: MEM_4GB,
        arg_5: memory::SHARE_USER.bits() as usize,
    };

    match tyche.dispatch(&mut state, &share_call) {
        Err(e) => panic!("Unable to share the region: {:?}", e),
        Ok(registers) => {
            // Check the new_local is now a resource capability with the same reigon.
            let new_local = registers.value_1;
            let current = state.resources.get(current_handle);
            let h = current
                .get_local_capa(new_local)
                .expect("This should be a valid idx")
                .as_region()
                .expect("Wrong owned capability type");
            let capa = state.resources.get_capa(h);
            assert_eq!(capa.access.start, HostPhysAddr::new(0));
            assert_eq!(capa.access.end, HostPhysAddr::new(MEM_4GB));
            assert_eq!(capa.access.flags, memory::ALL_RIGHTS);
            assert_eq!(capa.capa_type, CapabilityType::Resource);
        }
    };

    // Check the original local is now a revocation.
    let current = state.resources.get(current_handle);
    let h = current
        .get_local_capa(mem_idx)
        .expect("This handle should still be valid")
        .as_region()
        .expect("Wrong owned capability type");
    let capa = state.resources.get_capa(h);
    assert_eq!(capa.access.start, HostPhysAddr::new(0));
    assert_eq!(capa.access.end, HostPhysAddr::new(MEM_4GB));
    assert_eq!(capa.access.flags, memory::ALL_RIGHTS);
    assert_eq!(capa.capa_type, CapabilityType::Revocation);

    // Now check the other domain also has the right capability.
    let other_handle = state.resources.get_capa(dom_handle).handle;
    let other = state.resources.get(other_handle);
    let mut counter = 0;
    other.enumerate(|_, own| match *own {
        OwnedCapability::Region(h) => {
            counter += 1;
            let capa = state.resources.get_capa(h);
            assert_eq!(capa.access.start, HostPhysAddr::new(0));
            assert_eq!(capa.access.end, HostPhysAddr::new(MEM_4GB));
            assert_eq!(capa.access.flags, memory::SHARE_USER);
            assert_eq!(capa.capa_type, CapabilityType::Resource);
            let region = state.resources.get(capa.handle);
            assert_eq!(region.get_ref(&state.resources, &capa), 2);
        }
        _ => {
            counter += 1;
        }
    });
    assert_eq!(counter, 1);
}

#[test]
fn grant_unsealed_test() {
    full_init!(state);
    let tyche = Tyche {};
    let (_, local_idx, dom_handle) = create_helper(&tyche, &mut state, 1, 1);

    // Let's share the memory region.
    let mut mem_idx = usize::MAX;
    let mut counter = 0;
    let current_handle = state.get_current_domain().handle;
    {
        let current = state.resources.get(current_handle);
        current.enumerate(|idx, own| match *own {
            OwnedCapability::Region(_) => {
                mem_idx = idx;
                counter += 1;
            }
            _ => {}
        });
    }
    assert_eq!(counter, 1);
    let grant_call = Parameters {
        vmcall: tyche::TYCHE_GRANT,
        arg_1: local_idx,
        arg_2: mem_idx,
        arg_3: 0,
        arg_4: MEM_4GB,
        arg_5: memory::SHARE_USER.bits() as usize,
    };

    match tyche.dispatch(&mut state, &grant_call) {
        Err(e) => panic!("Unable to grant the region: {:?}", e),
        Ok(registers) => {
            // Check the new_local is revocation capability with the same region.
            let new_local = registers.value_1;
            let current = state.resources.get(current_handle);
            let handle = current
                .get_local_capa(new_local)
                .expect("This should be a valid idx")
                .as_region()
                .expect("Wrong owned capability type");
            let capa = state.resources.get_capa(handle);
            // What we get back in the case of a grant is a null capa.
            assert_eq!(capa.access.is_null(), false);
            assert_eq!(capa.access.start, HostPhysAddr::new(0));
            assert_eq!(capa.access.end, HostPhysAddr::new(MEM_4GB));
            assert_eq!(capa.access.flags, memory::ALL_RIGHTS);
            assert_eq!(capa.capa_type, CapabilityType::Revocation);
        }
    };
    // Check the original local is now a revocation.
    // This check is redundant but let's do it anyway.
    {
        let current = state.resources.get(current_handle);
        let handle = current
            .get_local_capa(mem_idx)
            .expect("This handle should still be valid")
            .as_region()
            .expect("Wrong owned capability type");
        let capa = state.resources.get_capa(handle);
        assert_eq!(capa.access.start, HostPhysAddr::new(0));
        assert_eq!(capa.access.end, HostPhysAddr::new(MEM_4GB));
        assert_eq!(capa.access.flags, memory::ALL_RIGHTS);
        assert_eq!(capa.capa_type, CapabilityType::Revocation);
    }

    // Now check the other domain also has the right capability.
    let other_handle = state.resources.get_capa(dom_handle).handle;
    let other = state.resources.get(other_handle);
    let mut counter = 0;
    other.enumerate(|_, own| match *own {
        OwnedCapability::Region(h) => {
            counter += 1;
            let capa = state.resources.get_capa(h);
            assert_eq!(capa.access.start, HostPhysAddr::new(0));
            assert_eq!(capa.access.end, HostPhysAddr::new(MEM_4GB));
            assert_eq!(capa.access.flags, memory::SHARE_USER);
            assert_eq!(capa.capa_type, CapabilityType::Resource);
            let region = state.resources.get(capa.handle);
            // This has to be one.
            assert_eq!(region.get_ref(&state.resources, &capa), 1);
        }
        _ => {
            counter += 1;
        }
    });
    assert_eq!(counter, 1);
}

#[test]
fn revoke_test() {
    full_init!(state);
    let monitor = Tyche {};
    let (_, local_idx, _) = create_helper(&monitor, &mut state, 1, 1);
    // Find a memory region
    let mut region_handle = usize::MAX;
    {
        let curr_handle = state.get_current_domain().handle;
        let curr = state.resources.get(curr_handle);
        curr.enumerate(|idx, own| match *own {
            OwnedCapability::Region(_) => {
                region_handle = idx;
            }
            _ => {}
        });
    };

    // Share the region.
    let share_call = Parameters {
        vmcall: tyche::TYCHE_SHARE,
        arg_1: local_idx,
        arg_2: region_handle,
        arg_3: 0,
        arg_4: MEM_4GB / 2,
        arg_5: memory::SHARE_USER.bits() as usize,
    };
    let new_local = monitor
        .dispatch(&mut state, &share_call)
        .expect("Unable to share the region!")
        .value_1;
    // Check the local capa retained the right access rights.
    {
        let curr_handle = state.get_current_domain().handle;
        let curr = state.resources.get(curr_handle);
        let new_access = curr
            .get_local_capa(new_local)
            .expect("Could not find local capa")
            .as_region()
            .expect("Error getting region");
        let capa = state.resources.get_capa(new_access);
        assert_eq!(capa.capa_type, CapabilityType::Resource);
        assert_eq!(capa.access.start, HostPhysAddr::new(0));
        assert_eq!(capa.access.end, HostPhysAddr::new(MEM_4GB));
        assert_eq!(capa.access.flags, memory::ALL_RIGHTS);
    }

    // Check the other domain has the correct memory region.
    {
        let handle = state.get_current_domain().handle;
        let other_capa_handle = state
            .resources
            .get(handle)
            .get_local_capa(local_idx)
            .expect("Unable to find the other domain")
            .as_domain()
            .expect("Unable to get the other domain");
        let other_handle = state.resources.get_capa(other_capa_handle).handle;
        let other = state.resources.get(other_handle);
        other.enumerate(|_, own| match *own {
            OwnedCapability::Region(h) => {
                let region = state.resources.get_capa(h);
                assert_eq!(region.capa_type, CapabilityType::Resource);
                assert_eq!(region.access.start, HostPhysAddr::new(0));
                assert_eq!(region.access.end, HostPhysAddr::new(MEM_4GB / 2));
                assert_eq!(region.access.flags, memory::SHARE_USER);
            }
            _ => {}
        });
    }
    // Now revoke the capa.
    let revoke_call = Parameters {
        vmcall: tyche::TYCHE_REVOKE,
        arg_1: region_handle,
        ..Default::default()
    };
    match monitor.dispatch(&mut state, &revoke_call) {
        Err(e) => panic!("Unable to revoke the region! {:?}", e),
        Ok(_) => {}
    };

    // Check we only have one in the current domain
    {
        let curr_handle = state.get_current_domain().handle;
        let curr = state.resources.get(curr_handle);
        let mut counter = 0;
        curr.enumerate(|_, own| match *own {
            OwnedCapability::Region(h) => {
                let capa = state.resources.get_capa(h);
                counter += 1;
                assert_eq!(capa.capa_type, CapabilityType::Resource);
                assert_eq!(capa.access.start, HostPhysAddr::new(0));
                assert_eq!(capa.access.end, HostPhysAddr::new(MEM_4GB));
                assert_eq!(capa.access.flags, memory::ALL_RIGHTS);
            }
            _ => {}
        });
        assert_eq!(counter, 1);
    }

    // Check the other domain has no memory region.
    {
        let curr_handle = state.get_current_domain().handle;
        let other_capa_handle = state
            .resources
            .get(curr_handle)
            .get_local_capa(local_idx)
            .expect("Unable to find the other domain")
            .as_domain()
            .expect("Failed to convert to domain");
        let other_handle = state.resources.get_capa(other_capa_handle).handle;
        let other = state.resources.get(other_handle);
        other.enumerate(|_, own| match *own {
            OwnedCapability::Region(_) => {
                panic!("The other domain still owns a capability for the region!")
            }
            _ => panic!("The other domain has an unexpected capability"),
        });
    }
}

#[test]
fn revoke_invalid() {
    full_init!(state);
    let monitor = Tyche {};
    let (_, dest, _) = create_helper(&monitor, &mut state, 0, 0);
    let mut region_handle = usize::MAX;
    {
        let curr_h = state.get_current_domain().handle;
        let curr = state.resources.get(curr_h);
        curr.enumerate(|idx, own| match *own {
            OwnedCapability::Region(_) => {
                region_handle = idx;
            }
            _ => {}
        });
    }
    // Share the region.
    let share_call = Parameters {
        vmcall: tyche::TYCHE_SHARE,
        arg_1: dest,
        arg_2: region_handle,
        arg_3: 0,
        arg_4: MEM_4GB / 2,
        arg_5: memory::SHARE_USER.bits() as usize,
    };
    let new_local = monitor
        .dispatch(&mut state, &share_call)
        .expect("Unable to share the region!")
        .value_1;
    // Attempt to revoke from the new_local.
    let revoke_call = Parameters {
        vmcall: tyche::TYCHE_REVOKE,
        arg_1: new_local,
        ..Default::default()
    };
    match monitor.dispatch(&mut state, &revoke_call) {
        Ok(_) => panic!("Revoke went through"),
        Err(_) => {}
    };

    // Check this didn't modify anything.
    {
        let curr_h = state.get_current_domain().handle;
        let curr = state.resources.get(curr_h);
        let mut counter = 0;
        let mut revoke = 0;
        curr.enumerate(|_, own| match *own {
            OwnedCapability::Region(h) => {
                counter += 1;
                let capa = state.resources.get_capa(h);
                if capa.capa_type == CapabilityType::Revocation {
                    revoke += 1;
                } else {
                    assert_eq!(capa.capa_type, CapabilityType::Resource);
                    assert_eq!(capa.access.start, HostPhysAddr::new(0));
                    assert_eq!(capa.access.end, HostPhysAddr::new(MEM_4GB));
                    assert_eq!(capa.access.flags, memory::ALL_RIGHTS);
                }
            }
            _ => {}
        });
        assert_eq!(counter, 2);
        assert_eq!(revoke, 1);
    }
    // Check the other domain has the correct memory region.
    {
        let handle = state.get_current_domain().handle;
        let other_capa_handle = state
            .resources
            .get(handle)
            .get_local_capa(dest)
            .expect("Unable to find the other domain")
            .as_domain()
            .expect("Unable to get the other domain");
        let other_handle = state.resources.get_capa(other_capa_handle).handle;
        let other = state.resources.get(other_handle);
        other.enumerate(|_, own| match *own {
            OwnedCapability::Region(h) => {
                let region = state.resources.get_capa(h);
                assert_eq!(region.capa_type, CapabilityType::Resource);
                assert_eq!(region.access.start, HostPhysAddr::new(0));
                assert_eq!(region.access.end, HostPhysAddr::new(MEM_4GB / 2));
                assert_eq!(region.access.flags, memory::SHARE_USER);
            }
            _ => {}
        });
    }
}

#[test]
fn domain_collection() {
    full_init!(state);
    let monitor = Tyche {};
    let (revoke, dest, _) = create_helper(&monitor, &mut state, 1, 1);
    let mut region_handle = usize::MAX;
    {
        let curr_h = state.get_current_domain().handle;
        let curr = state.resources.get(curr_h);
        curr.enumerate(|idx, own| match *own {
            OwnedCapability::Region(_) => {
                region_handle = idx;
            }
            _ => {}
        });
    }
    // Share the region.
    let share_call = Parameters {
        vmcall: tyche::TYCHE_SHARE,
        arg_1: dest,
        arg_2: region_handle,
        arg_3: 0,
        arg_4: MEM_4GB / 2,
        arg_5: memory::SHARE_USER.bits() as usize,
    };
    let _ = monitor
        .dispatch(&mut state, &share_call)
        .expect("Unable to share the region!");

    // Kill the other domain.
    let revoke_call = Parameters {
        vmcall: tyche::TYCHE_REVOKE,
        arg_1: revoke,
        ..Default::default()
    };
    let _ = monitor
        .dispatch(&mut state, &revoke_call)
        .expect("Failed revocation!");
    // Now check the state, we should have one domain, and two region_capas.
    // Check the domains:
    {
        let mut counter = 0;
        for i in 0..DOMAIN_POOL_SIZE {
            if state.resources.pools.domains.is_allocated(i) {
                counter += 1;
            }
        }
        assert_eq!(counter, 1);
    }
    // Check the region capas.
    {
        let mut counter = 0;
        let mut zombied = 0;
        let mut owned = 0;
        for i in 0..CAPA_POOL_SIZE {
            if state.resources.pools.region_capas.is_allocated(i) {
                counter += 1;
                let capa = state
                    .resources
                    .pools
                    .region_capas
                    .get(Handle::new_unchecked(i));
                match capa.owner {
                    Ownership::Zombie => {
                        zombied += 1;
                    }
                    Ownership::Domain(dom, _) => {
                        assert_eq!(dom, 0);
                        owned += 1;
                    }
                    _ => panic!("Unexpected owned type"),
                }
            }
        }
        assert_eq!(counter, 3);
        assert_eq!(zombied, 1);
        assert_eq!(owned, 2);
    }
}

#[test]
fn enumerate_test() {
    full_init!(state);
    let monitor = Tyche {};
    let mut domain_counter = 0;
    let mut region_counter = 0;
    let mut cpu_counter = 0;
    for i in 0..CAPAS_PER_DOMAIN {
        let enum_call = Parameters {
            vmcall: tyche::TYCHE_ENUMERATE,
            arg_1: i,
            ..Default::default()
        };

        match monitor.dispatch(&mut state, &enum_call) {
            Err(e) => {
                if e.code() != ErrorCode::OutOfBound {
                    panic!("Unexpected error {:?}", e);
                }
            }
            Ok(registers) => {
                // Check the type of the capa
                assert!(registers.value_2 < 3);
                match registers.value_2 {
                    tyche::TYCHE_DOMAIN_TYPE => {
                        assert_eq!(registers.value_3, 2);
                        assert_eq!(registers.value_4, 1);
                        assert_eq!(registers.value_5, 1);
                        assert_eq!(registers.value_6, 1);
                        domain_counter += 1;
                    }
                    tyche::TYCHE_REGION_TYPE => {
                        assert_eq!(registers.value_3, 0);
                        assert_eq!(registers.value_4, MEM_4GB);
                        assert_eq!(registers.value_5, memory::ALL_RIGHTS.bits() as usize);
                        assert_eq!(registers.value_6, 1);
                        region_counter += 1;
                    }
                    tyche::TYCHE_CPU_TYPE => {
                        assert_eq!(registers.value_3, 0);
                        assert_eq!(registers.value_4, 0);
                        assert_eq!(registers.value_5, 0);
                        assert_eq!(registers.value_6, 1);
                        cpu_counter += 1;
                    }
                    _ => panic!("Unexpected value in registers"),
                }
            }
        }
    }
    assert_eq!(domain_counter, 1);
    assert_eq!(region_counter, 1);
    assert_eq!(cpu_counter, 1);
}

#[test]
fn switch_test() {
    full_init!(state);
    let monitor = Tyche {};
    let (_, id_new, _) = create_helper(&monitor, &mut state, 1, 1);
    // Seal the new domain.
    let seal_call = Parameters {
        vmcall: tyche::TYCHE_SEAL_DOMAIN,
        arg_1: id_new,
        arg_2: ALL_CORES_ALLOWED,
        arg_3: 1,
        arg_4: 2,
        arg_5: 3,
    };
    let registers = monitor
        .dispatch(&mut state, &seal_call)
        .expect("Unable to seal the domain");

    // Now do a switch
    let switch_call = Parameters {
        vmcall: TYCHE_SWITCH,
        arg_1: registers.value_1,
        ..Default::default()
    };
    // Get the current domain before the switch.
    let prev = state.get_current_domain().handle;

    let _registers = monitor
        .dispatch(&mut state, &switch_call)
        .expect("unable to perform a switch");

    // Now compare the current domain.
    let current = state.get_current_domain().handle;
    assert_ne!(prev, current);

    // Check the CPU disappeared in the previous one.
    {
        let domain = state.resources.get(prev);
        let mut region: i32 = 0;
        let mut doms: i32 = 0;
        let mut revoke_dom = 0;
        let mut dom_active = 0;
        let mut transition = 0;
        domain.enumerate(|_i, own| match *own {
            OwnedCapability::CPU(_) => {
                panic!("The CPU should have disappeared!");
            }
            OwnedCapability::Domain(h) => {
                doms += 1;
                let capa = state.resources.get_capa(h);
                match capa.access {
                    DomainAccess::Sealed(_, _) => {
                        if capa.capa_type == CapabilityType::Revocation {
                            revoke_dom += 1;
                        } else {
                            dom_active += 1;
                        }
                        assert_eq!(capa.handle, prev);
                    }
                    DomainAccess::Transition(_) => {
                        assert_eq!(capa.capa_type, CapabilityType::Resource);
                        assert_ne!(capa.handle, prev);
                        transition += 1;
                    }
                    _ => panic!("Unexpected capability type."),
                }
            }
            OwnedCapability::Region(_) => {
                region += 1;
            }
            _ => panic!("Unexpected type of owned capa."),
        });
        assert_eq!(region, 1);
        // 3 sealed (2 revocations, 1 active), and 1 transition.
        assert_eq!(doms, 4);
        assert_eq!(revoke_dom, 2);
        assert_eq!(transition, 1);
        assert_eq!(dom_active, 1);
    }

    // Check now the current domain.
    {
        let domain = state.resources.get(current);
        let mut cpu = 0;
        let mut doms = 0;
        let mut sealed = 0;
        let mut sealed_revok = 0;
        let mut sealed_active = 0;
        let mut trans = 0;
        domain.enumerate(|_, own| match *own {
            OwnedCapability::Region(_) => panic!("There is an owned region capability!"),
            OwnedCapability::CPU(h) => {
                cpu += 1;
                assert_eq!(h, state.get_current_cpu_handle());
            }
            OwnedCapability::Domain(h) => {
                doms += 1;
                let capa = state.resources.get_capa(h);
                match capa.access {
                    DomainAccess::Transition(_) => {
                        // That's the return transition.
                        assert_eq!(capa.handle, prev);
                        trans += 1;
                    }
                    DomainAccess::Sealed(_, _) => {
                        sealed += 1;
                        if capa.capa_type == CapabilityType::Resource {
                            sealed_active += 1;
                            assert_eq!(capa.handle, current);
                        } else {
                            sealed_revok += 1;
                            assert_eq!(capa.handle, current);
                        }
                    }
                    _ => panic!("Unexpected domain access"),
                }
            }
            _ => panic!("Unexpected owned capability"),
        });
        assert_eq!(cpu, 1);
        assert_eq!(doms, 3);
        assert_eq!(sealed, 2);
        assert_eq!(sealed_revok, 1);
        assert_eq!(sealed_active, 1);
        assert_eq!(trans, 1);
    }
}
