//! Tests for domains.

use arena::{Handle, TypedArena};

use crate::access::AccessRights;
use crate::backend::{NoBackend, EMPTY_CPU, EMPTY_CPU_CAPA, EMPTY_DOMAIN, EMPTY_DOMAIN_CAPA};
use crate::domain::{Domain, DomainAccess};
use crate::error::ErrorCode;
use crate::memory::{EMPTY_MEMORY_REGION, EMPTY_MEMORY_REGION_CAPA};
use crate::{
    domain, Capability, OPool, Pool, State, CAPA_POOL_SIZE, CPU_POOL_SIZE, DOMAIN_POOL_SIZE,
    MEMORY_POOL_SIZE,
};

#[test]
fn valid_create_true_true() {
    let sealed = DomainAccess::Sealed(true, true);
    let unsealed = DomainAccess::Unsealed(true, true);

    assert_eq!(sealed.is_subset(&unsealed), true);
    assert_eq!(sealed.is_subset(&sealed), true);
    assert_eq!(unsealed.is_subset(&sealed), false);
    assert_eq!(sealed.is_valid_dup(&sealed, &unsealed), true);
    assert_eq!(sealed.is_valid_dup(&unsealed, &sealed), false);

    // Subset of rights.
    let unsealed = DomainAccess::Unsealed(false, false);
    assert_eq!(sealed.is_subset(&unsealed), true);
    assert_eq!(unsealed.is_subset(&sealed), false);
    assert_eq!(sealed.is_valid_dup(&sealed, &unsealed), true);
    assert_eq!(sealed.is_valid_dup(&unsealed, &sealed), false);

    let unsealed = DomainAccess::Unsealed(true, false);
    assert_eq!(sealed.is_subset(&unsealed), true);
    assert_eq!(unsealed.is_subset(&sealed), false);
    assert_eq!(sealed.is_valid_dup(&sealed, &unsealed), true);
    assert_eq!(sealed.is_valid_dup(&unsealed, &sealed), false);

    let unsealed = DomainAccess::Unsealed(false, true);
    assert_eq!(sealed.is_subset(&unsealed), true);
    assert_eq!(unsealed.is_subset(&sealed), false);
    assert_eq!(sealed.is_valid_dup(&sealed, &unsealed), true);
    assert_eq!(sealed.is_valid_dup(&unsealed, &sealed), false);
}

#[test]
fn valid_create_true_false() {
    let sealed = DomainAccess::Sealed(true, false);
    let unsealed = DomainAccess::Unsealed(true, false);
    assert_eq!(sealed.is_subset(&unsealed), true);
    assert_eq!(sealed.is_subset(&sealed), true);
    assert_eq!(unsealed.is_subset(&sealed), false);
    assert_eq!(sealed.is_valid_dup(&sealed, &unsealed), true);
    assert_eq!(sealed.is_valid_dup(&unsealed, &sealed), false);
    // Invalid ones
    let unsealed = DomainAccess::Unsealed(true, true);
    assert_eq!(sealed.is_subset(&unsealed), false);
    assert_eq!(sealed.is_subset(&sealed), true);
    assert_eq!(unsealed.is_subset(&sealed), false);
    assert_eq!(sealed.is_valid_dup(&sealed, &unsealed), false);
    assert_eq!(sealed.is_valid_dup(&unsealed, &sealed), false);
}

#[test]
fn invalid_create() {
    let sealed = DomainAccess::Sealed(false, true);
    let unsealed = DomainAccess::Unsealed(false, true);
    assert_eq!(sealed.is_subset(&unsealed), false);
    assert_eq!(sealed.is_subset(&sealed), true);
    assert_eq!(unsealed.is_subset(&sealed), false);
    assert_eq!(sealed.is_valid_dup(&sealed, &unsealed), false);
    assert_eq!(sealed.is_valid_dup(&unsealed, &sealed), false);
    assert_eq!(unsealed.is_valid_dup(&unsealed, &unsealed), false);
    assert_eq!(unsealed.is_valid_dup(&unsealed, &DomainAccess::NONE), false);

    let unsealed = DomainAccess::Unsealed(false, false);
    assert_eq!(sealed.is_subset(&unsealed), false);
    assert_eq!(unsealed.is_subset(&sealed), false);
    assert_eq!(sealed.is_valid_dup(&sealed, &unsealed), false);
    assert_eq!(sealed.is_valid_dup(&unsealed, &sealed), false);
}

#[test]
fn valid_channel_sealed() {
    let source = DomainAccess::Sealed(false, true);
    let chan = DomainAccess::Channel;

    assert_eq!(source.is_subset(&chan), true);
    assert_eq!(chan.is_subset(&source), false);
    assert_eq!(source.is_valid_dup(&source, &chan), true);
    assert_eq!(source.is_valid_dup(&chan, &source), false);

    let source = DomainAccess::Sealed(true, true);
    assert_eq!(source.is_subset(&chan), true);
    assert_eq!(chan.is_subset(&source), false);
    assert_eq!(source.is_valid_dup(&source, &chan), true);
    assert_eq!(source.is_valid_dup(&chan, &source), false);

    let source = DomainAccess::Sealed(true, false);
    assert_eq!(source.is_subset(&chan), false);
    assert_eq!(chan.is_subset(&source), false);
    assert_eq!(source.is_valid_dup(&source, &chan), false);
    assert_eq!(source.is_valid_dup(&chan, &source), false);

    let source = DomainAccess::Sealed(false, false);
    assert_eq!(source.is_subset(&chan), false);
    assert_eq!(chan.is_subset(&source), false);
    assert_eq!(source.is_valid_dup(&source, &chan), false);
    assert_eq!(source.is_valid_dup(&chan, &source), false);
}

#[test]
fn valid_channel_unsealed() {
    let source = DomainAccess::Unsealed(false, true);
    let chan = DomainAccess::Channel;

    assert_eq!(source.is_subset(&chan), true);
    assert_eq!(chan.is_subset(&source), false);
    assert_eq!(source.is_valid_dup(&source, &chan), true);
    assert_eq!(source.is_valid_dup(&chan, &source), false);

    let source = DomainAccess::Unsealed(true, true);
    assert_eq!(source.is_subset(&chan), true);
    assert_eq!(chan.is_subset(&source), false);
    assert_eq!(source.is_valid_dup(&source, &chan), true);
    assert_eq!(source.is_valid_dup(&chan, &source), false);

    let source = DomainAccess::Unsealed(true, false);
    assert_eq!(source.is_subset(&chan), false);
    assert_eq!(chan.is_subset(&source), false);
    assert_eq!(source.is_valid_dup(&source, &chan), false);
    assert_eq!(source.is_valid_dup(&chan, &source), false);

    let source = DomainAccess::Unsealed(false, false);
    assert_eq!(source.is_subset(&chan), false);
    assert_eq!(chan.is_subset(&source), false);
    assert_eq!(source.is_valid_dup(&source, &chan), false);
    assert_eq!(source.is_valid_dup(&chan, &source), false);
}

#[test]
fn valid_channel_channel() {
    let chan = DomainAccess::Channel;
    assert_eq!(chan.is_subset(&chan), true);
    assert_eq!(chan.is_valid_dup(&chan, &chan), true);
    assert_eq!(chan.is_valid_dup(&chan, &DomainAccess::NONE), true);
    assert_eq!(chan.is_valid_dup(&DomainAccess::NONE, &chan), true);
    assert_eq!(
        chan.is_valid_dup(&DomainAccess::NONE, &DomainAccess::NONE),
        true
    );
}

#[test]
fn none_domain_access_sealed() {
    let none = DomainAccess::NONE;
    let sealed_t_t = DomainAccess::Sealed(true, true);
    let sealed_t_f = DomainAccess::Sealed(true, false);
    let sealed_f_t = DomainAccess::Sealed(false, true);
    let sealed_f_f = DomainAccess::Sealed(false, false);
    assert_eq!(none.is_subset(&sealed_t_t), false);
    assert_eq!(none.is_subset(&sealed_t_f), false);
    assert_eq!(none.is_subset(&sealed_f_t), false);
    assert_eq!(none.is_subset(&sealed_f_f), false);
    assert_eq!(none.is_valid_dup(&sealed_t_t, &none), false);
    assert_eq!(none.is_valid_dup(&sealed_t_f, &none), false);
    assert_eq!(none.is_valid_dup(&sealed_f_t, &none), false);
    assert_eq!(none.is_valid_dup(&sealed_f_f, &none), false);
}

#[test]
fn none_domain_access_unsealed() {
    let none = DomainAccess::NONE;
    let unsealed_t_t = DomainAccess::Unsealed(true, true);
    let unsealed_t_f = DomainAccess::Unsealed(true, false);
    let unsealed_f_t = DomainAccess::Unsealed(false, true);
    let unsealed_f_f = DomainAccess::Unsealed(false, false);
    assert_eq!(none.is_subset(&unsealed_t_t), false);
    assert_eq!(none.is_subset(&unsealed_t_f), false);
    assert_eq!(none.is_subset(&unsealed_f_t), false);
    assert_eq!(none.is_subset(&unsealed_f_f), false);
    assert_eq!(none.is_valid_dup(&unsealed_t_t, &none), false);
    assert_eq!(none.is_valid_dup(&unsealed_t_f, &none), false);
    assert_eq!(none.is_valid_dup(&unsealed_f_t, &none), false);
    assert_eq!(none.is_valid_dup(&unsealed_f_f, &none), false);
}

#[test]
fn none_domain_access_channel() {
    let none = DomainAccess::NONE;
    let chan = DomainAccess::Channel;
    assert_eq!(none.is_subset(&chan), false);
    assert_eq!(none.is_valid_dup(&chan, &none), false);
    assert_eq!(none.is_valid_dup(&none, &chan), false);
    assert_eq!(none.is_valid_dup(&chan, &chan), false);
}

#[test]
fn domain_tree() {
    let mut pools = OPool {
        domains: TypedArena::new([EMPTY_DOMAIN; DOMAIN_POOL_SIZE]),
        domain_capas: TypedArena::new([EMPTY_DOMAIN_CAPA; CAPA_POOL_SIZE]),
        regions: TypedArena::new([EMPTY_MEMORY_REGION; MEMORY_POOL_SIZE]),
        region_capas: TypedArena::new([EMPTY_MEMORY_REGION_CAPA; CAPA_POOL_SIZE]),
        cpus: TypedArena::new([EMPTY_CPU; CPU_POOL_SIZE]),
        cpu_capas: TypedArena::new([EMPTY_CPU_CAPA; CAPA_POOL_SIZE]),
    };
    let state = State::<NoBackend> {
        backend: NoBackend {},
        pools: &mut pools,
    };
    // Create an original domain.
    let default_domain_handle: Handle<Domain<NoBackend>> = match state.allocate() {
        Ok(handle) => handle,
        Err(e) => panic!("Unable to allocate default domain: {:?}", e),
    };

    // Setup attributes for the default domain.
    {
        let mut domain = state.get_mut(default_domain_handle);
        domain.is_sealed = true;
        domain.ref_count = 1;
    }

    //Create the corresponding capability.
    let default_domain_capa_handle: Handle<Capability<Domain<NoBackend>>> =
        match state.allocate_capa() {
            Ok(handle) => handle,
            Err(e) => panic!("Unable to create the default domain capa: {:?}", e),
        };
    // Setup the default domain capability.
    {
        let mut capa = state.get_capa_mut(default_domain_capa_handle);
        capa.access = domain::DEFAULT_SEALED;
        capa.handle = default_domain_handle;
    }
    match state.set_owner_capa(default_domain_capa_handle, default_domain_handle.idx()) {
        Err(e) => panic!("Error setting owners {:?}", e),
        _ => {}
    }
    // Now create children.

    let (orig, child) = {
        let mut capa = state.get_capa_mut(default_domain_capa_handle);
        let access = capa.access;
        match capa.duplicate(access, domain::DEFAULT_UNSEALED, &state) {
            Ok((o, c)) => (o, c),
            Err(e) => panic!("Could not duplicate the domain! {:?}", e),
        }
    };
    // Check the result.
    {
        let orig_capa = state.get_capa(orig);
        let child_capa = state.get_capa(child);
        assert_eq!(orig_capa.handle, default_domain_handle);
        assert_eq!(orig_capa.access, domain::DEFAULT_SEALED);
        assert_ne!(child_capa.handle, default_domain_handle);
        assert_eq!(child_capa.access, domain::DEFAULT_UNSEALED);
    }
    // Attempt illegal duplicate.
    {
        let mut child_capa = state.get_capa_mut(child);
        match child_capa.duplicate(domain::DEFAULT_SEALED, domain::DEFAULT_UNSEALED, &state) {
            Ok(_) => panic!("Duplicate should have failed!"),
            Err(e) => assert_eq!(e.code(), ErrorCode::IncreasingAccessRights),
        }
    }
}

#[test]
fn domain_revocation() {
    let mut pools = OPool {
        domains: TypedArena::new([EMPTY_DOMAIN; DOMAIN_POOL_SIZE]),
        domain_capas: TypedArena::new([EMPTY_DOMAIN_CAPA; CAPA_POOL_SIZE]),
        regions: TypedArena::new([EMPTY_MEMORY_REGION; MEMORY_POOL_SIZE]),
        region_capas: TypedArena::new([EMPTY_MEMORY_REGION_CAPA; CAPA_POOL_SIZE]),
        cpus: TypedArena::new([EMPTY_CPU; CPU_POOL_SIZE]),
        cpu_capas: TypedArena::new([EMPTY_CPU_CAPA; CAPA_POOL_SIZE]),
    };
    let state = State::<NoBackend> {
        backend: NoBackend {},
        pools: &mut pools,
    };
    // Create an original domain.
    let default_domain_handle: Handle<Domain<NoBackend>> = match state.allocate() {
        Ok(handle) => handle,
        Err(e) => panic!("Unable to allocate default domain: {:?}", e),
    };

    // Setup attributes for the default domain.
    {
        let mut domain = state.get_mut(default_domain_handle);
        domain.is_sealed = true;
        domain.ref_count = 1;
    }

    //Create the corresponding capability.
    let default_domain_capa_handle: Handle<Capability<Domain<NoBackend>>> =
        match state.allocate_capa() {
            Ok(handle) => handle,
            Err(e) => panic!("Unable to create the default domain capa: {:?}", e),
        };
    // Setup the default domain capability.
    {
        let mut capa = state.get_capa_mut(default_domain_capa_handle);
        capa.access = domain::DEFAULT_SEALED;
        capa.handle = default_domain_handle;
    }
    match state.set_owner_capa(default_domain_capa_handle, default_domain_handle.idx()) {
        Err(e) => panic!("Error setting owners {:?}", e),
        _ => {}
    }

    let (orig, child) = {
        let mut capa = state.get_capa_mut(default_domain_capa_handle);
        let access = capa.access;
        match capa.duplicate(access, domain::DEFAULT_UNSEALED, &state) {
            Ok((o, c)) => (o, c),
            Err(e) => panic!("Could not duplicate the domain! {:?}", e),
        }
    };

    // Check the pool domains
    {
        let mut counter = 0;
        for i in 0..DOMAIN_POOL_SIZE {
            if state.pools.domains.is_allocated(i) {
                counter += 1;
            }
        }
        assert_eq!(counter, 2);
    }
    // Now revoke
    {
        let mut capa = state.get_capa_mut(default_domain_capa_handle);
        match capa.revoke(&state) {
            Err(e) => panic!("Unable to perform revocation {:?}", e),
            _ => {}
        }
    }
    {
        let mut counter = 0;
        for i in 0..DOMAIN_POOL_SIZE {
            if state.pools.domains.is_allocated(i) {
                counter += 1;
            }
        }
        assert_eq!(counter, 1);
    }
}
