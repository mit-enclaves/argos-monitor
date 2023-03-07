//! Tests for domains.

use core::panic;

use arena::{Handle, TypedArena};

use crate::access::AccessRights;
use crate::backend::{NoBackend, EMPTY_CPU, EMPTY_CPU_CAPA, EMPTY_DOMAIN, EMPTY_DOMAIN_CAPA};
use crate::domain::{
    Domain, DomainAccess, SealedStatus, CONTEXT_PER_DOMAIN, DEFAULT_SEALED, DEFAULT_TRANSITON,
    DEFAULT_TRANSITON_VAL,
};
use crate::error::ErrorCode;
use crate::memory::{EMPTY_MEMORY_REGION, EMPTY_MEMORY_REGION_CAPA};
use crate::{
    domain, Capability, OPool, Ownership, Pool, State, CAPA_POOL_SIZE, CPU_POOL_SIZE,
    DOMAIN_POOL_SIZE, MEMORY_POOL_SIZE,
};

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

macro_rules! full_init {
    ($pool:ident) => {
        declare_pool!(pools);
        declare_state!($pool, &pools);
    };
}

macro_rules! setup_default_domain {
    ($def_h:ident, $def_cap_h:ident, $state:expr) => {
        let ($def_h, $def_cap_h) = {
            // Create an original domain.
            let default_domain_handle: Handle<Domain<NoBackend>> = match $state.allocate() {
                Ok(handle) => handle,
                Err(e) => panic!("Unable to allocate default domain: {:?}", e),
            };

            //Create the corresponding capability.
            let default_domain_capa_handle: Handle<Capability<Domain<NoBackend>>> =
                match $state.allocate_capa() {
                    Ok(handle) => handle,
                    Err(e) => panic!("Unable to create the default domain capa: {:?}", e),
                };
            // Setup the default domain capability.
            {
                let mut capa = $state.get_capa_mut(default_domain_capa_handle);
                capa.access = domain::DEFAULT_SEALED;
                capa.handle = default_domain_handle;
            }

            match $state.set_owner_capa(default_domain_capa_handle, default_domain_handle.idx()) {
                Err(e) => panic!("Error setting owners {:?}", e),
                _ => {}
            }

            // Setup attributes for the default domain.
            {
                let mut domain = $state.get_mut(default_domain_handle);
                domain.ref_count = 1;
                let domain_capa = $state.get_capa(default_domain_capa_handle);
                if let Ownership::Domain(_, idx) = domain_capa.owner {
                    domain.sealed = SealedStatus::Sealed(Handle::new_unchecked(idx));
                } else {
                    panic!("The domain capa should be owned!");
                }
            }
            (default_domain_handle, default_domain_capa_handle)
        };
    };
}

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
fn context_test() {
    let context = DomainAccess::Transition(0);
    let empty = DomainAccess::Transition(DEFAULT_TRANSITON_VAL);
    let invalid = DomainAccess::Transition(1);
    assert_eq!(context.is_subset(&context), true);
    assert_eq!(context.is_subset(&empty), true);
    assert_eq!(context.is_subset(&invalid), false);
    assert_eq!(invalid.is_subset(&context), false);
    assert_eq!(empty.is_subset(&context), false);
    assert_eq!(empty.is_subset(&invalid), false);
    assert_eq!(context.is_valid_dup(&context, &empty), true);
    assert_eq!(context.is_valid_dup(&empty, &context), false);
    assert_eq!(context.is_valid_dup(&context, &invalid), false);
    assert_eq!(context.is_valid_dup(&invalid, &context), false);
    assert_eq!(context.is_valid_dup(&invalid, &empty), false);
    assert_eq!(context.is_valid_dup(&empty, &invalid), false);
    assert_eq!(context.is_valid_dup(&invalid, &invalid), false);
}

#[test]
fn domain_tree() {
    full_init!(state);
    setup_default_domain!(default_domain_handle, default_domain_capa_handle, state);

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
    full_init!(state);
    setup_default_domain!(_default_domain_handle, default_domain_capa_handle, state);

    let (_orig, _child) = {
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

#[test]
fn seal_revoke_test() {
    full_init!(state);
    setup_default_domain!(default_dom_handle, default_domain_capa_handle, state);
    // Do a bullshit duplicate
    {
        let (new_sealed, new_sealed_local) = {
            let mut capa = state.get_capa_mut(default_domain_capa_handle);
            let access = capa.access;
            let (new_sealed, _) = capa
                .duplicate(access, DEFAULT_TRANSITON, &state)
                .expect("Unable to duplicate");
            let new_sealed_capa = state.get_capa(new_sealed);
            match new_sealed_capa.access {
                DomainAccess::Sealed(true, true) => {}
                _ => panic!("The new sealed capa has the wrong access rights"),
            }
            let new_sealed_local = match new_sealed_capa.owner {
                Ownership::Domain(_, idx) => {
                    println!("The idx of the left one {:?}", idx);
                    idx
                }
                _ => panic!("The new sealed is not owned!"),
            };
            (new_sealed, new_sealed_local)
        };
        // Check the domain has been updated.
        let dom = state.get(default_dom_handle);
        match dom.sealed {
            SealedStatus::Sealed(h) => {
                let owned = dom
                    .get_local_capa(h.idx())
                    .expect("Unable to get local capa")
                    .as_domain()
                    .expect("Unable to convert to a domain");
                // Compare local.
                assert_eq!(new_sealed_local, h.idx());
                // Compare global.
                assert_eq!(new_sealed, owned);
            }
            _ => panic!("Unexpected sealed value"),
        }
    }
    // Now test the revocation.
    {
        let mut capa = state.get_capa_mut(default_domain_capa_handle);
        capa.revoke(&state)
            .expect("Unable to perform the revocation");
        let dom = state.get(capa.handle);
        match dom.sealed {
            SealedStatus::Sealed(idx) => {
                let handle = dom
                    .get_local_capa(idx.idx())
                    .expect("Unable to get local capa")
                    .as_domain()
                    .expect("Unable to convert to domain capa");
                assert_eq!(handle, default_domain_capa_handle);
            }
            _ => panic!("Wrong sealed status"),
        }
    }
}

#[test]
fn transition_test() {
    full_init!(state);
    setup_default_domain!(default_dom_handle, default_domain_capa_handle, state);

    // Do a transition duplicate.
    let transition = {
        let mut capa = state.get_capa_mut(default_domain_capa_handle);
        let (_new_curr, transition) = capa
            .duplicate(DEFAULT_SEALED, DEFAULT_TRANSITON, &state)
            .expect("Unable to duplicate.");
        transition
    };

    // Check we have an allocated context.
    let id = {
        let capa = state.get_capa(transition);
        let id = match capa.access {
            DomainAccess::Transition(idx) => idx,
            _ => panic!("Wrong type of capability"),
        };
        assert_eq!(default_dom_handle, capa.handle);
        let domain = state.get(capa.handle);
        assert_eq!(domain.contexts.is_allocated(id), true);
        let mut counter = 0;
        for i in 0..CONTEXT_PER_DOMAIN {
            if domain.contexts.is_allocated(i) {
                counter += 1;
            }
        }
        assert_eq!(counter, 1);
        id
    };

    // Duplicate the transition again.
    {
        let mut capa = state.get_capa_mut(transition);
        let (same_h, other_h) = capa
            .duplicate(DomainAccess::Transition(id), DEFAULT_TRANSITON, &state)
            .expect("Second duplicate failed");

        // Check that the original one still has the same id.
        if let DomainAccess::Transition(x) = capa.access {
            assert_eq!(x, id);
        } else {
            panic!("Duplicate changed the original id");
        }
        // Check the left.
        {
            let same = state.get_capa(same_h);
            if let DomainAccess::Transition(y) = same.access {
                assert_eq!(y, id);
            } else {
                panic!("Duplicate did not set the correct id");
            }
        }
        // Check the right.
        let other_id = {
            let other = state.get_capa(other_h);
            if let DomainAccess::Transition(y) = other.access {
                assert_ne!(y, id);
                y
            } else {
                panic!("Right has the same id.");
            }
        };
        // Check the domain has the correct contexts allocated.
        {
            let domain = state.get(capa.handle);
            let mut counter = 0;
            for i in 0..CONTEXT_PER_DOMAIN {
                if domain.contexts.is_allocated(i) {
                    counter += 1;
                }
            }
            assert_eq!(counter, 2);
            assert_eq!(domain.contexts.is_allocated(id), true);
            assert_eq!(domain.contexts.is_allocated(other_id), true);
        }
        // Now revoke the capa.
        capa.revoke(&state).expect("Failed revocation.");
        {
            let domain = state.get(capa.handle);
            let mut counter = 0;
            for i in 0..CONTEXT_PER_DOMAIN {
                if domain.contexts.is_allocated(i) {
                    counter += 1;
                }
            }
            assert_eq!(counter, 1);
            assert_eq!(domain.contexts.is_allocated(id), true);
            assert_eq!(domain.contexts.is_allocated(other_id), false);
        }
    }
}
