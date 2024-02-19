use capa_engine::{permission, AccessRights, CapaEngine, MEMOPS_ALL};

/// Snapshot testing
///
/// Checks that the given struct matches the provided snap!shot.
macro_rules! snap {
    ($snap:expr, $item:expr $(,)?) => {
        assert_eq!($snap, &format!("{}", $item));
    };
}

/// Creates a static CapaEngine and returns a mutable reference
///
/// This is required to avoid stack overflow when creating a new engine on the stack, due to the
/// size of the engine.
///
/// # SAFETY:
/// The macro returns a mutable reference to a global static, thus the usual rules applies.
/// The macro can be used multiple functions to define multiple engines in the .data section.
macro_rules! static_engine {
    () => {{
        static mut ENGINE: CapaEngine = CapaEngine::new();
        &mut ENGINE
    }};
}

// ——————————————————————————————— Scenarios ———————————————————————————————— //

#[test]
fn new_capa() {
    let engine = unsafe { static_engine!() };
    let core = 0;

    // Create initial domain
    let d0 = engine.create_manager_domain(permission::ALL).unwrap();
    let _ctx = engine.start_domain_on_core(d0, core).unwrap();

    // Create two new domains
    let d1 = engine.create_domain(d0).unwrap();
    let d2 = engine.create_domain(d0).unwrap();

    // Create initial region
    let r0 = engine
        .create_new_root_region(
            d0,
            AccessRights {
                start: 0,
                end: 0x100,
                ops: MEMOPS_ALL,
            },
        )
        .unwrap();

    // Alias and carve some regions
    let r1 = engine
        .alias_region(d0, r0, dummy_access(0x10, 0x20))
        .unwrap();
    let r2 = engine
        .carve_region(d0, r0, dummy_access(0x30, 0x50))
        .unwrap();
    let r3 = engine
        .alias_region(d0, r2, dummy_access(0x40, 0x50))
        .unwrap();
    let r4 = engine
        .carve_region(d0, r0, dummy_access(0x60, 0x80))
        .unwrap();

    // Send some of the regions
    engine.send(d0, r1, d1).unwrap();
    engine.send(d0, r2, d1).unwrap();
    engine.send(d0, r3, d2).unwrap();
    engine.send(d0, r4, d2).unwrap();

    let mut buff = vec![0; 4096];
    let n = engine.serialize_attestation(&mut buff).unwrap();
    assert!(n > 0);
    snap!("113", format!("{}", n));
}

// ————————————————————————————————— Utils —————————————————————————————————— //

fn dummy_access(start: usize, end: usize) -> AccessRights {
    AccessRights {
        start,
        end,
        ops: MEMOPS_ALL,
    }
}
