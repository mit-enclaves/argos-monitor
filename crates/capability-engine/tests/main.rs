use std::fmt::Write;

use capa_engine::{
    permission, AccessRights, CapaEngine, Domain, Handle, NextCapaToken, RegionTracker,
};

/// Snapshot testing
///
/// Checks that the given struct matches the provided snap!shot.
macro_rules! snap {
    ($snap:expr, $item:expr $(,)?) => {
        assert_eq!($snap, &format!("{}", $item));
    };
}

// ——————————————————————————————— Scenarios ———————————————————————————————— //

/// This scenario exercise multiple part of the engine: creating domains and region, sending and
/// revoking.
#[test]
fn scenario_1() {
    let mut engine = CapaEngine::new();

    // Create an initial domain with range 0x0 to 0x1000
    let domain = engine.create_manager_domain(permission::ALL).unwrap();
    let region = engine
        .create_root_region(
            domain,
            AccessRights {
                start: 0,
                end: 0x1000,
            },
        )
        .unwrap();
    snap!("{[0x0, 0x1000 | 1]}", regions(domain, &engine));
    snap!("{Region([0x0, 0x1000 | AC])}", capas(domain, &mut engine));
    snap!(
        "{PermissionUpdate(H(0, gen 0)), CreateDomain(H(0, gen 0))}",
        updates(&mut engine)
    );

    // Duplicate the initial range into two regions
    let (reg2, _reg3) = engine
        .duplicate_region(
            domain,
            region,
            AccessRights {
                start: 0,
                end: 0x200,
            },
            AccessRights {
                start: 0x300,
                end: 0x1000,
            },
        )
        .unwrap();
    snap!(
        "{[0x0, 0x200 | 1] -> [0x200, 0x300 | 0] -> [0x300, 0x1000 | 1]}",
        regions(domain, &engine),
    );
    snap!(
        "{Region([0x0, 0x1000 | _C]), Region([0x0, 0x200 | AC]), Region([0x300, 0x1000 | AC])}",
        capas(domain, &mut engine),
    );
    snap!("{PermissionUpdate(H(0, gen 0))}", updates(&mut engine));

    // Duplicate again
    let (_reg4, _reg5) = engine
        .duplicate_region(
            domain,
            reg2,
            AccessRights {
                start: 0,
                end: 0x50,
            },
            AccessRights {
                start: 0x50,
                end: 0x200,
            },
        )
        .unwrap();
    snap!(
        "{[0x0, 0x50 | 1] -> [0x50, 0x200 | 1] -> [0x200, 0x300 | 0] -> [0x300, 0x1000 | 1]}",
        regions(domain, &engine),
    );
    snap!(
        "{Region([0x0, 0x1000 | _C]), Region([0x0, 0x200 | _C]), Region([0x300, 0x1000 | AC]), Region([0x0, 0x50 | AC]), Region([0x50, 0x200 | AC])}",
        capas(domain, &mut engine)
    );
    snap!("{}", updates(&mut engine));

    // Create a new domain and send the inactive region there
    let dom2 = engine.create_domain(domain).unwrap();
    let domain2 = engine.get_domain_capa(domain, dom2).unwrap();
    engine.send(domain, reg2, dom2).unwrap();
    snap!(
        "{[0x0, 0x50 | 1] -> [0x50, 0x200 | 1] -> [0x200, 0x300 | 0] -> [0x300, 0x1000 | 1]}",
        regions(domain, &engine),
    );
    snap!("{}", regions(domain2, &engine));
    snap!(
        "{Region([0x0, 0x1000 | _C]), Region([0x300, 0x1000 | AC]), Region([0x0, 0x50 | AC]), Region([0x50, 0x200 | AC]), Management(2)}",
        capas(domain, &mut engine)
    );
    snap!("{Region([0x0, 0x200 | _C])}", capas(domain2, &mut engine));
    snap!("{CreateDomain(H(1, gen 0))}", updates(&mut engine));

    // Revoke the domain owning the active region. This invalidates regions from the first domain
    engine.revoke_domain(domain2).unwrap();
    snap!(
        "{[0x0, 0x50 | 0] -> [0x50, 0x200 | 0] -> [0x200, 0x300 | 0] -> [0x300, 0x1000 | 1]}",
        regions(domain, &engine),
    );
    snap!(
        "{Region([0x0, 0x1000 | _C]), Region([0x300, 0x1000 | AC])}",
        capas(domain, &mut engine)
    );
    snap!(
        "{PermissionUpdate(H(0, gen 0)), PermissionUpdate(H(0, gen 0)), RevokeDomain(H(1, gen 0))}",
        updates(&mut engine)
    );

    // Restore the initial region
    engine.restore_region(domain, region).unwrap();
    snap!(
        "{[0x0, 0x50 | 1] -> [0x50, 0x200 | 1] -> [0x200, 0x300 | 1] -> [0x300, 0x1000 | 1]}",
        regions(domain, &engine),
    );
    snap!("{Region([0x0, 0x1000 | AC])}", capas(domain, &mut engine));
    snap!("{PermissionUpdate(H(0, gen 0))}", updates(&mut engine));
}

// ————————————————————————————————— Utils —————————————————————————————————— //

fn regions(domain: Handle<Domain>, engine: &CapaEngine) -> &RegionTracker {
    engine[domain].regions()
}

fn capas(domain: Handle<Domain>, engine: &mut CapaEngine) -> String {
    let mut token = NextCapaToken::new();
    let mut buff = String::from("{");
    let mut is_first = true;

    while let Some((capa, new_token)) = engine.enumerate(domain, token) {
        if is_first {
            is_first = false;
        } else {
            buff.write_str(", ").unwrap();
        }
        buff.write_str(&format!("{:}", capa)).unwrap();
        token = new_token;
    }

    buff.write_str("}").unwrap();
    buff
}

fn updates(engine: &mut CapaEngine) -> String {
    let mut buff = String::from("{");
    let mut is_first = true;

    while let Some(update) = engine.pop_update() {
        if is_first {
            is_first = false;
        } else {
            buff.write_str(", ").unwrap();
        }
        buff.write_str(&format!("{}", update)).unwrap();
    }

    buff.write_str("}").unwrap();
    buff
}
