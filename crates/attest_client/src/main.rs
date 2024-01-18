use attest_client::Context;
use capa_engine::permission;

fn main() {
    println!("Hello, World!");

    let mut ctx = Context::new();
    let r0 = ctx.root(0, 100);
    let r1 = ctx.alias(r0, 10, 20);
    let r2 = ctx.carve(r0, 30, 50);
    let r3 = ctx.alias(r2, 40, 50);
    let r4 = ctx.carve(r0, 60, 80);
    let d0 = ctx.add_domain(permission::ALL);
    let d1 = ctx.add_domain(permission::ALL);
    let d2 = ctx.add_domain(permission::NONE);
    ctx[d0].add(r0).add(d1);
    ctx[d1].add(r1).add(r2).add(d2);
    ctx[d2].add(r3).add(r4);

    println!("{:?}", &ctx);
}
