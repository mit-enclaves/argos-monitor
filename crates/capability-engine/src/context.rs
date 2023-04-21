use crate::gen_arena::GenArena;
use crate::N;

pub(crate) type ContextPool = GenArena<Context, N>;

pub struct Context {}

impl Context {
    pub const fn new() -> Self {
        Context {}
    }
}
