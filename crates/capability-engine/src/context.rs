use crate::config::NB_CONTEXTS;
use crate::gen_arena::GenArena;

pub(crate) type ContextPool = GenArena<Context, NB_CONTEXTS>;

pub struct Context {}

impl Context {
    pub const fn new() -> Self {
        Context {}
    }
}
