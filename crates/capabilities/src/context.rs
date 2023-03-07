//! Represents an execution context.

use arena::ArenaItem;

use crate::backend::{Backend, BackendContext};
use crate::error::ErrorCode;

pub struct Context<B: Backend> {
    pub in_use: bool,
    pub state: B::Context,
}

impl<B: Backend> Context<B> {
    // TODO make these atomic
    pub fn lock(&mut self) -> bool {
        if self.in_use {
            return false;
        }
        self.in_use = true;
        return true;
    }

    pub fn unlock(&mut self) -> bool {
        if self.in_use {
            self.in_use = false;
            return true;
        }
        return false;
    }

    pub fn init(&mut self, arg1: usize, arg2: usize, arg3: usize) {
        self.in_use = false;
        self.state.init(arg1, arg2, arg3);
    }
}

// ——————————————————————— Arena Trait Implementation ——————————————————————— //
impl<B: Backend> ArenaItem for Context<B> {
    type Error = ErrorCode;
    const OUT_OF_BOUND_ERROR: Self::Error = ErrorCode::OutOfBound;
    const ALLOCATION_ERROR: Self::Error = ErrorCode::AllocationError;
}
