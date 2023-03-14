//! Represents an execution context.

use arena::{ArenaItem, Handle};

use crate::backend::{Backend, BackendContext};
use crate::domain::Domain;
use crate::error::ErrorCode;
use crate::Capability;

pub struct Context<B: Backend> {
    //TODO this should be a local capability pointer?
    pub return_context: Option<Handle<Capability<Domain<B>>>>,
    //TODO this should have a cpu associated that is a local capability too?
    pub state: B::Context,
}

impl<B: Backend> Context<B> {
    pub fn init(&mut self, arg1: usize, arg2: usize, arg3: usize) {
        self.state.init(arg1, arg2, arg3);
    }
}

// ——————————————————————— Arena Trait Implementation ——————————————————————— //

impl<B: Backend> ArenaItem for Context<B> {
    type Error = ErrorCode;
    const OUT_OF_BOUND_ERROR: Self::Error = ErrorCode::OutOfBound;
    const ALLOCATION_ERROR: Self::Error = ErrorCode::AllocationError;
}
