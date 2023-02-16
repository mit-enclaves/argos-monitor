//! Guests implements the guest-related operations for stage 2.
pub trait Guest {
    type ExitReason;
    type Error: core::fmt::Debug;

    fn start(&mut self);
}
