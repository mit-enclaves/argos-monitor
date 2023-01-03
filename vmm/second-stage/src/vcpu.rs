#[derive(PartialEq, Debug)]
pub enum HandlerResult {
    Resume,
    Exit,
    Crash,
}

pub trait Vcpu {
    type ExitReason;
    type Error: core::fmt::Debug;

    fn launch(&mut self) -> Result<Self::ExitReason, Self::Error>;
    fn resume(&mut self) -> Result<Self::ExitReason, Self::Error>;
    fn handle_exit(&mut self, reason: Self::ExitReason) -> Result<HandlerResult, Self::Error>;
    fn main_loop(&mut self);
}
