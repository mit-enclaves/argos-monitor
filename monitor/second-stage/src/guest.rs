//! Guests implements the guest-related operations for stage 2.

use crate::println;

#[derive(PartialEq, Debug)]
pub enum HandlerResult {
    Resume,
    Exit,
    Crash,
}

pub trait Guest {
    type ExitReason;
    type Error: core::fmt::Debug;

    fn launch(&mut self) -> Result<Self::ExitReason, Self::Error>;
    fn resume(&mut self) -> Result<Self::ExitReason, Self::Error>;
    fn handle_exit(&mut self, reason: Self::ExitReason) -> Result<HandlerResult, Self::Error>;

    fn main_loop(&mut self) {
        let mut result = self.launch();
        //let mut counter = 0;
        loop {
            let exit_reason = match result {
                Ok(exit_reason) => self
                    .handle_exit(exit_reason)
                    .expect("Failed to handle VM exit"),
                Err(err) => {
                    println!("Guest crash: {:?}", err);
                    HandlerResult::Crash
                }
            };

            if exit_reason != HandlerResult::Resume {
                println!("Exiting guest: {:?}", exit_reason);
                break;
            }

            // Shutdown after too many VM exits
            /*counter += 1;
            if counter >= 200000 {
                println!("Too many iterations: stoping guest");
                break;
            }*/

            // Resume VM
            result = self.resume();
        }
    }
}
