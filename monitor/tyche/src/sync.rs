//! Synchronization primitives

// We don't use the new barrier implementation on RISC-V yet, remove this once we do.
#![allow(dead_code)]

use core::sync::atomic::{AtomicUsize, Ordering};

pub struct Barrier {
    counter: AtomicUsize,
    unblocked: AtomicUsize,
}

impl Barrier {
    /// A fresh barrier initialized to 0.
    pub const NEW: Self = Self::new();

    pub const fn new() -> Self {
        Self {
            counter: AtomicUsize::new(0),
            unblocked: AtomicUsize::new(0),
        }
    }

    /// Initialize the barrier with a given count.
    ///
    /// No other core should wait on the barrier before it gets initialized, otherwise we consider
    /// this as a race condition and panic.
    pub fn set_count(&self, count: usize) {
        while let Err(_) =
            self.unblocked
                .compare_exchange(0, count, Ordering::SeqCst, Ordering::SeqCst)
        {
            // Come other cores are still blocked on this barrier, wait for them to be done
            core::hint::spin_loop();
        }

        self.counter
            .compare_exchange(0, count, Ordering::SeqCst, Ordering::SeqCst)
            .expect("Race condition on barrier initialization");
    }

    /// Wait on the barrier.
    pub fn wait(&self) {
        // We loop with a compare exchange so we can check that the counter is not zero and report
        // the issue if that is the case.
        loop {
            let counter = self.counter.load(Ordering::SeqCst);

            if counter == 0 {
                panic!("Tried to wait on a barrier with counter at 0");
            }

            match self.counter.compare_exchange(
                counter,
                counter - 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,                    // We've done out job
                Err(_) => core::hint::spin_loop(), // Let's try again
            }
        }

        // Now that we decremented the count by one, we wait until the count reaches 0, that is
        // until everyone waited on the barrier.
        while self.counter.load(Ordering::SeqCst) > 0 {
            core::hint::spin_loop();
        }

        // At this oint we exit the barrier, but we signaal we are done before so that the barrier
        // can be re-used.
        self.unblocked.fetch_sub(1, Ordering::SeqCst);
    }
}
