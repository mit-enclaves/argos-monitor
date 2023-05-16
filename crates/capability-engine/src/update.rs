#![allow(dead_code)]

use core::{fmt, mem};

use crate::config::NB_UPDATES;
use crate::{Domain, Handle};

#[derive(Debug)]
pub enum Update {
    PermissionUpdate { domain: Handle<Domain> },
    RevokeDomain { domain: Handle<Domain> },
    CreateDomain { domain: Handle<Domain> },
    None,
}

pub struct UpdateBuffer {
    buff: [Update; NB_UPDATES],
    head: usize,
}

impl UpdateBuffer {
    pub const fn new() -> Self {
        const NOOP: Update = Update::None;
        UpdateBuffer {
            buff: [NOOP; NB_UPDATES],
            head: 0,
        }
    }

    pub fn push(&mut self, update: Update) {
        log::trace!("Push {}", update);

        // Safety checks
        if self.head >= self.buff.len() {
            log::error!("Update buffer is full");
            panic!("Update buffer if full");
        }
        let Update::None = self.buff[self.head] else {
            log::error!("Update buffer contains unapplied update");
            panic!("Update buffer contains unapplied update");
        };

        self.buff[self.head] = update;
        self.head += 1;
    }

    pub fn pop(&mut self) -> Option<Update> {
        log::trace!("Poping");

        if self.head == 0 {
            return None;
        }

        self.head -= 1;
        let update = mem::replace(&mut self.buff[self.head], Update::None);

        // Safety checks
        match update {
            Update::None => {
                log::error!("Update buffer contains unapplied update");
                panic!("Update buffer contains unapplied update");
            }
            _ => (),
        }

        Some(update)
    }
}

// ———————————————————————————————— Display ————————————————————————————————— //

impl fmt::Display for Update {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Update::PermissionUpdate { domain } => write!(f, "PermissionUpdate({})", domain),
            Update::RevokeDomain { domain } => write!(f, "RevokeDomain({})", domain),
            Update::CreateDomain { domain } => write!(f, "CreateDomain({})", domain),
            Update::None => write!(f, "None"),
        }
    }
}
