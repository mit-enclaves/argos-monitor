use capabilities;

use crate::arch::BackendError;

pub type TycheError = capabilities::error::Error<BackendError>;
