//! List of valid monitor calls.

// TODO: Because Risc-V is not implemented yet we allow dead code on that platform.
// Remove this once the Risc-V version is implemented.
#![cfg_attr(target_arch = "riscv64", allow(dead_code))]

pub const CREATE_DOMAIN: usize = 1;
pub const SEAL_DOMAIN: usize = 2;
pub const SHARE: usize = 3;
pub const SEND: usize = 4;
pub const SEGMENT_REGION: usize = 5;
pub const REVOKE: usize = 6;
pub const DUPLICATE: usize = 7;
pub const ENUMERATE: usize = 8;
pub const SWITCH: usize = 9;
pub const EXIT: usize = 10;
pub const DEBUG: usize = 11;
pub const CONFIGURE: usize = 12;
pub const SET_ENTRY_ON_CORE: usize = 13;

//remote attestation calls
<<<<<<< HEAD
pub const GET_ATTESTATION : usize = 14;
pub const GET_RSA_KEY : usize = 15;
pub const CHALLENGE : usize = 16;
=======
pub const _GET_ATTESTATION : usize = 14;
pub const _GET_RSA_KEY : usize = 15;
pub const _CHALLENGE : usize = 16;
>>>>>>> Added mapping guest to Tyche addr space in stage 1 (support it in stage 2 ?) and initial measurement during sealing of domain. Problems: ubuntu_mount - fix the nbd problem
