//! List of valid monitor calls.

// TODO: Because Risc-V is not implemented yet we allow dead code on that platform.
// Remove this once the Risc-V version is implemented.
#![cfg_attr(target_arch = "riscv64", allow(dead_code))]

pub const CREATE_DOMAIN: usize = 1;
pub const SEAL_DOMAIN: usize = 2;
pub const SEND: usize = 3;
pub const SEGMENT_REGION: usize = 4;
pub const REVOKE: usize = 5;
pub const DUPLICATE: usize = 6;
pub const ENUMERATE: usize = 7;
pub const SWITCH: usize = 8;
pub const EXIT: usize = 9;
pub const DEBUG: usize = 10;
pub const CONFIGURE: usize = 11;
pub const SEND_REGION: usize = 12;
pub const CONFIGURE_CORE: usize = 13;
pub const GET_CONFIG_CORE: usize = 14;
pub const ALLOC_CORE_CONTEXT: usize = 15;
pub const READ_ALL_GP: usize = 16;
pub const WRITE_ALL_GP: usize = 17;
pub const WRITE_FIELDS: usize = 18;
pub const SELF_CONFIG: usize = 19;
// TODO: remove deadcode at some point
pub const _ENCLAVE_ATTESTATION: usize = 20;
pub const REVOKE_ALIASED_REGION: usize = 21;
pub const SERIALIZE_ATTESTATION: usize = 22;
pub const RETURN_TO_MANAGER: usize = 23;
pub const GET_HPA: usize = 24;
pub const CALL_MANAGER: usize = 25;
pub const SET_CPUID_ENTRY: usize = 26;
/// For benchmarks to measure the cost of communication with tyche.
pub const _TEST_CALL: usize = 30;
pub const TPM_SELFTEST: usize = 31;

// ————————————————————— Return values for the monitor —————————————————————— //
pub const MONITOR_SUCCESS: usize = 0;
pub const MONITOR_FAILURE: usize = 1;
pub const MONITOR_SWITCH_INTERRUPTED: usize = 2;
