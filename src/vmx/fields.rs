//! VMCS fields
//!
//! This module lists the different VMCS fields.
//!
//! Fields are classified according to their width:
//! - 16 bits
//! - 32 bits
//! - 64 bits
//! - Natural width (32 or 64 bits depending on the architecture)
//!
//! In addition, there a four distinct categories of fields:
//! - Control fields
//! - Read-only fields
//! - Guest state
//! - Host state
//!
//! To enforce correct usage of `vmwrite`, i.e. passing arguments with expected width, fields are
//! grouped by category and width and implements a trait enabling `vmwrite` with the expected
//! width.
//!
//! NOTE: `vmwrite` operates on the current VMCS.
//!
//! Usage:
//!
//! ```
//! // Bring all traits to current scope, this avoid having to import each trait individually
//! use fields::traits::*;
//!
//! // Import the desired fields
//! use fields::Ctrls64;
//!
//! // Write a value into that field
//! Ctrls64::IoBitmapA.vmwrite(0);
//! ```
//!
//! See Intel 3D Appendix B.

use super::raw;
use super::VmxError;

// ————————————————————————————————— Traits ————————————————————————————————— //

// Bring all traits into current scope
use traits::*;

pub mod traits {
    use super::*;

    /// A VMCS field containing a 64 bits value.
    pub trait VmcsField64 {
        fn raw(&self) -> u32;

        /// Writes a field to the current VMCS.
        unsafe fn vmwrite(&self, value: u64) -> Result<(), VmxError> {
            raw::vmwrite(self.raw() as u64, value)
        }
    }

    /// A VMCS field containing a 32 bits value.
    pub trait VmcsField32 {
        fn raw(&self) -> u32;

        /// Writes a field to the current VMCS.
        unsafe fn vmwrite(&self, value: u32) -> Result<(), VmxError> {
            raw::vmwrite(self.raw() as u64, value as u64)
        }
    }

    /// A VMCS field containing a 16 bits value.
    pub trait VmcsField16 {
        fn raw(&self) -> u32;

        /// Writes a field to the current VMCS.
        unsafe fn vmwrite(&self, value: u16) -> Result<(), VmxError> {
            raw::vmwrite(self.raw() as u64, value as u64)
        }
    }

    /// A VMCS field containing a natural width value (i.e. 32 bits on 32 bits systems, 64 bits on 64
    /// bits systems).
    pub trait VmcsFieldNatWidth {
        fn raw(&self) -> u32;

        /// Writes a field to the current VMCS.
        unsafe fn vmwrite(&self, value: usize) -> Result<(), VmxError> {
            raw::vmwrite(self.raw() as u64, value as u64)
        }
    }
}

// ————————————————————————————— Control Fields ————————————————————————————— //

/// VMCS fields encoding of 32 bits control fields.
#[rustfmt::skip]
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Ctrl32 {
    PinBasedExecCtrls             = 0x00004000,
    PrimaryProcBasedExecCtrls     = 0x00004002,
    ExceptionBitmap               = 0x00004004,
    PageFaultErrCodeMask          = 0x00004006,
    PageFaultErrCodeMatch         = 0x00004008,
    Cr3TargetCount                = 0x0000400A,
    VmExitCtrls                   = 0x0000400C,
    VmExitMsrStoreCount           = 0x0000400E,
    VmExitMsrLoadCount            = 0x00004010,
    VmEntryCtrls                  = 0x00004012,
    VmEntryMsrLoadCount           = 0x00004014,
    VmEntryIntInfoField           = 0x00004016,
    VmEntryExceptErrCode          = 0x00004018,
    VmEntryInstrLenght            = 0x0000401A,
    TprThreshold                  = 0x0000401C,
    SecondaryProcBasedVmExecCtrls = 0x0000401E,
    PleGap                        = 0x00004020,
    PleWindow                     = 0x00004022,
}

impl VmcsField32 for Ctrl32 {
    fn raw(&self) -> u32 {
        *self as u32
    }
}

/// VMCS fields encoding of 64 bits control fields.
#[rustfmt::skip]
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Ctrl64 {
    IoBitmapA         = 0x00002000,
    IoBitmapB         = 0x00002002,
    MsrBitmaps        = 0x00002004,
    VmExitStoreAddr   = 0x00002006,
    VmExitLoadAddr    = 0x00002008,
    VmEntryLoadAddr   = 0x0000200A,
    ExecVmcsPtr       = 0x0000200C,
    PmlAddr           = 0x0000200E,
    TscOffset         = 0x00002010,
    VirtApicAddr      = 0x00002012,
    ApicAccessAddr    = 0x00002014,
    PostedIntDescAddr = 0x00002016,
    VmFuncCtrls       = 0x00002018,
    EptPtr            = 0x0000201A,
    EoiExitBitmap0    = 0x0000201C,
    EoiExitBitmap1    = 0x0000201E,
    EoiExitBitmap2    = 0x00002020,
    EoiExitBitmap3    = 0x00002022,
    EptpListAddr      = 0x00002024,
    VmreadBitmapAddr  = 0x00002026,
    VmwriteBitmapAddr = 0x00002028,
    VirtExceptInfAddr = 0x0000202A,
    XssExitBitmap     = 0x0000202C,
    EnclsExitBitmap   = 0x0000202E,
    TscMultiplier     = 0x00002032,
}

impl VmcsField64 for Ctrl64 {
    fn raw(&self) -> u32 {
        *self as u32
    }
}

// ——————————————————————————— Host State Fields ———————————————————————————— //

/// VMCS fields encoding of 16 bits host state fields.
#[rustfmt::skip]
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum HostState16 {
    EsSelector = 0x00000C00,
    CsSelector = 0x00000C02,
    SsSelector = 0x00000C04,
    DsSelector = 0x00000C06,
    FsSelector = 0x00000C08,
    GsSelector = 0x00000C0A,
    TrSelector = 0x00000C0C,
}

impl VmcsField16 for HostState16 {
    fn raw(&self) -> u32 {
        *self as u32
    }
}

/// VMCS fields encodinf of 32 bits host state fields.
#[rustfmt::skip]
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum HostState32 {
    Ia32SysenterCs = 0x00004C00,
}

impl VmcsField32 for HostState32 {
    fn raw(&self) -> u32 {
        *self as u32
    }
}

/// VMCS fields encoding of natural width host state fields.
#[rustfmt::skip]
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum HostStateNat {
    Cr0             = 0x00006C00,
    Cr3             = 0x00006C02,
    Cr4             = 0x00006C04,
    FsBase          = 0x00006C06,
    GsBase          = 0x00006C08,
    TrBase          = 0x00006C0A,
    GdtrBase        = 0x00006C0C,
    IdtrBase        = 0x00006C0E,
    Ia32SysenterEsp = 0x00006C10,
    Ia32SysenterEip = 0x00006C12,
    Rsp             = 0x00006C14,
    Rip             = 0x00006C16,
}

impl VmcsFieldNatWidth for HostStateNat {
    fn raw(&self) -> u32 {
        *self as u32
    }
}
