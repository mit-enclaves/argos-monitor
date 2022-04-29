//! VMX bitmaps.
//!
//! Wrappers for simple and tape safe manipulation of bitmaps used throughout VMX operations.

use bitflags::bitflags;

bitflags! {
    /// Pin-based VM-execution controls.
    ///
    /// A set of bitmask flags useful when setting up [`PINBASED_EXEC_CONTROLS`] VMCS field.
    ///
    /// See Intel SDM, Volume 3C, Section 24.6.1.
    pub struct PinbasedControls: u32 {
        /// External-interrupt exiting.
        const EXTERNAL_INTERRUPT_EXITING = 1 << 0;
        /// NMI exiting.
        const NMI_EXITING                = 1 << 3;
        /// Virtual NMIs.
        const VIRTUAL_NMIS               = 1 << 5;
        /// Activate VMX-preemption timer.
        const VMX_PREEMPTION_TIMER       = 1 << 6;
        /// Process posted interrupts.
        const POSTED_INTERRUPTS          = 1 << 7;
    }

    /// Primary processor-based VM-execution controls.
    ///
    /// A set of bitmask flags useful when setting up [`PRIMARY_PROCBASED_EXEC_CONTROLS`] VMCS field.
    ///
    /// See Intel SDM, Volume 3C, Section 24.6.2, Table 24-6.
    pub struct PrimaryControls: u32 {
        /// Interrupt-window exiting.
        const INTERRUPT_WINDOW_EXITING = 1 << 2;
        /// Use TSC offsetting.
        const USE_TSC_OFFSETTING       = 1 << 3;
        /// HLT exiting.
        const HLT_EXITING              = 1 << 7;
        /// INVLPG exiting.
        const INVLPG_EXITING           = 1 << 9;
        /// MWAIT exiting.
        const MWAIT_EXITING            = 1 << 10;
        /// RDPMC exiting.
        const RDPMC_EXITING            = 1 << 11;
        /// RDTSC exiting.
        const RDTSC_EXITING            = 1 << 12;
        /// CR3-load exiting.
        const CR3_LOAD_EXITING         = 1 << 15;
        /// CR3-store exiting.
        const CR3_STORE_EXITING        = 1 << 16;
        /// CR8-load exiting.
        const CR8_LOAD_EXITING         = 1 << 19;
        /// CR8-store exiting.
        const CR8_STORE_EXITING        = 1 << 20;
        /// Use TPR shadow.
        const USE_TPR_SHADOW           = 1 << 21;
        /// NMI-window exiting.
        const NMI_WINDOW_EXITING       = 1 << 22;
        /// MOV-DR exiting
        const MOV_DR_EXITING           = 1 << 23;
        /// Unconditional I/O exiting.
        const UNCOND_IO_EXITING        = 1 << 24;
        /// Use I/O bitmaps.
        const USE_IO_BITMAPS           = 1 << 25;
        /// Monitor trap flag.
        const MONITOR_TRAP_FLAG        = 1 << 27;
        /// Use MSR bitmaps.
        const USE_MSR_BITMAPS          = 1 << 28;
        /// MONITOR exiting.
        const MONITOR_EXITING          = 1 << 29;
        /// PAUSE exiting.
        const PAUSE_EXITING            = 1 << 30;
        /// Activate secondary controls.
        const SECONDARY_CONTROLS       = 1 << 31;
    }

    /// VM-exit controls.
    ///
    /// A set of bitmask flags useful when setting up [`VMEXIT_CONTROLS`] VMCS field.
    ///
    /// See Intel SDM, Volume 3C, Section 24.7.
    pub struct ExitControls: u32 {
        /// Save debug controls.
        const SAVE_DEBUG_CONTROLS        = 1 << 2;
        /// Host address-space size.
        const HOST_ADDRESS_SPACE_SIZE    = 1 << 9;
        /// Load IA32_PERF_GLOBAL_CTRL.
        const LOAD_IA32_PERF_GLOBAL_CTRL = 1 << 12;
        /// Acknowledge interrupt on exit.
        const ACK_INTERRUPT_ON_EXIT      = 1 << 15;
        /// Save IA32_PAT.
        const SAVE_IA32_PAT              = 1 << 18;
        /// Load IA32_PAT.
        const LOAD_IA32_PAT              = 1 << 19;
        /// Save IA32_EFER.
        const SAVE_IA32_EFER             = 1 << 20;
        /// Load IA32_EFER.
        const LOAD_IA32_EFER             = 1 << 21;
        /// Save VMX-preemption timer.
        const SAVE_VMX_PREEMPTION_TIMER  = 1 << 22;
        /// Clear IA32_BNDCFGS.
        const CLEAR_IA32_BNDCFGS         = 1 << 23;
        /// Conceal VMX from PT.
        const CONCEAL_VMX_FROM_PT        = 1 << 24;
        /// Clear IA32_RTIT_CTL.
        const CLEAR_IA32_RTIT_CTL        = 1 << 25;
    }

    /// VM-entry controls.
    ///
    /// A set of bitmask flags useful when setting up [`VMENTRY_CONTROLS`] VMCS field.
    ///
    /// See Intel SDM, Volume 3C, Section 24.8.
    pub struct EntryControls: u32 {
        /// Load debug controls.
        const LOAD_DEBUG_CONTROLS        = 1 << 2;
        /// IA-32e mode guest.
        const IA32E_MODE_GUEST           = 1 << 9;
        /// Entry to SMM.
        const ENTRY_TO_SMM               = 1 << 10;
        /// Deactivate dual-monitor treatment.
        const DEACTIVATE_DUAL_MONITOR    = 1 << 11;
        /// Load IA32_PERF_GLOBAL_CTRL.
        const LOAD_IA32_PERF_GLOBAL_CTRL = 1 << 13;
        /// Load IA32_PAT.
        const LOAD_IA32_PAT              = 1 << 14;
        /// Load IA32_EFER.
        const LOAD_IA32_EFER             = 1 << 15;
        /// Load IA32_BNDCFGS.
        const LOAD_IA32_BNDCFGS          = 1 << 16;
        /// Conceal VMX from PT.
        const CONCEAL_VMX_FROM_PT        = 1 << 17;
        /// Load IA32_RTIT_CTL.
        const LOAD_IA32_RTIT_CTL         = 1 << 18;
    }

    pub struct ExceptionBitmap: u32 {
        // Dive Error #DE
        const DIVIDE_ERROR             = 1 << 0;
        // Debug #DB
        const DEBUG                    = 1 << 1;
        // Non Maskable Interrupt (NMI)
        const NMI                      = 1 << 2;
        // Breakpoint #BP
        const BREAKPOINT               = 1 << 3;
        // Overflow #OF
        const OVERFLOW                 = 1 << 4;
        // Bound range exceeded #BR
        const BOUND_RANGE_EXCEEDED     = 1 << 5;
        // Invalid Opcode #UD
        const INVALID_OPCODE           = 1 << 6;
        // Device not available #NM
        const DEVICE_NOT_AVAILABLE     = 1 << 7;
        // Double fault
        const DOUBLE_FAULT             = 1 << 8;
        // Invalid TSS exception #TS
        const INVALID_TSS              = 1 << 10;
        // Segment not present #NP
        const SEGMENT_NOT_PRESENT      = 1 << 11;
        // Stack segment #SS
        const STACK_SEGMENT_FAULT      = 1 << 12;
        // General protection fault #GP
        const GENERAL_PROTECTION_FAULT = 1 << 13;
        // Page fault #PF
        const PAGE_FAULT               = 1 << 14;
        // x87 floating point #MF
        const X87_FLOATING_POINT       = 1 << 16;
        // Alignment check #AC
        const ALIGNMENT_CHECK          = 1 << 17;
        // Machine check #MC
        const MACHINE_CHECK            = 1 << 18;
        // SIMD floating point #XF
        const SIMD_FLOATING_POINT      = 1 << 19;
        // ?
        const VIRTUALIZATION           = 1 << 20;
        // VMM communication #VC
        const VMM_COMMUNICATION        = 1 << 29;
        // Security #SX
        const SECURITY_EXCEPTION       = 1 << 30;
    }
}
