//! VMX Model Specific Registers
//!
//! A collection of some model specific registers relevant to VMX.

use core::arch::asm;

/// First address of low MSRs.
pub const LOW_MSR_START: u32 = 0;
/// Last address of low MSRs.
pub const LOW_MSR_END: u32 = 0x1FFF;
/// First address of high MSRs.
pub const HIGH_MSR_START: u32 = 0xC000_0000;
/// Last address of high MSRs.
pub const HIGH_MSR_END: u32 = 0xC000_1FFF;

// ——————————————————————————————— Known MSRs ——————————————————————————————— //

pub const FEATURE_CONTROL: Msr = Msr::new(0x3A);
pub const IA32_FS_BASE: Msr = Msr::new(0x100); // if CPUID.80000001:EDX.[29] = 1
pub const IA32_GS_BASE: Msr = Msr::new(0x101); // if CPUID.80000001:EDX.[29] = 1
pub const SYSENTER_CS: Msr = Msr::new(0x174);
pub const SYSENTER_ESP: Msr = Msr::new(0x175);
pub const SYSENTER_EIP: Msr = Msr::new(0x176);
pub const IA32_PERF_GLOBAL_CTRL: Msr = Msr::new(0x38F);
pub const VMX_BASIC: Msr = Msr::new(0x480);
pub const VMX_PINBASED_CTLS: Msr = Msr::new(0x481);
pub const VMX_PROCBASED_CTLS: Msr = Msr::new(0x482);
pub const VMX_EXIT_CTLS: Msr = Msr::new(0x483);
pub const VMX_ENTRY_CTLS: Msr = Msr::new(0x484);
pub const VMX_MISC: Msr = Msr::new(0x485);
pub const VMX_CR0_FIXED0: Msr = Msr::new(0x486);
pub const VMX_CR0_FIXED1: Msr = Msr::new(0x487);
pub const VMX_CR4_FIXED0: Msr = Msr::new(0x488);
pub const VMX_CR4_FIXED1: Msr = Msr::new(0x489);
pub const VMX_VMCS_ENUM: Msr = Msr::new(0x48A);
pub const VMX_PROCBASED_CTLS2: Msr = Msr::new(0x48B);
pub const VMX_EPT_VPID_CAP: Msr = Msr::new(0x48C);
pub const VMX_TRUE_PINBASED_CTLS: Msr = Msr::new(0x48D);
pub const VMX_TRUE_PROCBASED_CTLS: Msr = Msr::new(0x48E);
pub const VMX_TRUE_EXIT_CTLS: Msr = Msr::new(0x48F);
pub const VMX_TRUE_ENTRY_CTLS: Msr = Msr::new(0x490);
pub const VMX_VMFUNC: Msr = Msr::new(0x491);
pub const IA32_EFER: Msr = Msr::new(0xC000_0080);

// X2APIC
pub const IA32_X2APIC_APICID: Msr = Msr::new(0x802);
pub const IA32_X2APIC_VERSION: Msr = Msr::new(0x803);
pub const IA32_X2APIC_TPR: Msr = Msr::new(0x808);
pub const IA32_X2APIC_PPR: Msr = Msr::new(0x80a);
pub const IA32_X2APIC_EOI: Msr = Msr::new(0x80b);
pub const IA32_X2APIC_LDR: Msr = Msr::new(0x80d);
pub const IA32_X2APIC_SIVR: Msr = Msr::new(0x80f);
// TMR
pub const IA32_X2APIC_TMR0: Msr = Msr::new(0x818);
pub const IA32_X2APIC_TMR1: Msr = Msr::new(0x819);
pub const IA32_X2APIC_TMR2: Msr = Msr::new(0x81a);
pub const IA32_X2APIC_TMR3: Msr = Msr::new(0x81b);
pub const IA32_X2APIC_TMR4: Msr = Msr::new(0x81c);
pub const IA32_X2APIC_TMR5: Msr = Msr::new(0x81d);
pub const IA32_X2APIC_TMR6: Msr = Msr::new(0x81e);
pub const IA32_X2APIC_TMR7: Msr = Msr::new(0x81f);
// ISR
pub const IA32_X2APIC_ISR0: Msr = Msr::new(0x810);
pub const IA32_X2APIC_ISR1: Msr = Msr::new(0x811);
pub const IA32_X2APIC_ISR2: Msr = Msr::new(0x812);
pub const IA32_X2APIC_ISR3: Msr = Msr::new(0x813);
pub const IA32_X2APIC_ISR4: Msr = Msr::new(0x814);
pub const IA32_X2APIC_ISR5: Msr = Msr::new(0x815);
pub const IA32_X2APIC_ISR6: Msr = Msr::new(0x816);
pub const IA32_X2APIC_ISR7: Msr = Msr::new(0x817);
// IRR
pub const IA32_X2APIC_IRR0: Msr = Msr::new(0x820);
pub const IA32_X2APIC_IRR1: Msr = Msr::new(0x821);
pub const IA32_X2APIC_IRR2: Msr = Msr::new(0x822);
pub const IA32_X2APIC_IRR3: Msr = Msr::new(0x823);
pub const IA32_X2APIC_IRR4: Msr = Msr::new(0x824);
pub const IA32_X2APIC_IRR5: Msr = Msr::new(0x825);
pub const IA32_X2APIC_IRR6: Msr = Msr::new(0x826);
pub const IA32_X2APIC_IRR7: Msr = Msr::new(0x827);
// IPI
pub const IA32_X2APIC_ICR0: Msr = Msr::new(0x830);
pub const IA32_X2APIC_ICR1: Msr = Msr::new(0x831);
// Timer
pub const IA32_X2APIC_LVT_TIMER: Msr = Msr::new(0x832);
pub const IA32_X2APIC_INIT_COUNT: Msr = Msr::new(0x838);
pub const IA32_X2APIC_CUR_COUNT: Msr = Msr::new(0x839);
pub const IA32_X2APIC_DIV_CONF: Msr = Msr::new(0x83e);

// —————————————————————————————————— MSR ——————————————————————————————————— //

#[derive(Debug, Clone, Copy)]
pub struct Msr(u32);

impl Msr {
    /// Creates a new MSR for it's address.
    pub const fn new(reg: u32) -> Self {
        Self(reg)
    }

    /// Returns the address of this MSR.
    pub const fn address(self) -> u32 {
        self.0
    }

    /// Reads 64 bits MSR register.
    ///
    /// ## Safety
    ///
    /// The caller must ensure that this read operation has no unsafe side
    /// effects.
    #[inline]
    pub unsafe fn read(&self) -> u64 {
        let (high, low): (u32, u32);
        asm!(
            "rdmsr",
            in("ecx") self.0,
            out("eax") low, out("edx") high,
            options(nomem, nostack, preserves_flags),
        );
        ((high as u64) << 32) | (low as u64)
    }

    /// Writes 64 bits to MSR register.
    ///
    /// ## Safety
    ///
    /// The caller must ensure that this write operation has no unsafe side
    /// effects.
    #[inline]
    pub unsafe fn write(&mut self, value: u64) {
        let low = value as u32;
        let high = (value >> 32) as u32;

        asm!(
            "wrmsr",
            in("ecx") self.0,
            in("eax") low, in("edx") high,
            options(nostack, preserves_flags),
        );
    }
}

// —————————————————————————————— MSR Bitmaps ——————————————————————————————— //

/// An MSR bitmaps that can be used to configure direct read or write access to host MSRs.
///
/// See Intel manual section 24.6.9.
#[repr(C, align(0x1000))]
pub struct MsrBitmaps {
    read_low: [u8; 1024],
    read_high: [u8; 1024],
    write_low: [u8; 1024],
    write_high: [u8; 1024],
}

impl MsrBitmaps {
    /// Configures the bitmap so that all accesses are denied.
    pub fn deny_all(&mut self) {
        // Setting a bit to 1 means deny access.
        self.read_low.fill(0xFF);
        self.read_high.fill(0xFF);
        self.write_low.fill(0xFF);
        self.write_high.fill(0xFF);
    }

    /// Configures the bitmap so that all accesses are allowed.
    pub fn allow_all(&mut self) {
        // Setting a bit 0 means allow access.
        self.read_low.fill(0x00);
        self.read_high.fill(0x00);
        self.write_low.fill(0x00);
        self.write_high.fill(0x00);
    }

    /// Deny read access to the given MSR.
    pub fn deny_read(&mut self, msr: Msr) {
        let msr = msr.address();
        let byte_address = (msr >> 3) as usize;
        let bit_mask = 1 << (msr & 0b111);
        if msr >= LOW_MSR_START && msr <= LOW_MSR_END {
            let bitmap = self.read_low[byte_address];
            self.read_low[byte_address] = bitmap | bit_mask;
        } else if msr >= HIGH_MSR_START && msr <= HIGH_MSR_END {
            let bitmap = self.read_high[byte_address];
            self.read_high[byte_address] = bitmap | bit_mask;
        }
    }

    /// Allow read access to the given MSR.
    pub fn allow_read(&mut self, msr: Msr) {
        let msr = msr.address();
        let byte_address = (msr >> 3) as usize;
        let bit_mask = !(1 << (msr & 0b111));
        if msr >= LOW_MSR_START && msr <= LOW_MSR_END {
            let bitmap = self.read_low[byte_address];
            self.read_low[byte_address] = bitmap & bit_mask;
        } else if msr >= HIGH_MSR_START && msr <= HIGH_MSR_END {
            let bitmap = self.read_high[byte_address];
            self.read_high[byte_address] = bitmap & bit_mask;
        }
    }

    /// Deny write access to the given MSR.
    pub fn deny_write(&mut self, msr: Msr) {
        let msr = msr.address();
        let byte_address = (msr >> 3) as usize;
        let bit_mask = 1 << (msr & 0b111);
        if msr >= LOW_MSR_START && msr <= LOW_MSR_END {
            let bitmap = self.write_low[byte_address];
            self.write_low[byte_address] = bitmap | bit_mask;
        } else if msr >= HIGH_MSR_START && msr <= HIGH_MSR_END {
            let bitmap = self.write_high[byte_address];
            self.write_high[byte_address] = bitmap | bit_mask;
        }
    }

    /// Allow write access to the given MSR.
    pub fn allow_write(&mut self, msr: Msr) {
        let msr = msr.address();
        let byte_address = (msr >> 3) as usize;
        let bit_mask = !(1 << (msr & 0b111));
        if msr >= LOW_MSR_START && msr <= LOW_MSR_END {
            let bitmap = self.write_low[byte_address];
            self.write_low[byte_address] = bitmap & bit_mask;
        } else if msr >= HIGH_MSR_START && msr <= HIGH_MSR_END {
            let bitmap = self.write_high[byte_address];
            self.write_high[byte_address] = bitmap & bit_mask;
        }
    }
}

// ————————————————————————————————— Tests —————————————————————————————————— //

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn msr_bitmaps() {
        // Initializes a bitmap with some "unitialized" values
        let garbage = 0b10101010;
        let mut bitmap = MsrBitmaps {
            read_low: [garbage; 1024],
            read_high: [garbage; 1024],
            write_low: [garbage; 1024],
            write_high: [garbage; 1024],
        };

        // Initializes the bitmap to default allow
        bitmap.allow_all();
        assert_eq!(bitmap.read_low[0], 0);
        assert_eq!(bitmap.read_high[0], 0);
        assert_eq!(bitmap.write_low[0], 0);
        assert_eq!(bitmap.write_high[0], 0);

        // MSR corresponding to fourth bit of the second byte of the low bitmap
        let msr_1 = Msr::new(0b1011);
        bitmap.deny_read(msr_1);
        assert_eq!(bitmap.read_low[1], 0b0000_1000);
        bitmap.deny_write(msr_1);
        assert_eq!(bitmap.write_low[1], 0b0000_1000);

        // MSR corresponding to the 6th bit of the second byte of the low bitmap
        let msr_2 = Msr::new(0b1101);
        bitmap.deny_read(msr_2);
        assert_eq!(bitmap.read_low[1], 0b0010_1000);
        bitmap.deny_write(msr_2);
        assert_eq!(bitmap.write_low[1], 0b0010_1000);

        bitmap.allow_read(msr_2);
        assert_eq!(bitmap.read_low[1], 0b0000_1000);
        bitmap.allow_read(msr_1);
        assert_eq!(bitmap.read_low[1], 0b0000_0000);

        bitmap.allow_write(msr_2);
        assert_eq!(bitmap.write_low[1], 0b0000_1000);
        bitmap.allow_write(msr_1);
        assert_eq!(bitmap.write_low[1], 0b0000_0000);
    }
}
