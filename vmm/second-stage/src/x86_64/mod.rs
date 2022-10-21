//! x86_64 backend for stage 2

use crate::hypercalls::{Backend, ErrorCode, HypercallResult};
use crate::println;
use vmx::HostVirtAddr;
use vtd::Iommu;

pub struct Arch {
    iommu: Option<Iommu>,
}

impl Arch {
    pub fn new(iommu_addr: u64) -> Self {
        let iommu = if iommu_addr != 0 {
            unsafe { Some(Iommu::new(HostVirtAddr::new(iommu_addr as usize))) }
        } else {
            None
        };
        Self { iommu }
    }
}

impl Backend for Arch {
    fn debug_iommu(&mut self) -> HypercallResult {
        let iommu = match &mut self.iommu {
            Some(iommu) => iommu,
            None => {
                println!("Missing I/O MMU");
                return Err(ErrorCode::Failure);
            }
        };

        for fault in iommu.iter_fault() {
            println!(
                "I/O MMU fault:\n  addr:   0x{:x}\n  reason: 0x{:x}\n  record: {:?}",
                fault.addr,
                fault.record.reason(),
                fault.record
            );
        }

        Ok(Default::default())
    }
}
