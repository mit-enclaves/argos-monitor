use capa_engine::CapaError;
use vmx::fields::{VmcsField, VmcsFieldType};
use vmx::ActiveVmcs;

/// Represents all the fields that cannot be set by a user when creating a new domain.
///
///TODO(aghosn): For the moment, we have a single disallow list.
///In the future, we should come up with some bitmap-style implementation to make
///this more flexible.
const DISALLOWED_FIELDS: [VmcsField; 30] = [
    /*Ept pointer related fields.*/
    VmcsField::EptPointer,
    VmcsField::EptPointerHigh,
    VmcsField::EptpListAddress,
    VmcsField::EptpListAddressHigh,
    /*Host fields.*/
    VmcsField::HostEsSelector,
    VmcsField::HostCsSelector,
    VmcsField::HostSsSelector,
    VmcsField::HostDsSelector,
    VmcsField::HostFsSelector,
    VmcsField::HostGsSelector,
    VmcsField::HostTrSelector,
    VmcsField::HostIa32Pat,
    VmcsField::HostIa32PatHigh,
    VmcsField::HostIa32Efer,
    VmcsField::HostIa32EferHigh,
    VmcsField::HostIa32PerfGlobalCtrl,
    VmcsField::HostIa32PerfGlobalCtrlHigh,
    VmcsField::HostIa32SysenterCs,
    VmcsField::HostCr0,
    VmcsField::HostCr3,
    VmcsField::HostCr4,
    VmcsField::HostFsBase,
    VmcsField::HostGsBase,
    VmcsField::HostTrBase,
    VmcsField::HostGdtrBase,
    VmcsField::HostIdtrBase,
    VmcsField::HostIa32SysenterEsp,
    VmcsField::HostIa32SysenterEip,
    VmcsField::HostRsp,
    VmcsField::HostRip,
];

/// API to select which fields are exposed.
pub struct FilteredFields {}

impl FilteredFields {
    pub fn is_valid(idx: usize) -> bool {
        if let Some(value) = VmcsField::from_u32(idx as u32) {
            match DISALLOWED_FIELDS.iter().position(|item| *item == value) {
                Some(_) => return false,
                _ => return true,
            }
        }
        return false;
    }

    pub fn set_register(
        vcpu: &mut ActiveVmcs,
        field: VmcsField,
        value: usize,
    ) -> Result<(), CapaError> {
        if !FilteredFields::is_valid(field as usize) {
            log::error!("Invalid filtered field.");
            return Err(CapaError::InvalidOperation);
        }

        // These fields are not writable.
        if field.tpe() == VmcsFieldType::VmExitInformation {
            log::error!("Non-writable filtered field.");
            return Err(CapaError::InvalidOperation);
        }

        vcpu.set(field, value)
            .expect("Unable to write the register value");
        Ok(())
    }

    pub fn get_register(vcpu: &ActiveVmcs, field: VmcsField) -> Result<usize, CapaError> {
        if !FilteredFields::is_valid(field as usize) {
            log::error!("Invalid filtered field.");
            return Err(CapaError::InvalidOperation);
        }
        Ok(vcpu.get(field).expect("Unable to read the register value"))
    }
}
