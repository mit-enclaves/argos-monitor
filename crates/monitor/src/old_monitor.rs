//! Old Monitor implements the previous monitor API.

use capabilities::backend::Backend;
use capabilities::domain::OwnedCapability;
use capabilities::error::ErrorCode;
use capabilities::Pool;
use utils::HostPhysAddr;

use crate::tyche::Tyche;
use crate::{Monitor, MonitorCallResult, MonitorState, Parameters, Registers};

pub struct OldMonitor {
    tyche: Tyche,
}
pub type OldMonitorCall = usize;

// Valid monitor Calls.
pub const DOMAIN_GET_OWN_ID: OldMonitorCall = 0x100;
pub const DOMAIN_CREATE: OldMonitorCall = 0x101;
pub const DOMAIN_SEAL: OldMonitorCall = 0x102;
pub const DOMAIN_GRANT_REGION: OldMonitorCall = 0x103;
pub const DOMAIN_SHARE_REGION: OldMonitorCall = 0x104;
pub const DOMAIN_REVOK_REGION: OldMonitorCall = 0x105;
pub const REGION_SPLIT: OldMonitorCall = 0x200;
pub const REGION_GET_INFO: OldMonitorCall = 0x201;
pub const REGION_MERGE: OldMonitorCall = 0x202;
pub const CONFIG_NB_REGIONS: OldMonitorCall = 0x400;
pub const CONFIG_READ_REGION: OldMonitorCall = 0x401;
pub const EXIT: OldMonitorCall = 0x500;
pub const DEBUG_IOMMU: OldMonitorCall = 0x600;
pub const DOMAIN_SWITCH: OldMonitorCall = 0x999;

impl<B: Backend> Monitor<B> for OldMonitor {
    type MonitorCall = OldMonitorCall;

    fn dispatch(
        &self,
        cpu: &mut B::Core,
        state: &mut MonitorState<B>,
        params: &Parameters,
    ) -> MonitorCallResult<B> {
        match params.vmcall {
            DOMAIN_GET_OWN_ID => {
                let current = state.get_current_domain().handle.idx();
                Ok(Registers {
                    value_1: current,
                    ..Default::default()
                })
            }
            DOMAIN_CREATE => self.tyche.create_domain(state, 1, 1),
            DOMAIN_SEAL => self.tyche.seal_domain(
                cpu,
                state,
                params.arg_1,
                params.arg_2,
                params.arg_3,
                params.arg_4,
                params.arg_5,
            ),
            DOMAIN_GRANT_REGION => {
                self.share_grant(false, cpu, state, params.arg_1, params.arg_2, params.arg_3)
            }
            DOMAIN_SHARE_REGION => {
                self.share_grant(true, cpu, state, params.arg_1, params.arg_2, params.arg_3)
            }
            DOMAIN_REVOK_REGION => {
                let current = state.get_current_domain().handle;
                match *state
                    .resources
                    .get(current)
                    .get_local_capa(params.arg_1)
                    .map_err(|e| e.wrap())?
                {
                    OwnedCapability::Region(_) => {}
                    _ => {
                        return ErrorCode::InvalidRevocation.as_err();
                    }
                }
                self.tyche.revoke(cpu, state, params.arg_1)
            }
            REGION_SPLIT => {
                // Check it is a region.
                let current = state.get_current_domain().handle;
                match *state
                    .resources
                    .get(current)
                    .get_local_capa(params.arg_1)
                    .map_err(|e| e.wrap())?
                {
                    OwnedCapability::Region(h) => {
                        let mut to_split = state.resources.get_capa_mut(h);
                        let mut access1 = to_split.access;
                        let mut access2 = to_split.access;
                        access1.end = HostPhysAddr::new(params.arg_2);
                        access2.start = HostPhysAddr::new(params.arg_2);
                        let (left, right) =
                            to_split.duplicate(access1, access2, &state.resources)?;
                        let left_idx = state.resources.get_capa(left).get_local_idx()?;
                        let right_idx = state.resources.get_capa(right).get_local_idx()?;
                        Ok(Registers {
                            value_1: left_idx,
                            value_2: right_idx,
                            ..Default::default()
                        })
                    }
                    _ => ErrorCode::InvalidLocalCapa.as_err(),
                }
            }
            REGION_MERGE => ErrorCode::InvalidRevocation.as_err(),
            _ => todo!(),
        }
    }
    fn is_exit(&self, _state: &MonitorState<B>, params: &Parameters) -> bool {
        params.vmcall == EXIT
    }
}

impl OldMonitor {
    fn share_grant<B: Backend>(
        &self,
        is_share: bool,
        cpu: &mut B::Core,
        state: &MonitorState<B>,
        tgt_idx: usize,
        idx: usize,
        flags: usize,
    ) -> MonitorCallResult<B> {
        let (start, end) = {
            let current = state.get_current_domain().handle;
            match *state
                .resources
                .get(current)
                .get_local_capa(idx)
                .map_err(|e| e.wrap())?
            {
                OwnedCapability::Region(h) => {
                    let reg_capa = state.resources.get_capa(h);
                    (
                        reg_capa.access.start.as_usize(),
                        reg_capa.access.end.as_usize(),
                    )
                }
                _ => {
                    return ErrorCode::InvalidShareGrant.as_err();
                }
            }
        };
        self.tyche
            .share_grant(is_share, cpu, state, tgt_idx, idx, start, end, flags)
    }
}
