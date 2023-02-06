use arena::Handle;
use capabilities::access::AccessRights;
use capabilities::backend::Backend;
use capabilities::domain::{Domain, DomainAccess, OwnedCapability};
use capabilities::error::ErrorCode;
use capabilities::{Capability, Object, Pool};

use crate::{Monitor, MonitorCallResult, MonitorState, Parameters, Registers};

// ————————————————————————————————— Tyche —————————————————————————————————— //
pub struct Tyche {}

/// Valid monitor calls for the tyche profile.
pub type TycheCall = usize;

/// List of valid monitor calls.
pub const TYCHE_CREATE_DOMAIN: TycheCall = 1;
pub const TYCHE_SEAL_DOMAIN: TycheCall = 2;
pub const TYCHE_SHARE: TycheCall = 3;
pub const TYCHE_GRANT: TycheCall = 4;
pub const TYCHE_GIVE: TycheCall = 5;
pub const TYCHE_REVOKE: TycheCall = 6;
pub const TYCHE_ENUMERATE: TycheCall = 7;
pub const TYCHE_SWITCH: TycheCall = 8;
pub const TYCHE_EXIT: TycheCall = 9;

impl<B: Backend> Monitor<B> for Tyche {
    type MonitorCall = TycheCall;
    fn is_exit(&self, _state: &MonitorState<B>, params: &Parameters) -> bool {
        params.vmcall == TYCHE_EXIT
    }

    fn dispatch(&self, state: &mut MonitorState<B>, params: &Parameters) -> MonitorCallResult<B> {
        match params.vmcall {
            TYCHE_CREATE_DOMAIN => self.create_domain(state, params.arg_1, params.arg_2),
            TYCHE_SEAL_DOMAIN => self.seal_domain(state, params.arg_1),
            TYCHE_SHARE => self.share_grant(
                true,
                state,
                params.arg_1,
                params.arg_2,
                params.arg_3,
                params.arg_4,
                params.arg_5,
            ),
            TYCHE_GRANT => self.share_grant(
                false,
                state,
                params.arg_1,
                params.arg_2,
                params.arg_3,
                params.arg_4,
                params.arg_5,
            ),
            TYCHE_GIVE => self.transfer(state, params.arg_1, params.arg_2),
            TYCHE_REVOKE => self.revoke(state, params.arg_1),
            //TODO let's figure out the interface
            TYCHE_ENUMERATE => todo!(),
            TYCHE_SWITCH => todo!(),
            TYCHE_EXIT => panic!("Exit should not reach dispatch."),
            _ => panic!("Unknown MonitorCall in Tyche: {:?}", params.vmcall),
        }
    }
}

impl Tyche {
    pub fn create_domain<B: Backend>(
        &self,
        state: &mut MonitorState<B>,
        spawn: usize,
        comm: usize,
    ) -> MonitorCallResult<B> {
        let revocation = {
            state
                .get_current_domain()
                .get_local_idx()
                .map_err(|e| e.wrap())?
        };
        let (orig, new_domain) = {
            let mut current = state.get_current_domain();
            let new_access = DomainAccess::Unsealed(spawn == 1, comm == 1);
            let access = current.access;
            current.duplicate(access, new_access, &state.resources)?
        };
        // Patch up the current domain.
        let orig_idx = {
            state.set_current_domain(orig);
            let orig_capa = state.resources.get_capa(orig);
            orig_capa.get_local_idx().map_err(|e| e.wrap())?
        };
        let new_domain_idx = {
            let new_domain_capa = state.resources.get_capa(new_domain);
            new_domain_capa.get_local_idx().map_err(|e| e.wrap())?
        };
        // Return the local idx, not the pool ones.
        Ok(Registers {
            value_1: orig_idx,
            value_2: new_domain_idx,
            value_3: revocation,
            ..Default::default()
        })
    }

    pub fn seal_domain<B: Backend>(
        &self,
        state: &MonitorState<B>,
        idx: usize,
    ) -> MonitorCallResult<B> {
        let current = state.get_current_domain();

        let handle = match *state
            .resources
            .get(current.handle)
            .get_local_capa(idx)
            .map_err(|e| e.wrap())?
        {
            OwnedCapability::Domain(handle) => handle,
            _ => {
                return ErrorCode::InvalidLocalCapa.as_err();
            }
        };
        state
            .resources
            .get_capa_mut(handle)
            .seal()
            .map_err(|e| e.wrap())?;
        let dom = state.resources.get_capa(handle).handle;
        state.resources.transfer(handle, dom)?;
        Ok(Registers {
            ..Default::default()
        })
    }

    pub fn get_target<B: Backend>(
        &self,
        state: &MonitorState<B>,
        tgt_idx: usize,
    ) -> Result<Handle<Domain<B>>, ErrorCode> {
        let current = state.get_current_domain();
        let idx = match *state
            .resources
            .get(current.handle)
            .get_local_capa(tgt_idx)?
        {
            OwnedCapability::Domain(h) => {
                let capa = state.resources.get_capa(h);
                match capa.access {
                    // We do not need to check the comm.
                    DomainAccess::Unsealed(_, _) => capa.handle,
                    DomainAccess::Channel => capa.handle,
                    _ => {
                        return Err(ErrorCode::InvalidTransfer);
                    }
                }
            }
            _ => {
                return Err(ErrorCode::InvalidTransfer);
            }
        };
        Ok(idx)
    }

    pub fn transfer<B: Backend>(
        &self,
        state: &MonitorState<B>,
        tgt_idx: usize,
        idx: usize,
    ) -> MonitorCallResult<B> {
        let target = self.get_target(state, tgt_idx).map_err(|e| e.wrap())?;
        let current = state.get_current_domain().handle;
        match *state
            .resources
            .get(current)
            .get_local_capa(idx)
            .map_err(|e| e.wrap())?
        {
            // Easy cases
            OwnedCapability::CPU(h) => {
                state.resources.transfer(h, target)?;
            }
            OwnedCapability::Region(h) => {
                state.resources.transfer(h, target)?;
            }
            // Cases with checks
            OwnedCapability::Domain(h) => {
                {
                    let domain_capa = state.resources.get_capa(h);
                    match domain_capa.access {
                        DomainAccess::Unsealed(_, _) => {}
                        DomainAccess::Channel => {}
                        _ => {
                            return ErrorCode::InvalidTransfer.as_err();
                        }
                    }
                }
                state.resources.transfer(h, target)?;
            }
            _ => {
                return ErrorCode::InvalidTransfer.as_err();
            }
        };
        Ok(Registers {
            ..Default::default()
        })
    }

    pub fn share_grant<B: Backend>(
        &self,
        is_share: bool,
        state: &MonitorState<B>,
        tgt_idx: usize,
        capa_idx: usize,
        arg1: usize,
        arg2: usize,
        arg3: usize,
    ) -> MonitorCallResult<B> {
        let target = self.get_target(state, tgt_idx).map_err(|e| e.wrap())?;
        let current = state.get_current_domain().handle;
        match *state
            .resources
            .get(current)
            .get_local_capa(capa_idx)
            .map_err(|e| e.wrap())?
        {
            OwnedCapability::CPU(h) => {
                self.share_grant_inner(is_share, &state.resources, h, target, arg1, arg2, arg3)
            }
            OwnedCapability::Region(h) => {
                self.share_grant_inner(is_share, &state.resources, h, target, arg1, arg2, arg3)
            }
            OwnedCapability::Domain(h) => match state.resources.get_capa(h).access {
                DomainAccess::Channel => {
                    self.share_grant_inner(is_share, &state.resources, h, target, arg1, arg2, arg3)
                }
                _ => {
                    return ErrorCode::InvalidShareGrant.as_err();
                }
            },
            _ => {
                return ErrorCode::InvalidShareGrant.as_err();
            }
        }
    }

    fn share_grant_inner<O: Object, B: Backend>(
        &self,
        is_share: bool,
        pool: &impl Pool<O, B = B>,
        handle: Handle<Capability<O>>,
        target: Handle<Domain<B>>,
        arg1: usize,
        arg2: usize,
        arg3: usize,
    ) -> MonitorCallResult<B> {
        let orig_idx = {
            pool.get_capa(handle)
                .get_local_idx()
                .map_err(|e| e.wrap())?
        };
        let mut capa = pool.get_capa_mut(handle);
        let access = if is_share {
            capa.access
        } else {
            O::Access::get_null()
        };
        let (left, right) = capa.duplicate(access, O::from_bits(arg1, arg2, arg3), pool)?;
        pool.transfer(right, target)?;
        let left_idx = {
            if is_share {
                pool.get_capa(left).get_local_idx().map_err(|e| e.wrap())?
            } else {
                // In case of a grant, the left is null and not installed.
                orig_idx
            }
        };
        Ok(Registers {
            value_1: left_idx,
            ..Default::default()
        })
    }

    pub fn revoke<B: Backend>(
        &self,
        state: &MonitorState<B>,
        capa_idx: usize,
    ) -> MonitorCallResult<B> {
        let current = state.get_current_domain().handle;
        // We might have to access the object domain itself, so we need to do
        // this in two steps to avoid double borrow.
        let owned = match *state
            .resources
            .get(current)
            .get_local_capa(capa_idx)
            .map_err(|e| e.wrap())?
        {
            OwnedCapability::CPU(h) => OwnedCapability::CPU(h),
            OwnedCapability::Region(h) => OwnedCapability::Region(h),
            OwnedCapability::Domain(h) => OwnedCapability::Domain(h),
            _ => {
                return ErrorCode::InvalidRevocation.as_err();
            }
        };
        // Now that we don't have a reference on the object itself, we can
        // safely call the revoke function.
        match owned {
            OwnedCapability::CPU(h) => {
                state.resources.get_capa_mut(h).revoke(&state.resources)?;
            }
            OwnedCapability::Region(h) => {
                state.resources.get_capa_mut(h).revoke(&state.resources)?
            }
            OwnedCapability::Domain(h) => {
                state.resources.get_capa_mut(h).revoke(&state.resources)?
            }
            _ => {
                return ErrorCode::InvalidRevocation.as_err();
            }
        }
        Ok(Registers {
            ..Default::default()
        })
    }
}
