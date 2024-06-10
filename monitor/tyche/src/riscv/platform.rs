use core::sync::atomic::Ordering;

use capa_engine::{AccessRights, CapaEngine, CapaError, Domain, Handle};
use riscv_pmp::{
    clear_pmp, pmp_write_compute, PMPAddressingMode, PMPErrorCode, PMPWriteResponse,
    FROZEN_PMP_ENTRIES, PMP_CFG_ENTRIES, PMP_ENTRIES,
};
use spin::MutexGuard;

use crate::monitor::{CoreUpdate, Monitor, PlatformState};
use crate::riscv::context::ContextRiscv;
use crate::riscv::state::{DataRiscv, StateRiscv, CONTEXTS, DOMAINS, MONITOR_IPI_SYNC};

impl PlatformState for StateRiscv {
    type DomainData = DataRiscv;
    type Context = ContextRiscv;

    fn find_buff(
        engine: &MutexGuard<CapaEngine>,
        domain_handle: Handle<Domain>,
        addr: usize,
        end: usize,
    ) -> Option<usize> {
        todo!("Implement");
    }

    fn platform_init_io_mmu(&self, addr: usize) {
        todo!();
    }

    fn get_domain(domain: Handle<Domain>) -> MutexGuard<'static, Self::DomainData> {
        DOMAINS[domain.idx()].lock()
    }

    fn get_context(domain: Handle<Domain>, core: usize) -> MutexGuard<'static, Self::Context> {
        CONTEXTS[domain.idx()][core].lock()
    }

    fn remap_core(core: usize) -> usize {
        todo!();
    }

    fn remap_core_bitmap(bitmap: u64) -> u64 {
        todo!();
    }

    fn max_cpus() -> usize {
        todo!();
    }

    fn create_context(
        &mut self,
        _engine: MutexGuard<CapaEngine>,
        current: Handle<Domain>,
        domain: Handle<Domain>,
        core: usize,
    ) -> Result<(), CapaError> {
        todo!();
    }

    fn update_permission(domain: Handle<Domain>, engine: &mut MutexGuard<CapaEngine>) -> bool {
        todo!();
    }

    fn create_domain(domain: Handle<Domain>) {
        //Todo: Is there anything that needs to be done here?
        //
        //Also, in the x86 equivalent, what happens when EPT root fails to be allocated - Domain
        //creation fails? How is this reflected in the capa engine?
    }

    fn revoke_domain(_domain: Handle<Domain>) {
        // Noop for now, might need to send IPIs once we land multi-core
    }

    fn apply_core_update(
        &mut self,
        current_domain: &mut Handle<Domain>,
        core_id: usize,
        update: &CoreUpdate,
    ) {
        log::debug!("Core Update: {}", update);
        match *update {
            CoreUpdate::TlbShootdown { src_core } => {
                log::debug!("TLB Shootdown on core {} from src {}", core_id, src_core);
                // Rewrite the PMPs
                let domain = StateRiscv::get_domain(*current_domain);
                StateRiscv::update_pmps(domain);
                MONITOR_IPI_SYNC[src_core].fetch_sub(1, Ordering::SeqCst);
            }
            CoreUpdate::Switch {
                domain,
                return_capa,
                //current_reg_state,
            } => {
                log::debug!(
                    "Domain Switch on core {} for domain {}, return_capa: {:x}",
                    core_id,
                    domain,
                    return_capa.as_usize()
                );

                let current_ctx = &mut StateRiscv::get_context(*current_domain, core_id);
                let mut next_ctx = StateRiscv::get_context(domain, core_id);
                let next_domain = StateRiscv::get_domain(domain);
                //TODO: figure out what the original current_reg_state was.
                //Apparently taken from the handler. Let's ignore it.
                Self::switch_domain(
                    current_domain,
                    current_ctx,
                    //&mut current_ctx.reg_state,
                    //current_reg_state,
                    &mut next_ctx,
                    next_domain,
                    domain,
                );

                current_ctx.reg_state.a0 = 0x0;
                current_ctx.reg_state.a1 = return_capa.as_usize() as isize;
                *current_domain = domain;
            }
            CoreUpdate::Trap {
                manager,
                trap,
                info,
            } => {
                log::debug!("Trap {} on core {}", trap, core_id);
            }
        }
    }

    fn platform_shootdown(&mut self, domain: &Handle<Domain>, core: usize, trigger: bool) {
        todo!();
    }

    fn set_core(
        &mut self,
        engine: &mut MutexGuard<CapaEngine>,
        domain: &Handle<Domain>,
        core: usize,
        idx: usize,
        value: usize,
    ) -> Result<(), CapaError> {
        todo!();
    }

    fn get_core(
        &mut self,
        engine: &mut MutexGuard<CapaEngine>,
        domain: &Handle<Domain>,
        core: usize,
        idx: usize,
    ) -> Result<usize, CapaError> {
        todo!();
    }

    fn get_core_gp(
        &mut self,
        engine: &mut MutexGuard<CapaEngine>,
        domain: &Handle<Domain>,
        core: usize,
        result: &mut [usize],
    ) -> Result<(), CapaError> {
        todo!();
    }

    fn dump_in_gp(
        &mut self,
        _engine: &mut MutexGuard<CapaEngine>,
        domain: &mut Handle<Domain>,
        core: usize,
        src: &[usize],
    ) -> Result<(), CapaError> {
        todo!();
    }

    fn extract_from_gp(
        &mut self,
        _engine: &mut MutexGuard<CapaEngine>,
        domain: &Handle<Domain>,
        core: usize,
        res: &mut [(usize, usize); 6],
    ) -> Result<(), CapaError> {
        todo!();
    }

    fn check_overlaps(
        &mut self,
        _engine: &mut MutexGuard<CapaEngine>,
        domain: Handle<Domain>,
        alias: usize,
        repeat: usize,
        region: &AccessRights,
    ) -> bool {
        todo!();
    }

    fn map_region(
        &mut self,
        engine: &mut MutexGuard<CapaEngine>,
        domain: Handle<Domain>,
        alias: usize,
        repeat: usize,
        region: &AccessRights,
    ) -> Result<(), CapaError> {
        todo!();
    }

    fn unmap_region(
        &mut self,
        _engine: &mut MutexGuard<CapaEngine>,
        domain: Handle<Domain>,
        alias: usize,
        size: usize,
    ) -> Result<(), CapaError> {
        todo!();
    }

    fn prepare_notify(domain: &Handle<Domain>, core_count: usize) {
        todo!();
    }

    fn notify_cores(_domain: &Handle<Domain>, core_id: usize, core_map: usize) {
        todo!();
    }

    fn acknowledge_notify(domain: &Handle<Domain>) {
        todo!();
    }

    fn finish_notify(domain: &Handle<Domain>) {
        todo!();
    }

    fn context_interrupted(&mut self, domain: &Handle<Domain>, core: usize) {
        todo!();
    }
}

// ————————————————————————— Monitor Implementation ————————————————————————— //

pub struct MonitorRiscv {}

impl Monitor<StateRiscv> for MonitorRiscv {}
