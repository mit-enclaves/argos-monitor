
//use capa_engine::{Context, Domain, Handle};
use super::{arch, launch_guest, monitor, guest};
use crate::debug::qemu; 


pub fn arch_entry_point(hartid: u64, arg1: u64, next_addr: u64, next_mode: u64, log_level: log::LevelFilter) -> ! {
    logger::init(log_level);
    log::info!("============= Hello from Second Stage =============");

    monitor::init(); 

    let (mut domain, ctx) = monitor::start_initial_domain_on_cpu(); 

    arch::init(); 

    unsafe { 
        //Set the active domain. 
        guest::set_active_dom_ctx(domain, ctx);
    }

    monitor::do_debug();

    //TODO: Change function name to be arch independent. Not launching guest in RV.
    launch_guest(hartid, arg1, next_addr, next_mode);
    qemu::exit(qemu::ExitCode::Success);
}
