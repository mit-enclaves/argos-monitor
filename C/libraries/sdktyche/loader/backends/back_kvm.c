#include "back_kvm.h"
#include "common.h"
#include "../backend.h"
#include "contalloc_driver.h"
#include "sdk_tyche.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <linux/kvm.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h>
// ———————————————————————— Backend specific defines ———————————————————————— //

#define KVM_DRIVER ("/dev/kvm")
#define CONTALLOC_DRIVER ("/dev/contalloc")


// ———————————————————————————— Helper functions ———————————————————————————— //

static void default_sregs(struct kvm_sregs* sregs)
{
  //TODO!!!
}

static void default_regs(struct kvm_regs *regs)
{
  //TODO
}

// —————————————————————————————— Backend API ——————————————————————————————— //

int backend_td_create(tyche_domain_t* domain)
{
  msg_info_t info = {UNINIT_USIZE, UNINIT_USIZE};
  // Open the kvm driver.
  int kvm_fd = open(KVM_DRIVER, O_RDWR);
  if (kvm_fd < 0) {
    ERROR("Unable to open kvm driver");
    goto failure;
  }

  // Create the vm.
  domain->handle = ioctl(kvm_fd, KVM_CREATE_VM, 0); 
  if (domain->handle < 0) {
    ERROR("Unable to create a VM!");
    close(kvm_fd);
    goto failure;
  }

  domain->backend.kvm_run_mmap_size = ioctl(kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
  if (domain->backend.kvm_run_mmap_size < 0) {
    ERROR("Failure to get the vcpu mmap size.");
    close(kvm_fd);
    close(domain->handle);
    goto failure;
  }
  // Don't need it anymore?
  close(kvm_fd);
  return SUCCESS;
failure:
  return FAILURE;
}

int backend_td_alloc_mem(tyche_domain_t* domain)
{
  msg_info_t info = {0};
  if (domain == NULL) {
    ERROR("Nul argument.");
    goto failure;
  }
  // Call contalloc driver to get contiguous memory.
  domain->backend.memfd = open(CONTALLOC_DRIVER, O_RDWR);
  if (domain->backend.memfd < 0) {
    ERROR("Unable to open the contalloc driver.");
    close(domain->handle);
    goto failure;
  }
  domain->map.virtoffset = (usize) mmap(NULL, (size_t) domain->map.size,
      PROT_READ|PROT_WRITE, MAP_SHARED|MAP_POPULATE, domain->backend.memfd, 0);
  if (((void*)(domain->map.virtoffset)) == MAP_FAILED) {
    ERROR("Unable to allocate memory for the domain.");
    close(domain->handle);
    close(domain->backend.memfd);
    goto failure;
  }

  if (ioctl(domain->backend.memfd, CONTALLOC_GET_PHYSOFFSET, &info) != SUCCESS) {
    ERROR("Getting physoffset failed!");
    close(domain->handle);
    close(domain->backend.memfd);
    //TODO: munmap?
    goto failure;
  }
  domain->map.physoffset = info.physoffset; 
  return SUCCESS;
failure:
  return FAILURE;
}

int backend_td_register_region(
    tyche_domain_t* domain,
    usize vstart,
    usize size,
    memory_access_right_t flags,
    segment_type_t tpe) {
  
  backend_region_t* new_region = NULL;
  if (domain == NULL) {
    ERROR("Nul argument.");
    goto failure;
  }
  if (domain->map.virtoffset > vstart) {
    ERROR("Invalid vstart address");
    goto failure;
  }
  if (domain->map.virtoffset + domain->map.size < vstart + size) {
    ERROR("Overflow of region.");
    goto failure;
  } 

  new_region = (backend_region_t*) malloc(sizeof(backend_region_t));
  if (new_region == NULL) {
    ERROR("Unable to allocate a new region.");
    goto failure;
  }
  memset(new_region, 0, sizeof(backend_region_t));
  dll_init_elem(new_region, list);
  new_region->kvm_mem.slot = domain->backend.counter_slots++;
  new_region->kvm_mem.userspace_addr = vstart;
  new_region->kvm_mem.memory_size = size;
  new_region->kvm_mem.guest_phys_addr = (vstart - domain->map.virtoffset);
  //TODO: handle the flags? for now just save them.
  new_region->flags = flags;
  new_region->tpe = tpe;

  /// Register the region with kvm.
  if (ioctl(domain->handle, KVM_SET_USER_MEMORY_REGION, &new_region->kvm_mem) != 0) {
    ERROR("Failed to register the kvm mem region");
    goto fail_free;
  }

  /// Add the region to the list.
  dll_add(&(domain->backend.kvm_regions), new_region, list);

  /// All done!
  return SUCCESS;
fail_free:
  free(new_region);
failure:
  return FAILURE;
}

int backend_td_config(tyche_domain_t* domain, usize config, usize value)
{
 //TODO implement. For the moment it's done directly in KVM. 
 return SUCCESS;
}

int backend_td_create_vcpu(tyche_domain_t* domain, usize core_idx)
{
  struct backend_vcpu_info_t *vcpu = NULL;
  if (domain == NULL) {
    ERROR("Nul argument.");
    goto failure;
  }
  if (core_idx >= MAX_CORES || (domain->core_map & (1ULL << core_idx)) == 0) {
    ERROR("Invalid core index");
    goto failure;
  }
  // Create a vcpu. 
  vcpu = (backend_vcpu_info_t *) malloc(sizeof(backend_vcpu_info_t));
  if (vcpu == NULL) {
    ERROR("Unable to allocate vcpu for core %lld", core_idx);
    goto failure;
  }
  memset(vcpu, 0, sizeof(backend_vcpu_info_t));
  dll_init_elem(vcpu, list);
  vcpu->core_id = core_idx; 
  
  // Create the vpcu.
  vcpu->fd = ioctl(domain->handle, KVM_CREATE_VCPU, vcpu->core_id); 
  if (vcpu->fd < 0) {
    ERROR("Unable to create vcpu for core %lld", core_idx);
    goto free_failure;
  }

  // Allocate its memory region.
  vcpu->kvm_run = mmap(NULL, domain->backend.kvm_run_mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpu->fd, 0);
  if (vcpu->kvm_run == MAP_FAILED) {
    ERROR("Map failed for vcpu on core %lld", core_idx);
    goto close_failure;
  }

  // Add the vcpu to the list.
  dll_add(&(domain->vcpus), vcpu, list);  

  // All done!
  return SUCCESS;
close_failure:
  close(vcpu->fd);
free_failure:
  free(vcpu);
failure:
  return FAILURE;
}

int backend_td_init_vcpu(tyche_domain_t* domain, usize core_idx)
{
  struct backend_vcpu_info_t* vcpu = NULL;
  if (domain == NULL) {
    ERROR("Nul argument.");
    goto failure;
  }
  dll_foreach(&(domain->vcpus), vcpu, list) {
    if (vcpu->core_id == core_idx) {
      break;
    }
  }
  // Unable to find it.
  if (vcpu == NULL) {
    ERROR("Unable to find vcpu for core %lld. Call create_vcpu first!", core_idx);
    goto failure;
  }

  default_sregs(&(vcpu->sregs));
  default_regs(&(vcpu->regs));

  // TODO we need to figure out how to make this work for multiple core.
  // Store the info in the elf?
  vcpu->regs.rip = domain->config.entry;
  vcpu->regs.rsp = domain->config.stack;
  vcpu->sregs.cr3 = domain->config.page_table_root;
  //vcpu->sregs.interrupt_bitmap = ??? TODO ???;

  // Register it with kvm.
  if (ioctl(vcpu->fd, KVM_SET_SREGS, &(vcpu->sregs)) < 0) {
    ERROR("Unable to set the sregs for core %lld", core_idx);
    goto failure;
  }
  if (ioctl(vcpu->fd, KVM_SET_REGS, &(vcpu->regs)) < 0) {
    ERROR("Unable to set the regs for core %lld", core_idx);
    goto failure;
  }
  // All done!
  return SUCCESS;
failure:
  return FAILURE;
}

int backend_td_commit(tyche_domain_t* domain)
{
  if (domain == NULL) {
    ERROR("Nul argument.");
    goto failure;
  }
  //I don't think there is anything to do in the kvm case.
  //Let's keep the hook just in case though.
  return SUCCESS;
failure:
  return FAILURE;
}

int backend_td_vcpu_run(tyche_domain_t* domain, usize core)
{
  int ret = 0;
  struct backend_vcpu_info_t *vcpu = NULL;
  if (domain == NULL) {
    ERROR("Nul argument");
    goto failure;
  }
  dll_foreach(&(domain->vcpus), vcpu, list) {
    if (vcpu->core_id == core) {
      break;
    }
  }
  // Unable to find it.
  if (vcpu == NULL) {
    ERROR("Unable to find vcpu for core %lld. Call create_vcpu first!", core);
    goto failure;
  }

  ret = ioctl(vcpu->fd, KVM_RUN, 0);
  if (ret < 0) {
    ERROR("kvm run failed on core %lld", core);
    goto failure;
  }
  //All done!
  return SUCCESS;
failure:
  return FAILURE;
}

int backend_td_delete(tyche_domain_t* domain)
{
  if (domain == NULL) {
    ERROR("Nul argument.");
    goto failure;
  }
  while(!dll_is_empty(&(domain->vcpus))) {
    struct backend_vcpu_info_t *vcpu = domain->vcpus.head;
    dll_remove(&(domain->vcpus), vcpu, list);
    munmap((void*) vcpu->kvm_run, domain->backend.kvm_run_mmap_size);
    close(vcpu->fd);
    free(vcpu);
  }
  // Regions.
  while(!dll_is_empty(&(domain->backend.kvm_regions))) {
    backend_region_t *region = domain->backend.kvm_regions.head;
    dll_remove(&(domain->backend.kvm_regions), region, list);
    free(region);
  }
  // Unmap the domain.
  munmap((void*) domain->map.virtoffset, domain->map.size); 
  close(domain->handle);
  return SUCCESS;
failure:
  return FAILURE;

}
