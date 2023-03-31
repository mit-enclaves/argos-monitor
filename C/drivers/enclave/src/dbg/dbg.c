#include <linux/types.h>
#include <linux/sched.h>
#include <linux/pagewalk.h>
#include <linux/mm.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <asm/pgtable_types.h>
#include <asm/io.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include "dbg.h"
#include "x86_64_pt.h"

static uint64_t other_cr3 = 0;

unsigned long debugging_cr3(void)
{
  /*void* cr3_virt = NULL;
  void* dest = NULL;
  unsigned long cr3_phys = 0;*/
  int i = 0;
  entry_t* root = NULL;
  /*cr3_virt = current->mm->pgd;
  cr3_phys = virt_to_phys(cr3_virt);
  printk(KERN_NOTICE "The current root v: %llx | p: %lx\n", (uint64_t)cr3_virt, cr3_phys);
  root = (entry_t*) phys_to_virt(cr3_phys | 0x1000);
  for (i = 0; i < 512; i++) {
    if ((root[i] & 0x1) == 0) {
      continue;
    }
    printk(KERN_NOTICE "[DUMP] %d: %llx\n", i, root[i]);
  }
  dest = alloc_pages_exact(PT_PAGE_SIZE, GFP_KERNEL);
  memcpy((void*)dest,(void*) root, PT_PAGE_SIZE);
  printk(KERN_NOTICE "The new root %llx | %llx\n", virt_to_phys(dest), PT_PAGE_SIZE);
  */
  printk(KERN_NOTICE "The registered cr3 %llx\n", other_cr3);
  root = (entry_t*)phys_to_virt(other_cr3);

  // Try copying current one into the other?
  //memcpy(&root[1], &((entry_t*)cr3_virt)[1], PT_PAGE_SIZE -sizeof(entry_t)); 

  for (i = 0; i < 512; i++) {
    if (root[i] == 0) {
      continue;
    }
    printk("[DUMP_O] %d: %llx\n",i,  root[i]);
  }
  asm (
    "cli\n\t"
    "movq $0xdeadbeef, %%rax\n\t"
    "movq %0, %%rcx\n\t"
    "vmcall\n\t"
    "movq $0x500, %%rax\n\t"
    "movq $0xbadbeef, %%rcx\n\t"
    "vmcall"
    :
    : "rm" (other_cr3)
    : "rax", "rcx", "memory");
  return other_cr3;
  //return virt_to_phys(dest);
}

void debugging_transition(domain_id_t handle)
{
  asm(
      "cli\n\t"
      "movq $0x999, %%rax\n\t"
      "movq %0, %%rcx\n\t"
      "vmcall"
      :
      : "rm" (handle)
      : "rax", "rcx", "memory"
      );
}

void register_cr3(uint64_t cr3)
{
  other_cr3 = cr3;
  printk(KERN_NOTICE "Registered cr3 %llx\n", other_cr3);
}
