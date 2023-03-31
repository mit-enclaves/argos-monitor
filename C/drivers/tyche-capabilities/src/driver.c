#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include "tyche_capabilities.h"
// —————————————————————————————— Module Info ——————————————————————————————— //

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tyche team");
MODULE_DESCRIPTION("Tyche Capability driver LKM");
MODULE_VERSION("0.01");

// ———————————————————————————————— Helpers ————————————————————————————————— //

static void* local_allocator(unsigned long size)
{
  return kmalloc(size, GFP_KERNEL);
}

static void local_free(void* ptr)
{
  kfree(ptr);
}

static void local_print(const char *msg)
{
  printk(KERN_ERR "[CAPA]: %s",msg);
}

// —————————————————————— Loading/Unloading  functions —————————————————————— //
static int __init tyche_capabilities_init(void)
{
  return init_domain(local_allocator, local_free, local_print);
}

static void __exit tyche_capabilities_exit(void)
{
  printk(KERN_INFO "Removing Tyche Capability LKM driver.");
}

// ————————————————————————————— API forwarders ————————————————————————————— //

int tc_create_domain(domain_id_t* handle)
{
  return create_domain(handle);
}

int tc_transfer_capability(domain_id_t dom, paddr_t start, paddr_t end, capability_type_t tpe)
{
  return transfer_capa(dom, start, end, tpe);
}

int tc_seal_domain(domain_id_t dom, paddr_t cr3, paddr_t entry, paddr_t stack, capa_index_t* invoke_capa)
{
  return seal_domain(dom, cr3, entry, stack, invoke_capa);
}

int tc_revoke_region(domain_id_t dom, paddr_t start, paddr_t end)
{
  return revoke_capa(dom, start, end); 
}
// ————————————————————————— Module's Registration —————————————————————————— //

module_init(tyche_capabilities_init);
module_exit(tyche_capabilities_exit);
EXPORT_SYMBOL(tc_create_domain);
EXPORT_SYMBOL(tc_transfer_capability);
EXPORT_SYMBOL(tc_seal_domain);
EXPORT_SYMBOL(tc_revoke_region);
