#include "tyche_ioctl.h"
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include "common.h"
#include "dbg_addresses.h"

// —————————————————————————————— Module Info ——————————————————————————————— //

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tyche team");
MODULE_DESCRIPTION("Tyche Driver");
MODULE_VERSION("0.01");


// —————————————————————— Loading/Unloading  functions —————————————————————— //
static int __init tyche_enclave_init(void)
{
  int result = 0;
  printk(KERN_INFO "Loading Tyche driver.");
  result = tyche_register();
  printk(KERN_INFO "tyche_register() complete");
  /* if (init_page_walker() != 0) {
    ERROR("Unable to init the page walker for some reason!");
    return -1;
  }
  printk(KERN_INFO "Exiting tyche_enclave_init"); */
  return result;
}

static void __exit tyche_enclave_exit(void)
{
  printk(KERN_INFO "Removing Tyche driver.");
  tyche_unregister();
}

// ————————————————————————— Module's Registration —————————————————————————— //

module_init(tyche_enclave_init);
module_exit(tyche_enclave_exit);
