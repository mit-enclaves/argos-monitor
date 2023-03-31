#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include "tyche_enclave_ioctl.h"
// —————————————————————————————— Module Info ——————————————————————————————— //

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tyche team");
MODULE_DESCRIPTION("Tyche Enclave driver LKM");
MODULE_VERSION("0.01");


// —————————————————————— Loading/Unloading  functions —————————————————————— //
static int __init tyche_enclave_init(void)
{
  int result = 0;
  printk(KERN_INFO "Loading Tyche Enclave LKM driver.");
  result = tyche_enclave_register();
  return result;
}

static void __exit tyche_enclave_exit(void)
{
  printk(KERN_INFO "Removing Tyche Enclave LKM driver.");
  tyche_enclave_unregister();
}

// ————————————————————————— Module's Registration —————————————————————————— //

module_init(tyche_enclave_init);
module_exit(tyche_enclave_exit);
