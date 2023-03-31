#include <linux/ioctl.h>
#include <linux/kernel.h>   /* printk() */
#include <linux/cdev.h> 
#include <linux/device.h>
#include <linux/fs.h>

#include "internal/process.h"
#include "tyche_enclave_ioctl.h"
#include "dbg/dbg.h"

#define _IN_MODULE
#include "tyche_enclave.h"
#undef _IN_MODULE

#include "internal/enclave.h"

// —————————————————————— Global Driver Configuration ——————————————————————— //
static char* device_name = "tyche_enclave";
static char* device_class = "tyche";
static char* device_region = "tyche_enclave";

dev_t dev = 0;
static struct cdev tyche_cdev;
static struct class *dev_class;

// —————————————————————————————— Local State ——————————————————————————————— //
static uint64_t tyche_ids = 0; 


// File operation structure
static struct file_operations fops =
{
        .owner          = THIS_MODULE,
        //.read           = tyche_enclave_read,
        //.write          = tyche_enclave_write,
        .open           = tyche_enclave_open,
        .unlocked_ioctl = tyche_enclave_ioctl,
        //.release        = tyche_enclave_release,
};

// ———————————————————————————— Driver Functions ———————————————————————————— //

int tyche_enclave_register(void)
{
  // Allocating Major number
  if((alloc_chrdev_region(&dev, 0, 1, device_region)) <0){
    pr_err("[TE]: Cannot allocate major number\n");
    return -1;
  }
  pr_info("[TE]: Major = %d Minor = %d \n",MAJOR(dev), MINOR(dev));

  // Creating the cdev structure
  cdev_init(&tyche_cdev, &fops);

  // Adding character device to the system.
  if ((cdev_add(&tyche_cdev, dev, 1)) < 0)
  {
    pr_err("[TE]: Cannot add the device to the system.\n");
    goto r_class;
  }

  // Creating the struct class.
  if ((dev_class = class_create(THIS_MODULE, device_class)) == NULL)
  {
    pr_err("[TE]: Cannot create the struct class.\n");
    goto r_class;
  }

  // Creating the device.
  if ((device_create(dev_class, NULL, dev, NULL, device_name)) == NULL)
  {
    pr_err("[TE]: Cannot create the Device 1\n");
    goto r_device;
  }
  pr_info("[TE]: Device Driver Insert Done!\n");
  enclave_init();
  if (init_page_walker()) {
    goto r_device; 
  }
  return 0; 

r_device:
  class_destroy(dev_class);
r_class:
  unregister_chrdev_region(dev, 1);
  return -1;
}

void tyche_enclave_unregister(void)
{
  device_destroy(dev_class, dev);
  class_destroy(dev_class);
  cdev_del(&tyche_cdev);
  unregister_chrdev_region(dev, 1);
  pr_info("[TE]: Device Driver Remove Done!\n");
}

// —————————————————————————————————— API ——————————————————————————————————— //

int tyche_enclave_open(struct inode *inode, struct file *file)
{
  pr_info("[TE]: Driver Opened from user space.\n");
  return 0;
}

long tyche_enclave_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
  struct tyche_encl_create_t handle;
  struct tyche_encl_add_region_t region;
  struct tyche_encl_commit_t commit;
  struct tyche_encl_transition_t transition;
  //uint64_t dest = 0;
  switch(cmd)
  {
    case TYCHE_ENCLAVE_DBG:
      pr_info("[TE]: Invoked TYCHE_ENCLAVE_DBG.\n");
      /*dest = (uint64_t) debugging_cr3();
      if (copy_to_user((uint64_t*)arg, &dest, sizeof(uint64_t))) {
        pr_err("[TE]: Debugging error.\n");
        return -1;
      }*/
      debugging_transition(arg);
      break;
    case TYCHE_TRANSITION:
      if (copy_from_user(&transition, (struct tyche_encl_transition_t*)arg,
            sizeof(struct tyche_encl_transition_t))) {
        pr_err("[TE]: unable to copy transition argument.\n");
        return -1;
      }
      if(enclave_transition(&transition) != 0) {
        pr_err("[TE]: error enclave_transition.\n");
        return -1;
      }
      break;
    case TYCHE_ENCLAVE_DELETE:
      if (delete_enclave((tyche_encl_handle_t) arg) != 0) {
        pr_err("[TE]: delete_enclave failed!\n");
        return -1;
      }
      break;
    case TYCHE_ENCLAVE_CREATE:
      // TODO replace this with a tyche vmcall that yields an address
      // to a page that's map exclusively to the vm and then return an index.
      handle.handle = tyche_ids++;

      //TODO initialize some internal structure etc. to keep track of the enclave.
      if(add_enclave(handle.handle)) {
        pr_err("[TE]: Error adding the enclave!\n");
        return -1;
      }

      // Return handle number to the user.
      if (copy_to_user((struct tyche_encl_create_t*)arg, &handle, sizeof(handle)))
      {
        pr_err("[TE]: Error copying handle to user space.\n");
        return -1;
      }
      break;
    case TYCHE_ENCLAVE_ADD_REGION:
      //TODO THIS IS DANGEROUS AS IT ALLOWS TO WRITE ON A STACK VARIABLE
      //CHANGE THIS.
      if (copy_from_user(&region, (struct tyche_encl_add_region_t*)arg, sizeof(region)))
      {
        pr_err("[TE]: Error copying region from user space.\n");
        return -1;
      }
     
      // The region is now safe against TOCTOU.
      if (add_region(&region) == -1) {
        pr_err("[TE]: Failed to add region.\n");
        return -1;
      }
      break;
    case TYCHE_ENCLAVE_COMMIT:
      if (copy_from_user(&commit, (struct tyche_encl_commit_t*)arg, sizeof(commit))) {
        pr_err("[TE]: failed to copy commit message.\n");
      }
      if (commit_enclave(&commit) == -1) {
        pr_err("[TE]: Failed to commit the enclave!\n");
        return -1;
      } 
      // Copy back the result.
      if (copy_to_user((struct tyche_encl_commit_t*)arg, &commit, sizeof(commit))) {
        pr_err("[TE]: Failed to copy back the commit result.\n");
        return -1;
      }
      break;
    case TYCHE_ENCLAVE_ADD_STACK:
      if (copy_from_user(&region, (struct tyche_encl_add_region_t*) arg, sizeof(region)))
      {
        pr_err("[TE]: error copying stack region from user space.\n");
        return -1;
      }
      if (add_stack_region(&region) == -1) {
        pr_err("[TE]: unable to add the stack region.\n");
        return -1;
      }  
      break; 
    default:
      pr_err("[TE]: Wrong command for tyche enclave driver.\n");
      return -1;
      break;
  }
  return 0; 
}


