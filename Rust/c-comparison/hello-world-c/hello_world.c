#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
   

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Noé Terrier");	
MODULE_DESCRIPTION("C hello_world module");	


static int my_init(void)
{
    printk( KERN_NOTICE "Hello world from C module! (init)\n" );
    return  0;
}
   
static void my_exit(void)
{
    printk( KERN_NOTICE "Goodbye from C module! (exit)\n" );
    return;
}
   
module_init(my_init);
module_exit(my_exit);