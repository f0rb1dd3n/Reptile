#include <linux/module.h> 

static int __init hello_module(void) { 
	
	printk("Hello kernel world!\n"); 
	return 0; 
} 

static void __exit bye_module(void) { 
	printk("Good bye kernel!\n"); 
}

module_init(hello_module);
module_exit(bye_module);
MODULE_LICENSE("GPL");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("F0rb1dd3n - ighor@intruder-security.com");
MODULE_DESCRIPTION("LKM hello world");

