#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>

#include "my_kallsyms_lookup_name_mod.h"

MODULE_LICENSE("GPL");


static int test_init(void)
{
	
	long long res = my_kallsyms_lookup_name("test");
	printk(KERN_INFO "TEST got %llu\n", res);
	printk(KERN_INFO "TEST got hex %llx\n", res);

	return -1;
}

module_init(test_init);
