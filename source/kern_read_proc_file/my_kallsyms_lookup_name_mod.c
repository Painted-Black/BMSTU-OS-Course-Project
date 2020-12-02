#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>
#include "my_kallsyms_lookup_name_mod.h"

#define BUFF_SIZE 50

MODULE_LICENSE("GPL");

const char* filename = "/proc/kallsyms";


struct file *file_open(const char *path, int flags, int rights) 
{
    struct file *filp = NULL;
    int err = 0;
    filp = filp_open(path, flags, rights);
    if (IS_ERR(filp)) {
        err = PTR_ERR(filp);
        return NULL;
    }
    return filp;
}

void my_str_replace(char* str, size_t len, char what, char with)
{
	size_t i;
	for (i = 0; i < len; ++i)
	{
		if (str[i] == what)
		{
			str[i] = with;
		}
	}
}

extern long long my_kallsyms_lookup_name(const char* name)
{
	struct file *filp;
	loff_t offset = 0;
	int max_count = 10;
	int cur_count = 0;
	loff_t inner_offset = 0;
	int res = 1;

	printk(KERN_INFO "MY_KALLSYMS_LOOKUP: looking up name %s\n", name);

	filp = NULL;
	filp = file_open(filename, 'r', 0);
	if (IS_ERR(filp))
	{
		printk(KERN_INFO "MY_KALLSYMS_LOOKUP: cannot open file\n");
		return -1;
	}

	while (cur_count < max_count && res > 0)
	{
		char data_buff[BUFF_SIZE];
		offset = inner_offset;
		res = kernel_read(filp, data_buff, BUFF_SIZE, &offset);
		if (res > 0)
		{
			my_str_replace(data_buff, res, '\n', '\0');
			printk(KERN_INFO "MY_KALLSYMS_LOOKUP: read %s\n", data_buff);
			inner_offset += strlen(data_buff) + 1;
		}
		cur_count++;
	}
	
	filp_close(filp, NULL);

	return 0;
}

EXPORT_SYMBOL(my_kallsyms_lookup_name);

static int fh_init(void)
{	
	printk(KERN_INFO "MY_KALLSYMS_LOOKUP: module loaded\n");

	return 0;
}

static void fh_exit(void)
{
	printk(KERN_INFO "MY_KALLSYMS_LOOKUP: module unloaded\n");
}

module_exit(fh_exit);
module_init(fh_init);
