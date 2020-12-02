#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>

const char* filename = "/proc/kallsyms";

struct file *file_open(const char *path, int flags, int rights) 
{
    struct file *filp = NULL;
    //mm_segment_t oldfs;
    int err = 0;

    //oldfs = get_fs();
    //set_fs(get_fs());
    filp = filp_open(path, flags, rights);
    //set_fs(oldfs);
    if (IS_ERR(filp)) {
        err = PTR_ERR(filp);
        return NULL;
    }
    return filp;
}

void file_close(struct file *file) 
{
    filp_close(file, NULL);
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

static int fh_init(void)
{
	struct file *filp;

	printk(KERN_INFO "KERN_READ: filename: %s\n", filename);

	filp = NULL;
	filp = file_open(filename, 'r', 0);
	if (IS_ERR(filp))
	{
		printk(KERN_INFO "KERN_READ: cannot open file\n");
	}

	size_t buffsiz = 50;
	loff_t offset = 0;
	int max_count = 10;
	int cur_count = 0;
	loff_t inner_offset = 0;
	int res = 1;
	while (cur_count < max_count && res > 0)
	{
		char data_buff[buffsiz];
		offset = inner_offset;
		res = kernel_read(filp, data_buff, buffsiz, &offset);
		printk(KERN_INFO "KERN_READ: res %d\n", res);
		if (res > 0)
		{
			my_str_replace(data_buff, res, '\n', '\0');
			printk(KERN_INFO "KERN_READ: read %s\n", data_buff);
			inner_offset += strlen(data_buff) + 1;
		}
		cur_count++;
	}
	
	file_close(filp);
	
	printk(KERN_INFO "KERN_READ: module loaded\n");

	return 0;
}

static void fh_exit(void)
{
	printk(KERN_INFO "KERN_READ: module unloaded\n");
}
module_exit(fh_exit);
module_init(fh_init);
