#include <linux/kernel.h>
#include <linux/module.h>

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

int file_read(struct file *file, unsigned long long offset, unsigned char *data, unsigned int size) 
{
    //mm_segment_t oldfs;
    int ret;

    //oldfs = get_fs();
    //set_fs(get_fs());

    ret = kernel_read(file, data, size, &offset);

    //set_fs(oldfs);
    return ret;
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

	size_t buffsiz = 100;
	char data_buff[buffsiz];
	loff_t offset = 0;
	int max_count = 100;
	int cur_count = 0;
	int res = 1;
	while (cur_count < max_count && res > 0)
	{
		res = kernel_read(filp, data_buff, buffsiz, &offset);
		if (res > 0)
		{
			printk(KERN_INFO "KERN_READ: read %s\n", data_buff);
			offset += res;
			count++;
		}
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
