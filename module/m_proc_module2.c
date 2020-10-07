#include <linux/module.h>
#include <linux/kernel.h> 
#include <linux/proc_fs.h>
#include <linux/vmalloc.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Anastasia Ovchinnikova");

#define PROCESS_FILE_NAME "m_my_process_info2"
#define RIGHTS_FILE 0666 // (-rw-rw-rw-)
#define BUFFSIZE 100

int proc_module_init(void);
void proc_module_exit(void);
ssize_t process_write(struct file *filp, const char *buf, size_t count, loff_t *offp);
ssize_t process_read(struct file *filp, char *buf, size_t count, loff_t *offp) ;


static const struct proc_ops f_process_ops =
{
	.proc_read = process_read,
	.proc_write = process_write,
};

struct proc_dir_entry *proc_file_process;
struct proc_dir_entry *proc_info_dir;

ssize_t process_write(struct file *filp, const char *buf, size_t count, loff_t *offp)
{
	printk(KERN_INFO "+++ Process info write.\n");
	return count;
}

ssize_t process_read(struct file *filp, char *buf, size_t count, loff_t *offp) 
{	int is_error, _count, cnt;
	char* str;
	struct task_struct *task;

	printk(KERN_INFO "+++ Process info read.\n");
	
	
	is_error = 0;
	_count = 0;
	str = NULL;

	str = vmalloc(BUFFSIZE * sizeof(char));

	if (str == NULL)
	{
		printk(KERN_INFO "Unable to allocate memory");
		return 0;
	}

	//task = &init_task;
    //do
    //{
	//	_count++;
	//	//is_error = copy_to_user(buf,info_buff, 5);
    //} while ((task = next_task(task)) != &init_task);

	cnt = sprintf(str, "Proccesses total");
	printk(KERN_INFO "sprintf");
	str[cnt] = '\0';

	//memcpy(buf + (*offp), str, strlen(str));
	(*offp) += strlen(str);
	printk(KERN_INFO "sprintf");
	buf[*offp] = '\0';
	vfree(str);	  
	return 0;
}

int proc_module_init(void)
{
	//proc_info_dir = proc_mkdir(NAME_DIR, NULL);
	proc_file_process = proc_create(PROCESS_FILE_NAME, RIGHTS_FILE, NULL, &f_process_ops);
	//printk("+++ dir: %d", proc_info_dir);

	if (proc_file_process == NULL)
	{
		printk(KERN_INFO "+++ Could not initialize files in /proc");
		return -ENOMEM;
	}

	printk(KERN_INFO "+++ Proc module loaded.\n");
	return 0;
}

void proc_module_exit(void)
{
	remove_proc_entry(PROCESS_FILE_NAME, proc_info_dir);
	printk(KERN_INFO "+++ Proc module module unloaded.\n");
}

module_init(proc_module_init);
module_exit(proc_module_exit);
