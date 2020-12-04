#define pr_fmt(fmt) "ftrace_hook: " fmt

#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/timekeeping.h>

MODULE_DESCRIPTION("Example module hooking clone() and execve() via ftrace");
MODULE_AUTHOR("ilammy <a.lozovsky@gmail.com>");
MODULE_LICENSE("GPL");


/*
 * There are two ways of preventing vicious recursive loops when hooking:
 * - detect recusion using function return address (USE_FENTRY_OFFSET = 0)
 * - avoid recusion by jumping over the ftrace call (USE_FENTRY_OFFSET = 1)
 */
#define USE_FENTRY_OFFSET 0

/**
 * struct ftrace_hook - описывает перехватываемую функцию
 *
 * @name:       имя перехватываемой функции
 *
 * @function:   адрес функции-обёртки, которая будет вызываться вместо
 *              перехваченной функции
 *
 * @original:   указатель на место, куда следует записать адрес
 *              перехватываемой функции, заполняется при установке
 *
 * @address:    адрес перехватываемой функции, выясняется при установке
 *
 * @ops:        служебная информация ftrace, инициализируется нулями,
 *              при установке перехвата будет доинициализирована
 */
struct ftrace_hook {
	const char *name;
	void *function;
	void *original;

	unsigned long address;
	struct ftrace_ops ops;
};

#define LOG_FILE "/var/log/fsmonitor.log"
#define CONFIG_PATH "/etc/fsmonitor.conf"
#define BUFF_SIZE 1024//PATH_MAX
#define MONITOR_ALL_MARKER "ALL"

short Monitor_All = 0;
struct file* f;

int write_log(const char* file, const char* what)
{
	time64_t cur_seconds;
	unsigned long local_time;
	char new_sl[BUFF_SIZE];

	if (IS_ERR(f))
	{
		pr_info("Failed to write log");
		return -1;
	}

	cur_seconds = ktime_get_real_seconds(); 
	local_time = (u32)(cur_seconds - (sys_tz.tz_minuteswest * 60));

	sprintf(new_sl, "%.2lu:%.2lu:%.6lu \t %s \t %s \n",
                    (local_time / 3600) % (24),
                    (local_time / 60) % (60),
                    local_time % 60,
				    file, what);
		
	kernel_write(f, new_sl, strlen(new_sl), &f->f_pos);

	pr_info("Successfully write log");
	return 0;
}

/**
 * fh_resolve_hook_address() - поиск адреса функции, 
 * 							   которую будем перехватывать
 * @hook: хук, в котором заполнено поле name
 *
 * @returns 0 в случае успеха, иначе отрицательный код ошибки.
 */
static int fh_resolve_hook_address(struct ftrace_hook *hook)
{
	if (strcmp(hook->name, "__x64_sys_mkdir") == 0)
	{
	    hook->address = (unsigned long) 0xffffffffaf6b2680;
	}
	else
	{
	    hook->address = 0;
	}
	//hook->address = (unsigned long) 0xffffffff93aa8f80;

	if (!hook->address)
	{
		printk(KERN_INFO "unresolved symbol: %s\n", hook->name);
		return -ENOENT;
	}

#if USE_FENTRY_OFFSET
	*((unsigned long*) hook->original) = hook->address + MCOUNT_INSN_SIZE;
#else
	*((unsigned long*) hook->original) = hook->address;
#endif

	return 0;
}

/**
 *	fh_ftrace_thunk() -- коллбек, который будет вызываться 
 						 при трассировании функции
 * Изменяя регистр %rip — указатель на следующую исполняемую 
 * инструкцию,— мы изменяем инструкции, которые исполняет процессор 
 * — то есть можем заставить его выполнить безусловный переход из 
 * текущей функции в нашу. Таким образом мы перехватываем 
 * управление на себя.
 * notrace помогает предотвратить зависание системы в бесконечном цикле
 */
static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
		struct ftrace_ops *ops, struct pt_regs *regs)
{
	// получаем адрес нашей struct ftrace_hook
	// по адресу внедрённой в неё struct ftrace_ops
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

	// заменяем значение регистра %rip в структуре 
	// struct pt_regs на адрес нашего обработчика
#if USE_FENTRY_OFFSET
	regs->ip = (unsigned long) hook->function;
#else
	// parent_ip содержит адрес возврата в функцию, 
	// которая вызвала трассируемую функцию
	// можно воспользоваться им для того, 
	// чтобы отличить первый вызов перехваченной функции от повторного
	if (!within_module(parent_ip, THIS_MODULE))
		regs->ip = (unsigned long) hook->function;
#endif
}

/**
 * fh_install_hook() - регистрация и активация хука
 * @hook: хук для установки
 *
 * @returns 0 в случае успеха, иначе отрицательный код ошибки.
 */
int fh_install_hook(struct ftrace_hook *hook)
{
	int err;

	err = fh_resolve_hook_address(hook);
	if (err)
		return err;

	/*
	 * Мы будем модифицировать регистр %rip поэтому необходим флаг IPMODIFY
	 * и SAVE_REGS. Флаги предписывают ftrace сохранить и восстановить
	 * регистры процессора, содержимое которых мы сможем изменить в 
	 * коллбеке. Защита ftrace от рекурсии бесполезна, если 
	 * изменять %rip, поэтому вычлючаем ее с помощью RECURSION_SAFE.
	 * Проверки для защиты от рекурсии будут выполнены на входе в
	 * трассируемую функцию.
	 */
	hook->ops.func = fh_ftrace_thunk;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
	                | FTRACE_OPS_FL_RECURSION_SAFE
	                | FTRACE_OPS_FL_IPMODIFY;
			

	// включить ftrace для интересующей нас функции
	err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
	if (err)
	{
		printk(KERN_INFO "ftrace_set_filter_ip() failed: %d\n", err);
		return err;
	}

	// разрешить ftrace вызывать наш коллбек
	err = register_ftrace_function(&hook->ops);
	if (err)
	{
		printk(KERN_INFO "register_ftrace_function() failed: %d\n", err);
		// выключаем ftrace в случае ошибки
		ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
		return err;
	}

	return 0;
}

/**
 * fh_remove_hook() - выключить хук
 * @hook: хук для выключения
 */
void fh_remove_hook(struct ftrace_hook *hook)
{
	int err;

	// отключаем наш коллбек
	err = unregister_ftrace_function(&hook->ops);
	if (err)
	{
		printk(KERN_INFO "unregister_ftrace_function() failed: %d\n", err);
	}

	// отключаем ftrace
	err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
	if (err)
	{
		printk(KERN_INFO "ftrace_set_filter_ip() failed: %d\n", err);
	}
}

/**
 * fh_install_hooks() - регистрация хуков
 * @hooks: массив хуков для регистрации
 * @count: количество хуков для регистрации
 *
 * Если один из хуков не удалось зарегистрировать, 
 * то все остальные (которые удалось установить), удаляются.
 *
 * @returns 0 в случае успеха, иначе отрицательный код ошибки.
 */
int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
	int err = 0;
	size_t i;

	for (i = 0; i < count && err == 0; i++)
	{
		err = fh_install_hook(&hooks[i]);
		//if (err)
		//	goto error;
	}
	if (err == 0)
	{
		return 0;
	}
	while (i != 0)
	{
		fh_remove_hook(&hooks[--i]);
	}

	return err;
}

/**
 * fh_remove_hooks() - выключить хуки
 * @hooks: массив хуков для выключения
 * @count: количество хуков для выключения
 */
void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++)
		fh_remove_hook(&hooks[i]);
}

#ifndef CONFIG_X86_64
#error Currently only x86_64 architecture is supported
#endif

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

/*
 * Оптимизация хвостового вызова может помешать обнаружению рекурсии
 * на основе обратного адреса в стеке. 
 * Отключаем ее, чтобы предотвратить зависание.
 */
#if !USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif


static char *duplicate_filename(const char __user *filename)
{
	char *kernel_filename;
	int res;

	kernel_filename = kmalloc(4096, GFP_KERNEL);
	if (!kernel_filename)
		return NULL;

	if ((res = strncpy_from_user(kernel_filename, filename, 4096)) < 0)
	{
		printk(KERN_INFO "FH copy_from_user() returned %d \n", res);
		printk(KERN_INFO "FH copy_from_user() failed\n");
		kfree(kernel_filename);
		return NULL;
	}

	printk(KERN_INFO "FH copy_from_user() returned %d \n", res);

	return kernel_filename;
}

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_mkdir)(struct pt_regs *regs);

static asmlinkage long fh_sys_mkdir(struct pt_regs *regs)
{
	long ret;
	char *kernel_filename;
	char buffer[BUFF_SIZE];
	char *path;

	kernel_filename = duplicate_filename((void*) regs->di);
	write_log("FILENAME", "mkdir");

	pr_info("register mkdir() before: %s\n", kernel_filename);
	
	//smth = duplicate_filename((void*) regs->si);
	path = dentry_path_raw(current->fs->pwd.dentry, buffer, 4095);
	pr_info("register mkdir() before proc pwd: %s\n", path);
	//pr_info("register mkdir() before proc pwd: %s\n", current->fs->pwd.dentry->d_iname);

	kfree(kernel_filename);

	ret = real_sys_mkdir(regs);

	pr_info("register new mkdir() after: %ld\n", ret);

	return ret;
}
#else
static asmlinkage long (*real_sys_mkdir)(const char __user *pathname, umode_t mode);

static asmlinkage long fh_sys_mkdir(const char __user *pathname, umode_t mode)
{
	long ret;
	char *kernel_filename;

	kernel_filename = duplicate_filename(pathname);

	pr_info("mkdir() before: %s, %c, mode: %lu\n", kernel_filename, pathname[0], mode);

	kfree(kernel_filename);

	ret = real_sys_mkdir(pathname, mode);

	pr_info("mkdir() after: %ld\n", ret);

	return ret;
}
#endif

/*
 * ядра x86_64 имеют особое соглашение о названиях входных точек системных вызовов.
 */
#ifdef PTREGS_SYSCALL_STUBS
#define SYSCALL_NAME(name) ("__x64_" name)
#else
#define SYSCALL_NAME(name) (name)
#endif

#define HOOK(_name, _function, _original)	\
	{					\
		.name = SYSCALL_NAME(_name),	\
		.function = (_function),	\
		.original = (_original),	\
	}

static struct ftrace_hook fs_hooks[] = {
	HOOK("sys_mkdir", fh_sys_mkdir,  &real_sys_mkdir),
	//HOOK("sys_execve",  fh_sys_execve,  &real_sys_execve),
};

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

int process_filename(const char* filename)
{
	return 0;
	if (strcmp(filename, MONITOR_ALL_MARKER) == 0)
	{
		Monitor_All = 1;
		return 0;
	}
	else
	{
		if (filename[0] != '/' || filename[0] != '~')
		{
		}
	}
	return 0;
}

int read_config(void)
{
	struct file* file;
	int res = 1;
	loff_t offset = 0;
	loff_t inner_offset = 0;
	int return_val = 0;

	file = filp_open(CONFIG_PATH, O_RDONLY, 0);
	if (IS_ERR(f))
	{
		return -1;
	}

	pr_info("Reading config from %s\n", CONFIG_PATH);

	while (res > 0)
	{
		char* data_buff = kmalloc(BUFF_SIZE, GFP_KERNEL);
		offset = inner_offset;
		res = kernel_read(file, data_buff, BUFF_SIZE, &offset);
		if (res > 0 && return_val == 0)
		{
			my_str_replace(data_buff, res, '\n', '\0');
			pr_info("read %s\n", data_buff);
			inner_offset += strlen(data_buff) + 1;
			return_val = process_filename(data_buff);
			if (return_val != 0)
			{
				kfree((void*) data_buff);
			}
		}
	}
	filp_close(file, NULL);
	return return_val;
}

static int fh_init(void)
{
	int err;
	f = filp_open(LOG_FILE, O_APPEND | O_CREAT | O_WRONLY, 0);
	if (IS_ERR(f))
	{
		pr_info("Unable to open log file\n");
		return -1;
	}

	if ((err = read_config()) != 0)
	{
		pr_info("Unable to read config file\n");
		return err;
	}

	err = fh_install_hooks(fs_hooks, ARRAY_SIZE(fs_hooks));
	if (err)
		return err;


	printk(KERN_INFO "FH module loaded\n");

	return 0;
}
module_init(fh_init);

static void fh_exit(void)
{
	filp_close(f, NULL);
	fh_remove_hooks(fs_hooks, ARRAY_SIZE(fs_hooks));

	printk(KERN_INFO "FH module unloaded\n");
}
module_exit(fh_exit);
