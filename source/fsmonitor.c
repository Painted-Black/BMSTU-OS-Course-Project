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
#include <linux/stat.h>
#include <linux/types.h>
#include <linux/buffer_head.h>
#include <linux/fdtable.h>

MODULE_DESCRIPTION("File system monitor");
MODULE_AUTHOR("Ovchinnikova Anastasia");
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
struct ftrace_hook
{
	const char *name;
	void *function;
	void *original;

	unsigned long address;
	struct ftrace_ops ops;
};

#define LOG_FILE "/var/log/fsmonitor.log"
#define CONFIG_PATH "/etc/fsmonitor.conf"
#define BUFF_SIZE 1024 //PATH_MAX
#define MONITOR_ALL_MARKER "ALL"

struct list_node
{
	struct list_node *next_node;
	void *value;
	size_t type_size;
};

struct list
{
	struct list_node *head;
	struct list_node *tail;
};

short Monitor_All = 0;
struct file *f;
struct list monitor_files, monitor_dirs;
loff_t File_Pos = 0;

/**
 * инициализация списка
 */
void init(struct list *lst)
{
	lst->head = NULL;
	lst->tail = NULL;
}

/**
 * добавление элемента в список
 */
struct list_node *push(struct list *node, void *value, size_t size)
{
	void *next_node = kmalloc(sizeof(struct list_node) + size, GFP_KERNEL);
	struct list_node *__next_node = next_node;
	__next_node->value = next_node + sizeof(struct list_node);
	__next_node->type_size = size;
	__next_node->next_node = NULL;
	memcpy(__next_node->value, value, size);

	if (node->head == NULL)
	{
		node->head = __next_node;
		node->tail = __next_node;
	}
	else
	{
		node->tail->next_node = __next_node;
		node->tail = __next_node;
	}

	return next_node;
}

/*
 * удаление элемента из списка
 */
struct list_node *pop(struct list *node)
{
	struct list_node *value = node->head == NULL
								  ? NULL
								  : node->head->next_node;

	if (value != NULL)
	{
		kfree(node->head);
		node->head = value;
	}
	return value;
}

/**
 * очищение списка
 */ 
void free_list(struct list *list)
{
	if (list->head != NULL)
	{
		do
		{
			//pr_info("Deleting %s\n", *(char **)list->head->value);
			kfree(*(char **)list->head->value);
		} while (pop(list) != NULL);
	}
}

/**
 * удаляет последний элемент пути (path/to/file -> path/to)
 */
char *cut_last_filename(char *filename)
{
	size_t n;
	int i = 0, go = 1;
	n = strlen(filename);
	for (i = n - 1; i >= 0 && go == 1; --i)
	{
		if (filename[i] == '/')
		{
			go = 0;
		}
		filename[i] = '\0';
	}
	return filename;
}

int write_log(const char *log)
{
	time64_t cur_seconds;
	unsigned long local_time;
	char *new_sl;
	int ret;

	new_sl = kmalloc(BUFF_SIZE, GFP_KERNEL);
	if (new_sl == NULL)
	{
		pr_info("Unable to allocate memory\n");
		return -1;
	}

	if (log == NULL)
	{
		pr_info("Empty log message.\n");
		return -1;
	}

	if (IS_ERR(f))
	{
		pr_info("Failed to write log");
		return -1;
	}

	cur_seconds = ktime_get_real_seconds();
	local_time = (u32)(cur_seconds - (sys_tz.tz_minuteswest * 60));

	snprintf(new_sl, BUFF_SIZE, "%.2lu:%.2lu:%.6lu \t %s",
			 (local_time / 3600) % (24),
			 (local_time / 60) % (60),
			 local_time % 60,
			 log);

	ret = kernel_write(f, new_sl, strlen(new_sl), &File_Pos);
	File_Pos += strlen(new_sl);
	kfree(new_sl);

	return 0;
}

/**
 * проверяет, содержит ли список имя name
 * @returns 1 если да, иначе 0 
 */
int list_find(struct list *list, const char *name)
{
	struct list_node *_node = list->head;
	int ret = 0;
	while (_node != NULL && ret == 0)
	{
		if (strcmp(name, *(char **)_node->value) == 0)
		{
			ret = 1;
		}
		_node = _node->next_node;
	}
	return ret;
}

/**
 * проверяет, находится ли данный файл в списке отслеживаемых
 * @returns 1 если да, иначе 0 
 */
int check_filename(const char *filename, int search_file, int search_dir)
{
	int ret = 0;

	if (search_file == 1 && search_dir == 0)
	{
		ret = list_find(&monitor_files, filename);
		return ret;
	}
	if (search_dir == 1 && search_file == 0)
	{
		ret = list_find(&monitor_dirs, filename);
		return ret;
	}
	if (search_file == 1 && search_dir == 1)
	{
		ret = list_find(&monitor_files, filename);
		ret += list_find(&monitor_dirs, filename);
		if (ret == 2)
		{
			ret--;
		}
		return ret;
	}
	return ret;
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
	hook->address = kallsyms_lookup_name(hook->name);

	if (!hook->address)
	{
		printk(KERN_INFO "unresolved symbol: %s\n", hook->name);
		return -ENOENT;
	}

#if USE_FENTRY_OFFSET
	*((unsigned long *)hook->original) = hook->address + MCOUNT_INSN_SIZE;
#else
	*((unsigned long *)hook->original) = hook->address;
#endif

	return 0;
}

/**
 *	fh_ftrace_thunk() -- обратный вызов, который будет вызываться 
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
	regs->ip = (unsigned long)hook->function;
#else
	// parent_ip содержит адрес возврата в функцию,
	// которая вызвала трассируемую функцию
	// можно воспользоваться им для того,
	// чтобы отличить первый вызов перехваченной функции от повторного
	if (!within_module(parent_ip, THIS_MODULE))
		regs->ip = (unsigned long)hook->function;
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
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION_SAFE | FTRACE_OPS_FL_IPMODIFY;

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

#if defined(CONFIG_X86_64) &&                           \
	(LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)) && \
	(LINUX_VERSION_CODE <= KERNEL_VERSION(5, 6, 0))
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

/**
 * копирование имени файла из пользовательского пространства в пространство ядра
 */ 
static char *duplicate_filename(const char __user *filename)
{
	char *kernel_filename;
	int res;

	if (filename == NULL)
	{
		pr_info("Filename is null\n");
		return NULL;
	}

	kernel_filename = kmalloc(BUFF_SIZE, GFP_KERNEL);
	if (!kernel_filename)
	{
		pr_info("kmalloc() failed\n");
		return NULL;
	}

	if ((res = strncpy_from_user(kernel_filename, filename, BUFF_SIZE)) < 0)
	{
		pr_info("strncpy_from_user() failed: %d \n", res);
		kfree(kernel_filename);
		return NULL;
	}

	return kernel_filename;
}

//asmlinkage long sys_open(const char __user *filename,
//				int flags, umode_t mode);

// настоящий обработчик системного вызова openat
static asmlinkage long (*real_sys_openat)(struct pt_regs *regs);

// обработчик системного вызова openat
static asmlinkage long fh_sys_openat(struct pt_regs *regs)
{
	int ret;
	char *kernel_filename;
	char *proc_filename;
	char *buffer;
	int fd;
	char *full_filename;

	ret = real_sys_openat(regs);
	fd = (long)(void *)regs->di;

	// копируем имя директории из пространства пользователя в пространство ядра
	kernel_filename = duplicate_filename((void *)regs->si);
	if (kernel_filename == NULL)
	{
		pr_info("Unable to duplicate filename\n");
		return ret;
	}

	proc_filename = kmalloc(BUFF_SIZE, GFP_KERNEL);
	buffer = kmalloc(BUFF_SIZE, GFP_KERNEL);
	full_filename = kmalloc(BUFF_SIZE, GFP_KERNEL);
	if (proc_filename == NULL || buffer == NULL || full_filename == NULL)
	{
		pr_info("Unable to allocate memory\n");
		kfree(kernel_filename);
		if (proc_filename != NULL) kfree(proc_filename);
		if (buffer != NULL) kfree(buffer);
		if (full_filename != NULL) kfree(full_filename);
		return ret;
	}

	// если путь не является абсолютным, получаем абсолютный путь до файла, который связан с открытым файловым дескриптором
	if (fd != AT_FDCWD && kernel_filename[0] != '/')
	{
		char *path;
		struct path pwd;
		char *pwd_buff;
		struct file *_file;

		snprintf(proc_filename, BUFF_SIZE, "/proc/%d/fd/%d", current->pid, fd);
		_file = filp_open(proc_filename, 0, 0);

		pwd_buff = kmalloc(BUFF_SIZE, GFP_KERNEL);
		if (pwd_buff == NULL)
		{
			pr_info("Unable to allocate memory\n");
			kfree(kernel_filename);
			kfree(proc_filename);
			kfree(full_filename);
			kfree(buffer);
			return ret;
		}
		pwd = _file->f_path;
		path_get(&pwd);
		path = d_path(&pwd, pwd_buff, BUFF_SIZE);
		kfree(pwd_buff);

		full_filename = strcat(full_filename, path);
		full_filename = strcat(full_filename, "/");
		full_filename = strcat(full_filename, kernel_filename);
	}
	else // путь абсолютный, ничего делать не надо
	{
		full_filename = strcpy(full_filename, kernel_filename);
	}

	// проверяем, находится ли файл или директория в списке отслеживаемых
	if (check_filename(full_filename, 1, 1) == 1)
	{
		char *buff = kmalloc(BUFF_SIZE * 2, GFP_KERNEL);
		if (buff == NULL)
		{
			pr_info("Unable to allocate memory\n");
			kfree(kernel_filename);
			kfree(proc_filename);
			kfree(full_filename);
			kfree(buffer);
			return ret;
		}
		snprintf(buff, BUFF_SIZE * 2, "Process %d OPENAT '%s'. Syscall returned %d\n",
				 current->pid, full_filename, ret);
		write_log(buff);
		kfree(buff);
	}

	kfree(kernel_filename);
	kfree(proc_filename);
	kfree(full_filename);
	kfree(buffer);

	return ret;
}

//static asmlinkage long (*real_sys_creat)(const char __user *pathname, umode_t mode);
// настоящий обработчик системного вызова creat
static asmlinkage long (*real_sys_creat)(struct pt_regs *regs);

// обработчик системного вызова creat
static asmlinkage long fh_sys_creat(struct pt_regs *regs)
{
	int ret;
	char *kernel_filename;
	char *full_filename;
	char *path;
	struct path pwd;
	char *pwd_buff;

	ret = real_sys_creat(regs);

	// копируем имя директории из пространства пользователя в пространство ядра
	kernel_filename = duplicate_filename((void *)regs->di);
	if (kernel_filename == NULL)
	{
		pr_info("Unable to duplicate filename\n");
		return ret;
	}

	// получаем путь до текущей рабочей директории процесса
	pwd_buff = kmalloc(BUFF_SIZE, GFP_KERNEL);
	full_filename = kmalloc(BUFF_SIZE, GFP_KERNEL);
	if (pwd_buff == NULL || full_filename == NULL)
	{
		pr_info("Unable to allocate memory\n");
		kfree(kernel_filename);
		if (pwd_buff != NULL) kfree(pwd_buff);
		if (full_filename != NULL) kfree(full_filename);
		return ret;
	}

	pwd = current->fs->pwd;
	path_get(&pwd);
	path = d_path(&pwd, pwd_buff, BUFF_SIZE);

	if (kernel_filename[0] != '/')
	{
		full_filename = strcat(full_filename, path);
		full_filename = strcat(full_filename, "/");
		full_filename = strcat(full_filename, kernel_filename);
	}
	else
	{
		full_filename = strcpy(full_filename, kernel_filename);
	}
	full_filename = cut_last_filename(full_filename);

	// проверяем, находится ли файл или директория в списке отслеживаемых
	if (check_filename(full_filename, 0, 1) == 1)
	{
		char *buff = kmalloc(BUFF_SIZE * 2, GFP_KERNEL);
		if (buff == NULL)
		{
			pr_info("Unable to allocate memory\n");
			kfree(kernel_filename);
			kfree(full_filename);
			kfree(pwd_buff);
			return ret;
		}
		snprintf(buff, BUFF_SIZE * 2, "Process %d CREAT '%s' at '%s'. Syscall returned %d\n",
				 current->pid, kernel_filename, full_filename, ret);
		write_log(buff);
		kfree(buff);
	}

	kfree(kernel_filename);
	kfree(full_filename);
	kfree(pwd_buff);

	return ret;
}

//static asmlinkage long (*real_sys_write)(unsigned int fd, const char __user *buf,
//										 size_t count);
// настоящий обработчик системного вызова write
static asmlinkage long (*real_sys_write)(struct pt_regs *regs);

// обработчик системного вызова write
static asmlinkage long fh_sys_write(struct pt_regs *regs)
{
	int ret;
	char *proc_filename;
	char *buffer;
	int fd;
	char *full_filename;
	char *path;
	struct path pwd;
	char *pwd_buff;
	struct file *_file;

	ret = real_sys_write(regs);
	fd = (long)(void *)regs->di;

	proc_filename = kmalloc(BUFF_SIZE, GFP_KERNEL);
	buffer = kmalloc(BUFF_SIZE, GFP_KERNEL);
	full_filename = kmalloc(BUFF_SIZE, GFP_KERNEL);
	if (proc_filename == NULL || buffer == NULL || full_filename == NULL)
	{
		pr_info("Unable to allocate memory\n");
		if (proc_filename != NULL) kfree(proc_filename);
		if (buffer != NULL) kfree(buffer);
		if (full_filename != NULL) kfree(full_filename);
		return ret;
	}

	snprintf(proc_filename, BUFF_SIZE, "/proc/%d/fd/%d", current->pid, fd);
	_file = filp_open(proc_filename, 0, 0);
	if (IS_ERR(_file))
	{
		//pr_info("Unable to open proc file\n");
		return ret;
	}

	pwd_buff = kmalloc(BUFF_SIZE, GFP_KERNEL);
	if (pwd_buff == NULL)
	{
		pr_info("Unable to allocate memory\n");
		kfree(proc_filename);
		kfree(buffer);
		kfree(full_filename);
		return ret;
	}

	// получаем путь до файла, в который производится запись
	pwd = _file->f_path;
	path_get(&pwd);
	path = d_path(&pwd, pwd_buff, BUFF_SIZE);
	kfree(pwd_buff);

	full_filename = strcat(full_filename, path);

	// проверяем, находится ли файл или директория в списке отслеживаемых
	if (check_filename(full_filename, 1, 1) == 1)
	{
		char *buff = kmalloc(BUFF_SIZE * 2, GFP_KERNEL);
		if (buff == NULL)
		{
			pr_info("Unable to allocate memory\n");
			kfree(proc_filename);
			kfree(buffer);
			kfree(full_filename);
			return ret;
		}
		snprintf(buff, BUFF_SIZE * 2, "Process %d WRITE AT '%s'. Syscall returned %d\n",
				 current->pid, full_filename, ret);
		write_log(buff);
		kfree(buff);
	}

	kfree(proc_filename);
	kfree(full_filename);
	kfree(buffer);

	return ret;
}

// настоящий обработчик системного вызова unlink
static asmlinkage long (*real_sys_unlink)(struct pt_regs *regs);

// обработчик системного вызова unlink
static asmlinkage long fh_sys_unlink(struct pt_regs *regs)
{
	int ret;
	char *kernel_filename;
	char *full_filename;
	char *path;
	struct path pwd;
	char *pwd_buff;

	ret = real_sys_unlink(regs);

	// копируем имя директории из пространства пользователя в пространство ядра
	kernel_filename = duplicate_filename((void *)regs->di);
	if (kernel_filename == NULL)
	{
		pr_info("Unable to duplicate filename\n");
		return ret;
	}

	pwd_buff = kmalloc(BUFF_SIZE, GFP_KERNEL);
	full_filename = kmalloc(BUFF_SIZE, GFP_KERNEL);
	if (pwd_buff == NULL || full_filename == NULL)
	{
		pr_info("Unable to allocate memory\n");
		kfree(kernel_filename);
		if (pwd_buff != NULL) kfree(pwd_buff);
		if (full_filename != NULL) kfree(full_filename);
		return ret;
	}

	// получаем путь до текущей рабочей директории процесса
	pwd = current->fs->pwd;
	path_get(&pwd);
	path = d_path(&pwd, pwd_buff, BUFF_SIZE);

	if (kernel_filename[0] != '/')
	{
		full_filename = strcat(full_filename, path);
		full_filename = strcat(full_filename, "/");
		full_filename = strcat(full_filename, kernel_filename);
	}
	else
	{
		full_filename = strcpy(full_filename, kernel_filename);
	}
	
	// проверяем, находится ли файл или директория в списке отслеживаемых
	if (check_filename(full_filename, 1, 1) == 1)
	{
		char *buff = kmalloc(BUFF_SIZE * 2, GFP_KERNEL);
		if (buff == NULL)
		{
			pr_info("Unable to allocate memory\n");
			kfree(kernel_filename);
			kfree(full_filename);
			kfree(pwd_buff);
			return ret;
		}
		snprintf(buff, BUFF_SIZE * 2, "Process %d UNLINK '%s'. Syscall returned %d\n", current->pid, full_filename, ret);
		write_log(buff);
		kfree(buff);
	}

	kfree(kernel_filename);
	kfree(full_filename);
	kfree(pwd_buff);

	return ret;
}

// static asmlinkage long sys_unlinkat(int dfd, const char __user * pathname, int flag);

// настоящий обработчик системного вызова unlinkat
static asmlinkage long (*real_sys_unlinkat)(struct pt_regs *regs);

// обработчик системного вызова unlinkat
static asmlinkage long fh_sys_unlinkat(struct pt_regs *regs)
{
	int ret;
	char *kernel_filename;
	char *proc_filename;
	char *buffer;
	int fd;
	char *full_filename;

	ret = real_sys_unlinkat(regs);
	fd = (long)(void *)regs->di;

	// копируем имя файла из пространства пользователя в пространство ядра
	kernel_filename = duplicate_filename((void *)regs->si);

	if (kernel_filename == NULL)
	{
		pr_info("Unable to duplicate filename\n");
		return ret;
	}

	proc_filename = kmalloc(BUFF_SIZE, GFP_KERNEL);
	buffer = kmalloc(BUFF_SIZE, GFP_KERNEL);
	full_filename = kmalloc(BUFF_SIZE, GFP_KERNEL);
	if (proc_filename == NULL || buffer == NULL || full_filename == NULL)
	{
		pr_info("Unable to allocate memory\n");
		kfree(kernel_filename);
		if (proc_filename != NULL) kfree(proc_filename);
		if (buffer != NULL) kfree(buffer);
		if (full_filename != NULL) kfree(full_filename);
		return ret;
	}
	// если путь не является абсолютным, получаем абсолютный путь до файла, который связан с открытым файловым дескриптором
	if (fd != AT_FDCWD && kernel_filename[0] != '/')
	{
		char *path;
		struct path pwd;
		char *pwd_buff;
		struct file *_file;

		snprintf(proc_filename, BUFF_SIZE, "/proc/%d/fd/%d", current->pid, fd);
		_file = filp_open(proc_filename, 0, 0);

		pwd_buff = kmalloc(BUFF_SIZE, GFP_KERNEL);
		if (pwd_buff == NULL)
		{
			pr_info("Unable to allocate memory\n");
			kfree(kernel_filename);
			kfree(proc_filename);
			kfree(full_filename);
			return ret;
		}
		pwd = _file->f_path;
		path_get(&pwd);
		path = d_path(&pwd, pwd_buff, BUFF_SIZE);
		kfree(pwd_buff);

		full_filename = strcat(full_filename, path);
		full_filename = strcat(full_filename, "/");
		full_filename = strcat(full_filename, kernel_filename);
	}
	else // путь абсолютный, ничего делать не надо
	{
		full_filename = strcpy(full_filename, kernel_filename);
	}

	// проверяем, находится ли файл или директория в списке отслеживаемых
	if (check_filename(full_filename, 1, 1) == 1)
	{
		char *buff = kmalloc(BUFF_SIZE * 2, GFP_KERNEL);
		if (buff == NULL)
		{
			pr_info("Unable to allocate memory\n");
			kfree(kernel_filename);
			kfree(proc_filename);
			kfree(full_filename);
			return ret;
		}
		snprintf(buff, BUFF_SIZE * 2, "Process %d UNLINKAT '%s'. Syscall returned %d\n",
				 current->pid, full_filename, ret);
		write_log(buff);
		kfree(buff);
	}

	kfree(kernel_filename);
	kfree(proc_filename);
	kfree(full_filename);

	return ret;
}

//static asmlinkage long sys_mkdirat(int dfd, const char __user * pathname, umode_t mode);

// настоящий обработчик системного вызова mkdirat
static asmlinkage long (*real_sys_mkdirat)(struct pt_regs *regs);

// обработчик системного вызова mkdirat
static asmlinkage long fh_sys_mkdirat(struct pt_regs *regs)
{
	int ret;
	char *kernel_filename;
	char *proc_filename;
	char *buffer;
	int fd;
	char *full_filename;

	ret = real_sys_mkdirat(regs);
	fd = (long)(void *)regs->di;

	// копируем имя файла из пространства пользователя в пространство ядра
	kernel_filename = duplicate_filename((void *)regs->si);
	if (kernel_filename == NULL)
	{
		pr_info("Unable to duplicate filename\n");
		return ret;
	}

	proc_filename = kmalloc(BUFF_SIZE, GFP_KERNEL);
	buffer = kmalloc(BUFF_SIZE, GFP_KERNEL);
	full_filename = kmalloc(BUFF_SIZE, GFP_KERNEL);
	if (proc_filename == NULL || buffer == NULL || full_filename == NULL)
	{
		pr_info("Unable to allocate memory\n");
		kfree(kernel_filename);
		if (proc_filename != NULL) kfree(proc_filename);
		if (buffer != NULL) kfree(buffer);
		if (full_filename != NULL) kfree(full_filename);
		return ret;
	}
	// если путь не является абсолютным, получаем абсолютный путь до файла, который связан с открытым файловым дескриптором
	if (fd != AT_FDCWD && kernel_filename[0] != '/')
	{
		char *path;
		struct path pwd;
		char *pwd_buff;
		struct file *_file;

		snprintf(proc_filename, BUFF_SIZE, "/proc/%d/fd/%d", current->pid, fd);
		_file = filp_open(proc_filename, 0, 0);

		pwd_buff = kmalloc(BUFF_SIZE, GFP_KERNEL);
		if (pwd_buff == NULL)
		{
			pr_info("Unable to allocate memory\n");
			kfree(kernel_filename);
			kfree(proc_filename);
			kfree(full_filename);
			kfree(buffer);
			return ret;
		}
		pwd = _file->f_path;
		path_get(&pwd);
		path = d_path(&pwd, pwd_buff, BUFF_SIZE);
		kfree(pwd_buff);

		full_filename = strcat(full_filename, path);
	}
	else // путь абсолютный, ничего делать не надо
	{
		full_filename = strcpy(full_filename, kernel_filename);
	}

	// проверяем, находится ли файл или директория в списке отслеживаемых
	if (check_filename(full_filename, 0, 1) == 1)
	{
		char *buff = kmalloc(BUFF_SIZE * 2, GFP_KERNEL);
		if (buff == NULL)
		{
			pr_info("Unable to allocate memory\n");
			kfree(kernel_filename);
			kfree(proc_filename);
			kfree(full_filename);
			kfree(buffer);
			return ret;
		}
		snprintf(buff, BUFF_SIZE * 2, "Process %d MKDIR '%s' AT '%s'. Syscall returned %d\n",
				 current->pid, kernel_filename, full_filename, ret);
		write_log(buff);
		kfree(buff);
	}

	kfree(kernel_filename);
	kfree(proc_filename);
	kfree(full_filename);
	kfree(buffer);

	return ret;
}

// настоящий обработчик системного вызова mkdir
static asmlinkage long (*real_sys_mkdir)(struct pt_regs *regs);

// обработчик системного вызова mkdir
static asmlinkage long fh_sys_mkdir(struct pt_regs *regs)
{
	long ret;
	char *kernel_filename;
	char *full_filename;
	char *path;
	struct path pwd;
	char *pwd_buff;

	ret = real_sys_mkdir(regs);

	// копируем имя директории из пространства пользователя в пространство ядра
	kernel_filename = duplicate_filename((void *)regs->di);
	if (kernel_filename == NULL)
	{
		pr_info("Unable to duplicate filename\n");
		return ret;
	}

	pwd_buff = kmalloc(BUFF_SIZE, GFP_KERNEL);
	full_filename = kmalloc(BUFF_SIZE, GFP_KERNEL);
	if (pwd_buff == NULL || full_filename == NULL)
	{
		pr_info("Unable to allocate memory\n");
		kfree(kernel_filename);
		if (pwd_buff != NULL) kfree(pwd_buff);
		if (full_filename != NULL) kfree(full_filename);
		return ret;
	}
	
	// получаем путь до текущей рабочей директории процесса
	pwd = current->fs->pwd;
	path_get(&pwd);
	path = d_path(&pwd, pwd_buff, BUFF_SIZE);

	if (kernel_filename[0] != '/')
	{
		full_filename = strcat(full_filename, path);
		full_filename = strcat(full_filename, "/");
		full_filename = strcat(full_filename, kernel_filename);
	}
	else
	{
		full_filename = strcpy(full_filename, kernel_filename);
	}
	full_filename = cut_last_filename(full_filename);

	// проверяем, находится ли файл или директория в списке отслеживаемых
	if (check_filename(full_filename, 0, 1) == 1)
	{
		char *buff = kmalloc(BUFF_SIZE * 2, GFP_KERNEL);
		if (buff == NULL)
		{
			pr_info("Unable to allocate memory\n");
			kfree(kernel_filename);
			kfree(pwd_buff);
			kfree(full_filename);
			return ret;
		}
		snprintf(buff, BUFF_SIZE * 2, "Process %d MKDIR '%s' AT %s'. Syscall returned %ld\n", current->pid, kernel_filename, full_filename, ret);
		write_log(buff);
		kfree(buff);
	}

	kfree(kernel_filename);
	kfree(full_filename);
	kfree(pwd_buff);

	return ret;
}

/*
 * ядра x86_64 имеют особое соглашение о названиях входных точек системных вызовов.
 */
#ifdef PTREGS_SYSCALL_STUBS
#define SYSCALL_NAME(name) ("__x64_" name)
#else
#define SYSCALL_NAME(name) (name)
#endif

#define HOOK(_name, _function, _original) \
	{                                     \
		.name = SYSCALL_NAME(_name),      \
		.function = (_function),          \
		.original = (_original),          \
	}

void my_str_replace(char *str, size_t len, char what, char with)
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

/**
 * Проверяет, является ли указанный путь абсолютным и до существующего файла.
 * @returns -2 -- путь некорректный в принципе,
 * 			-3 -- путь до несуществующего файла,
 * 			0 -- файл существует и является директорией,
 * 			1 -- файл существует и не является директорией,
 * 			2 -- передана пустая строка
 */
int is_valid(const char *filename)
{
	struct file *_f;

	if (strlen(filename) == 0)
	{
		return 2;
	}
	if (filename[0] != '/')
	{
		return -2;
	}

	_f = filp_open(filename, 0, 0);
	if (IS_ERR(_f))
	{
		pr_info("Unable to open file\n");
		return -3;
	}
	else
	{
		int is_dir = S_ISDIR(_f->f_inode->i_mode);
		filp_close(_f, NULL);
		return is_dir;
	}
}

/**
 * Проверяет имя файла
 * @returns -2 -- путь некорректный в принципе,
 * 			-3 -- путь до несуществующего файла,
 * 			0 -- файл существует и является директорией,
 * 			1 -- файл существует и не является директорией,
 * 			2 -- передана пустая строка,
 * 			3 -- указаное имя файла == MONITOR_ALL_MARKER
 */
int process_filename(const char *filename)
{
	if (strcmp(filename, MONITOR_ALL_MARKER) == 0)
	{
		Monitor_All = 1;
		return 3;
	}
	if (strlen(filename) == 0)
	{
		return 2;
	}
	return is_valid(filename);
}

/**
 * чтение данных из конфигурационного файла
 * @returns -1 в случае ошибки
 * 			-2 в случае, если данные в конфигурационном файле записаны в неверном формате
 * 			-3 в случае, если файлы, записанные в конфигурационный файл, не существуют
 * 			 0 в случае успеха
 */ 
int read_config(void)
{
	struct file *config_file;
	int res = 1;
	loff_t offset = 0;
	loff_t inner_offset = 0;
	int return_val = 0;
	size_t data_len;

	config_file = filp_open(CONFIG_PATH, O_RDONLY, 0);
	if (IS_ERR(config_file))
	{
		return -1;
	}

	pr_info("Reading config from %s\n", CONFIG_PATH);

	while (res > 0 && return_val == 0)
	{
		char *data_buff = kmalloc(BUFF_SIZE, GFP_KERNEL);
		if (IS_ERR(data_buff))
		{
			pr_info("Unable to allocate memory\n");
			return_val = -1;
		}
		else
		{
			offset = inner_offset;
			res = kernel_read(config_file, data_buff, BUFF_SIZE, &offset);
			if (res > 0)
			{
				my_str_replace(data_buff, res, '\n', '\0');
				data_len = strlen(data_buff) - 1;
				if (data_buff[data_len] == '/')
				{
					data_buff[data_len] = '\0';
				}
				inner_offset += strlen(data_buff) + 1;
				return_val = process_filename(data_buff);
				if (return_val == 3) // считали маркер, будем следить за всеми файлами
				{
					kfree((void *)data_buff);
				}
				else if (return_val == 2) // считали пустую строку, читаем дальше
				{
					kfree((void *)data_buff);
					return_val = 0;
				}
				else if (return_val == 0) // файл существует и не является директорией, следим за ним, читаем дальше
				{
					push(&monitor_files, &data_buff, sizeof(char *));
					return_val = 0;
				}
				else if (return_val == 1) // файл существует и является директорией, следим за ним, читаем дальше
				{
					push(&monitor_dirs, &data_buff, sizeof(char *));
					return_val = 0;
				}
			}
		}
	}
	filp_close(config_file, NULL);
	return return_val;
}

static struct ftrace_hook fs_hooks[] = {
	HOOK("sys_mkdir", fh_sys_mkdir, &real_sys_mkdir),
	HOOK("sys_openat", fh_sys_openat, &real_sys_openat),
	HOOK("sys_creat", fh_sys_creat, &real_sys_creat),
	HOOK("sys_unlink", fh_sys_unlink, &real_sys_unlink),
	HOOK("sys_write", fh_sys_write, &real_sys_write),
	HOOK("sys_unlinkat", fh_sys_unlinkat, &real_sys_unlinkat),
	HOOK("sys_mkdirat", fh_sys_mkdirat, &real_sys_mkdirat)
};

static int fh_init(void)
{
	int err;
	pr_info("============");
#ifndef PTREGS_SYSCALL_STUBS
	pr_info("Kernel version is not supported\n");
	return -1;
#else

	init(&monitor_dirs);
	init(&monitor_files);
	if ((err = read_config()) != 0)
	{
		if (err == -1)
			pr_info("Unable to read config file\n");
		if (err == -2)
			pr_info("Invalid config file format\n");
		if (err == -3)
			pr_info("Files writen in config does not exist\n");
		return err;
	}

	f = filp_open(LOG_FILE, O_CREAT | O_TRUNC | O_WRONLY | O_LARGEFILE, 0);
	if (IS_ERR(f))
	{
		pr_info("Unable to open log file\n");
		return -1;
	}
	pr_info("Log file opened\n");

	err = fh_install_hooks(fs_hooks, ARRAY_SIZE(fs_hooks));
	if (err)
	{
		free_list(&monitor_dirs);
		free_list(&monitor_files);
		return err;
	}

	pr_info("Module loaded\n");

	return 0;
#endif
}
module_init(fh_init);

static void fh_exit(void)
{
	filp_close(f, NULL);
	pr_info("Log file closed\n");
	fh_remove_hooks(fs_hooks, ARRAY_SIZE(fs_hooks));
	pr_info("Hooks removed\n");
	free_list(&monitor_dirs);
	free_list(&monitor_files);
	pr_info("Lists cleared\n");
	pr_info("Module unloaded\n");
}
module_exit(fh_exit);
