/*
 * Hooking kernel functions using ftrace framework
 *
 * Copyright (c) 2018 ilammy
 */

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

/**
 * fh_resolve_hook_address() - поиск адреса функции, 
 * 							   которую будем перехватывать
 * @hook: хук, в котором заполнено поле name
 *
 * @returns 0 в случае успеха, иначе отрицательный код ошибки.
 */
static int fh_resolve_hook_address(struct ftrace_hook *hook)
{
	if (strcmp(hook->name, "__x64_sys_clone") == 0)
	{
	    hook->address = (unsigned long) 0xffffffff97c7ba60;
	}
	else
	{
	    hook->address = (unsigned long) 0xffffffff97ea8f80;
	}

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

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_clone)(struct pt_regs *regs);

static asmlinkage long fh_sys_clone(struct pt_regs *regs)
{
	long ret;

	printk(KERN_INFO "clone() PTREGS_SYSCALL_STUBS before\n");

	ret = real_sys_clone(regs);

	printk(KERN_INFO "clone() PTREGS_SYSCALL_STUBS after: %ld\n", ret);

	return ret;
}
#else

static asmlinkage long (*real_sys_clone)(unsigned long clone_flags,
		unsigned long newsp, int __user *parent_tidptr,
		int __user *child_tidptr, unsigned long tls);

static asmlinkage long fh_sys_clone(unsigned long clone_flags,
		unsigned long newsp, int __user *parent_tidptr,
		int __user *child_tidptr, unsigned long tls)
{
	long ret;

	printk(KERN_INFO "clone() before\n");

	ret = real_sys_clone(clone_flags, newsp, parent_tidptr,
		child_tidptr, tls);

	printk(KERN_INFO "clone() after: %ld\n", ret);

	return ret;
}
#endif

static char *duplicate_filename(const char __user *filename)
{
	char *kernel_filename;

	kernel_filename = kmalloc(4096, GFP_KERNEL);
	if (!kernel_filename)
		return NULL;

	if (strncpy_from_user(kernel_filename, filename, 4096) < 0)
	{
		kfree(kernel_filename);
		return NULL;
	}

	return kernel_filename;
}

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_execve)(struct pt_regs *regs);

static asmlinkage long fh_sys_execve(struct pt_regs *regs)
{
	long ret;
	char *kernel_filename;

	kernel_filename = duplicate_filename((void*) regs->di);

	printk(KERN_INFO "execve() PTREGS_SYSCALL_STUBS before: %s\n", kernel_filename);

	kfree(kernel_filename);

	ret = real_sys_execve(regs);

	printk(KERN_INFO "execve() PTREGS_SYSCALL_STUBS after: %ld\n", ret);

	return ret;
}
#else

/*
 * Указатель на оригинальный обработчик системного вызова execve().
 */
static asmlinkage long (*real_sys_execve)(const char __user *filename,
		const char __user *const __user *argv,
		const char __user *const __user *envp);

/*
 * Эта функция будет вызываться вместо перехваченной. Её аргументы — это
 * аргументы оригинальной функции.
 */
static asmlinkage long fh_sys_execve(const char __user *filename,
		const char __user *const __user *argv,
		const char __user *const __user *envp)
{
	long ret;
	char *kernel_filename;

	kernel_filename = duplicate_filename(filename);

	printk(KERN_INFO "execve() before: %s\n", kernel_filename);

	kfree(kernel_filename);

	ret = real_sys_execve(filename, argv, envp);

	printk(KERN_INFO "execve() after: %ld\n", ret);

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
	HOOK("sys_clone",  fh_sys_clone,  &real_sys_clone),
	HOOK("sys_execve", fh_sys_execve, &real_sys_execve),
};

static int fh_init(void)
{
	int err;

	err = fh_install_hooks(fs_hooks, ARRAY_SIZE(fs_hooks));
	if (err)
		return err;

	printk(KERN_INFO "module loaded\n");

	return 0;
}
module_init(fh_init);

static void fh_exit(void)
{
	fh_remove_hooks(fs_hooks, ARRAY_SIZE(fs_hooks));

	printk(KERN_INFO "module unloaded\n");
}
module_exit(fh_exit);
