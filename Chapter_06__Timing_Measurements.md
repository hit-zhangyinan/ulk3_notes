# 第 6 章 定时测量

定时测量是由基于固定频率振荡器和计数器的几个硬件电路完成的

## 时钟和定时器电路

### Real Time Clock (RTC)

所有 PC 都包含一个名叫 RTC 的时钟，它独立于 CPU 和所有其他芯片

### Time Stamp Counter (TSC)

算出 CPU 实际频率的任务是在系统初始化期间完成的

```c
// file: arch/x86/include/asm/x86_init.h

struct x86_platform_ops {
	unsigned long (*calibrate_cpu)(void);
	unsigned long (*calibrate_tsc)(void);
    ...
};

// file: arch/x86/kernel/x86_init.c
struct x86_platform_ops x86_platform __ro_after_init = {
	.calibrate_cpu			= native_calibrate_cpu_early,
	.calibrate_tsc			= native_calibrate_tsc,
    ...
};

// file: arch/x86/kernel/tsc.c
/**
 * native_calibrate_tsc - determine TSC frequency
 * Determine TSC frequency via CPUID, else return 0.
 */
unsigned long native_calibrate_tsc(void) { }
```

### Programmable Interval Timer (PIT)

```c
// file: arch/x86/include/asm/timex.h
/* Assume we use the PIT time source for the clock tick */
#define CLOCK_TICK_RATE		PIT_TICK_RATE

// file: include/linux/timex.h
/* The clock frequency of the i8253/i8254 PIT */
#define PIT_TICK_RATE 1193182ul
```

### CPU Local Timer

### High Precision Event Timer (HPET)

HPET 是由 Intel 和 Microsoft 联合开发的新型定时器芯片

### ACPI Power Management Timer

ACPI (Advanced Configuration and Power Interface) is a

Power Management and configuration standard for the PC,

developed by Intel, Microsoft and Toshiba.

可查看 ACPI Specification 的第 3 章 "ACPI CONCEPTS" 部分

[ACPI Specification](https://uefi.org/specifications)

如果系统中存在 HPET 设备，那么比起其他电路而言它总是首选，因为它更复杂的结构使得功能更强

## Linux 计时体系结构

### Data Structures of the Timekeeping Architecture

```c
// file: kernel/time/jiffies.c

#if (BITS_PER_LONG < 64)
u64 get_jiffies_64(void)
{
	unsigned int seq;
	u64 ret;

	do {
		seq = read_seqcount_begin(&jiffies_seq);
		ret = jiffies_64;
	} while (read_seqcount_retry(&jiffies_seq, seq));
	return ret;
}
EXPORT_SYMBOL(get_jiffies_64);
#endif

// file: include/linux/jiffies.h
#if (BITS_PER_LONG < 64)
u64 get_jiffies_64(void);
#else
/**
 * get_jiffies_64 - read the 64-bit non-atomic jiffies_64 value
 *
 * When BITS_PER_LONG < 64, this uses sequence number sampling using
 * jiffies_lock to protect the 64-bit read.
 *
 * Return: current 64-bit jiffies value
 */
static inline u64 get_jiffies_64(void)
{
	return (u64)jiffies;
}
#endif
```

### 单处理器系统上的计时体系结构

在内核初始化期间，time_init() 函数用来建立计时体系结构

```c
/*
 * Initialize TSC and delay the periodic timer init to
 * late x86_late_time_init() so ioremap works.
 */
void __init time_init(void)
{
	late_time_init = x86_late_time_init;
}

/* Default timer init function */
void __init hpet_time_init(void)
{
	if (!hpet_enable()) {
		if (!pit_timer_init())
			return;
	}

	setup_default_timer_irq();
}

static __init void x86_late_time_init(void)
{
	/*
	 * Before PIT/HPET init, select the interrupt mode. This is required
	 * to make the decision whether PIT should be initialized correct.
	 */
	x86_init.irqs.intr_mode_select();

	/* Setup the legacy timers */
	x86_init.timers.timer_init();

	/*
	 * After PIT/HPET timers init, set up the final interrupt mode for
	 * delivering IRQs.
	 */
	x86_init.irqs.intr_mode_init();
	tsc_init();

	if (static_cpu_has(X86_FEATURE_WAITPKG))
		use_tpause_delay();
}
```

```c
// file: arch/x86/kernel/hpet.c

/**
 * hpet_enable - Try to setup the HPET timer. Returns 1 on success.
 */
int __init hpet_enable(void) { }
```

#### 时钟中断处理程序

timer_interrupt() 函数是 PIT 或 HPET 的中断服务例程 (ISR)

```c
// file: arch/x86/kernel/time.c

/*
 * Default timer interrupt handler for PIT/HPET
 */
static irqreturn_t timer_interrupt(int irq, void *dev_id)
{
	global_clock_event->event_handler(global_clock_event);
	return IRQ_HANDLED;
}

static void __init setup_default_timer_irq(void)
{
	unsigned long flags = IRQF_NOBALANCING | IRQF_IRQPOLL | IRQF_TIMER;

	/*
	 * Unconditionally register the legacy timer interrupt; even
	 * without legacy PIC/PIT we need this for the HPET0 in legacy
	 * replacement mode.
	 */
	if (request_irq(0, timer_interrupt, flags, "timer", NULL))
		pr_info("Failed to register legacy timer interrupt\n");
}
```

## Updating System Statistics

### 更新本地 CPU 统计数

```c
// file: kernel/time/timer.c

void update_process_times(int user_tick)
{
	struct task_struct *p = current;

	/* Note: this timer irq context must be accounted for as well. */
	account_process_tick(p, user_tick);
	run_local_timers();
	rcu_sched_clock_irq(user_tick);
#ifdef CONFIG_IRQ_WORK
	if (in_irq())
		irq_work_tick();
#endif
	sched_tick();
	if (IS_ENABLED(CONFIG_POSIX_TIMERS))
		run_posix_cpu_timers();
}
```

### 记录系统负载

```c
// file: include/linux/sched/loadavg.h

static inline unsigned long
calc_load(unsigned long load, unsigned long exp, unsigned long active)
{
	unsigned long newload;

	newload = load * exp + active * (FIXED_1 - exp);
	if (active >= load)
		newload += FIXED_1-1;

	return newload / FIXED_1;
}
```

### Profiling the Kernel Code

Linux 用 profiler 来发现内核在内核态的什么地方花费时间，确定执行最频繁的内核代码片段

profile_tick() 函数为 profiler 采集数据

```c
// file: kernel/profile.c

void profile_tick(int type)
{
	struct pt_regs *regs = get_irq_regs();

	/* This is the old kernel-only legacy profiling */
	if (!user_mode(regs))
		profile_hit(type, (void *)profile_pc(regs));
}
```

### Checking the NMI Watchdogs

A Non-Maskable Interrupt (NMI) in computer science refers to

an interrupt mechanism with the highest priority that

cannot be disabled by the programmer.

It is typically used to handle critical events like imminent power loss.

一旦每个时钟节拍到来，所有的 CPU，不管其正在做什么，都开始执行 NMI 中断处理程序

当 NMI 中断处理程序检测到一个 CPU 冻结时，它就会 dump 该 CPU 寄存器的内容和内核栈的内容

最后杀死当前进程，为内核开发者提供发现错误的机会

## 软定时器和延迟函数

### 动态定时器

动态定时器存放在 timer_list 结构中：

```c
// file: include/linux/timer_types.h

struct timer_list {
	/*
	 * All fields that change during normal runtime grouped to the
	 * same cacheline
	 */
	struct hlist_node	entry;
	unsigned long		expires;
	void			(*function)(struct timer_list *);
	u32			flags;

#ifdef CONFIG_LOCKDEP
	struct lockdep_map	lockdep_map;
#endif
};
```

#### 动态定时器与竞争条件

```c
// file: include/linux/timer.h

/**
 * del_timer_sync - Delete a pending timer and wait for a running callback
 * @timer:	The timer to be deleted
 *
 * See timer_delete_sync() for detailed explanation.
 *
 * Do not use in new code. Use timer_delete_sync() instead.
 *
 * Returns:
 * * %0	- The timer was not pending
 * * %1	- The timer was pending and deactivated
 */
static inline int del_timer_sync(struct timer_list *timer)
{
	return timer_delete_sync(timer);
}
```

del_timer_sync() 函数相当复杂，而且执行速度慢，因为它必须考虑定时器重新激活自己的情况

#### 动态定时器处理

```c
// file: kernel/time/timer.c

void __init init_timers(void)
{
	init_timer_cpus();
	posix_cputimers_init_work();
	open_softirq(TIMER_SOFTIRQ, run_timer_softirq);
}
```

run_timer_softirq() 函数是与 TIMER_SOFTIRQ 软中断请求相关的可延迟函数

```c
// file: kernel/time/timer.c

/*
 * This function runs timers and the timer-tq in bottom half context.
 */
static __latent_entropy void run_timer_softirq(struct softirq_action *h)
{
	run_timer_base(BASE_LOCAL);
	if (IS_ENABLED(CONFIG_NO_HZ_COMMON)) {
		run_timer_base(BASE_GLOBAL);
		run_timer_base(BASE_DEF);

		if (is_timers_nohz_active())
			tmigr_handle_remote();
	}
}

static void run_timer_base(int index)
{
	struct timer_base *base = this_cpu_ptr(&timer_bases[index]);

	__run_timer_base(base);
}

struct timer_base {
	raw_spinlock_t		lock;
	struct timer_list	*running_timer;
#ifdef CONFIG_PREEMPT_RT
	spinlock_t		expiry_lock;
	atomic_t		timer_waiters;
#endif
	unsigned long		clk;
	unsigned long		next_expiry;
	unsigned int		cpu;
	bool			next_expiry_recalc;
	bool			is_idle;
	bool			timers_pending;
	DECLARE_BITMAP(pending_map, WHEEL_SIZE);
	struct hlist_head	vectors[WHEEL_SIZE];
} ____cacheline_aligned;

static DEFINE_PER_CPU(struct timer_base, timer_bases[NR_BASES]);
```

#### nanosleep() 系统调用

```c
// file: kernel/time/hrtimer.c
/*
 *  High-resolution kernel timers
 *
 *  In contrast to the low-resolution timeout API, aka timer wheel,
 *  hrtimers provide finer resolution and accuracy depending on system
 *  configuration and capabilities.
*/

#ifdef CONFIG_64BIT

SYSCALL_DEFINE2(nanosleep, struct __kernel_timespec __user *, rqtp,
		struct __kernel_timespec __user *, rmtp)
{
	struct timespec64 tu;

	if (get_timespec64(&tu, rqtp))
		return -EFAULT;

	if (!timespec64_valid(&tu))
		return -EINVAL;

	current->restart_block.fn = do_no_restart_syscall;
	current->restart_block.nanosleep.type = rmtp ? TT_NATIVE : TT_NONE;
	current->restart_block.nanosleep.rmtp = rmtp;
	return hrtimer_nanosleep(timespec64_to_ktime(tu), HRTIMER_MODE_REL,
				 CLOCK_MONOTONIC);
}

#endif
```
