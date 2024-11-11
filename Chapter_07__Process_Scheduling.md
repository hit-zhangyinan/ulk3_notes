# 第 7 章 进程调度

进程调度主要关心什么时候进行进程切换和选择哪一个进程来运行

## 调度策略

在 Linux 中，进程的优先级是动态的。调度程序跟踪进程正在做什么，并周期性地调整它们的优先级

### 进程的抢占

被抢占的进程并没有挂起，因为它还处于 TASK_RUNNING 状态，只不过不再使用 CPU

### 一个时间片应该多长？

时间片的长短对系统性能是很关键的：它既不能太长也不能太短

Linux 采取单凭经验的方法：选择尽可能长、同时能保持良好响应时间的一个时间片

## 调度算法

调度程序总是能成功找到要执行的进程。

事实上，总是至少有一个可运行进程，即 `swapper` 进程，

它的 PID 等于 0，而且它只有在 CPU 不能执行其他进程时才执行。

every CPU of a multiprocessor system has its own swapper process with PID equal to 0

多处理器系统的每个 CPU 都有它自己的 swapper 进程，其 PID 等于 0

```c
// header file: include/uapi/linux/sched.h

/*
 * Scheduling policies
 */
#define SCHED_NORMAL      0
#define SCHED_FIFO        1
#define SCHED_RR          2
#define SCHED_BATCH       3
```

* SCHED_FIFO 是先进先出的实时进程

* SCHED_RR 是时间片轮转的实时进程

* SCHED_NORMAL 是普通的分时进程

关于 SCHED_BATCH 调度策略的介绍：

`SCHED_BATCH` 是 Linux 操作系统中的一种调度策略，专门设计用于批处理任务。批处理任务通常是那些不需要与用户交互的任务，它们可以在系统负载较低时运行，以最大化系统资源利用率。以下是关于 `SCHED_BATCH` 调度策略的一些详细信息：

### 特点

1. **低优先级**：
   - `SCHED_BATCH` 任务的优先级较低，通常在系统空闲时运行。它们不会与交互式任务竞争 CPU 时间，从而避免影响系统的响应速度。

2. **时间片较长**：
   - 由于批处理任务通常不需要频繁的上下文切换，`SCHED_BATCH` 调度策略会为这些任务分配较长的时间片。这有助于减少上下文切换的开销，提高系统的整体效率。

3. **非实时调度**：
   - `SCHED_BATCH` 并不是实时调度策略，因此它不保证任务在特定时间内完成。它适用于那些可以容忍延迟的任务。

### 使用场景

- 长时间运行的计算任务，例如数据分析、科学计算、视频编码等。
- 后台服务和守护进程，这些任务不需要与用户直接交互。
- 批量文件处理任务，例如日志分析、备份等。

调度算法根据进程是普通进程还是实时进程而有很大不同。

### 普通进程的调度

每个普通进程都有它自己的静态优先级，内核用从 100 (最高优先级) 到 139 (最低优先级) 的数

表示普通进程的静态优先级，值越大静态优先级越低

#### 基本时间片

静态优先级本质上决定了进程的基本时间片，静态优先级越高，基本时间片就越长

#### 动态优先级和平均睡眠时间

普通进程除了静态优先级，还有动态优先级，其值的范围是 100 (最高优先级) 到 139 (最低优先级)

动态优先级是调度程序在选择新进程来运行的时候使用的数。

#### 活动和过期进程

#### 实时进程的调度

每个实时进程都与一个实时优先级相关，

实时优先级是一个范围从 1 (最高优先级) 到 99 (最低优先级) 的值

只有在下述事件之一发生时，实时进程才会被另外一个进程取代：

* 进程被另外一个具有更高实时优先级的实时进程抢占

* 进程执行了阻塞操作并进入睡眠 (处于 TASK_INTERRUPTIBLE 或 TASK_UNINTERRUPTIBLE 状态)

* 进程停止或被杀死

* 进程通过系统调用 `sched_yield()` 自愿放弃 CPU

* 进程是基于时间片轮转的实时进程 (SCHED_RR)，而且用完了它的时间片

## 调度程序使用的数据结构

进程链表链接所有的进程描述符，运行队列链表

链接所有的可运行进程 (处于 TASK_RUNNING 状态的进程) 的进程描述符，

swapper 进程 (idle 进程) 除外

### 数据结构 runqueue

runqueue 是 Linux 调度程序最重要的数据结构。

系统中的每个 CPU 都有它自己的运行队列，所有的 runqueue 结构存放在 runqueues 每 CPU 变量中

宏 `this_rq()` 产生本地 CPU 运行队列的地址，

宏 `cpu_rq(n)` 产生索引为 n 的 CPU 的运行队列的地址

```c
// file: kernel/sched/sched.h

DECLARE_PER_CPU_SHARED_ALIGNED(struct rq, runqueues);

#define cpu_rq(cpu)        (&per_cpu(runqueues, (cpu)))
#define this_rq()        this_cpu_ptr(&runqueues)

/*
 * This is the main, per-CPU runqueue data structure.
 *
 * Locking rule: those places that want to lock multiple runqueues
 * (such as the load balancing or the thread migration code), lock
 * acquire operations must be ordered by ascending &runqueue.
 */

struct rq {
    /* runqueue lock: */
    raw_spinlock_t      __lock;
    unsigned int        nr_running;

    u64                 nr_switches;

    /*
    * This is part of a global counter where only the total sum
    * over all CPUs matters. A task can increase this counter on
    * one CPU and if it got migrated afterwards it may decrease
    * it on another CPU. Always updated under the runqueue lock:
    */
    unsigned int        nr_uninterruptible;

    struct task_struct __rcu    *curr;
    struct task_struct    *idle;

    struct mm_struct    *prev_mm;
    atomic_t            nr_iowait;
    struct sched_domain __rcu    *sd;

    /* sys_sched_yield() stats */
    unsigned int        yld_count;

    /* schedule() stats */
    unsigned int        sched_count;
    unsigned int        sched_goidle;

    /* try_to_wake_up() stats */
    unsigned int        ttwu_count;
    unsigned int        ttwu_local;
};
```

系统中的每个可运行进程属于且只属于一个运行队列。

只要可运行进程保持在同一个运行队列中，它就只可能在拥有该运行队列的 CPU 上执行。

可运行进程会从一个运行队列迁移到另一个运行队列

#### 进程描述符与调度

进程描述符与调度相关的字段：

```c
// file: arch/x86/include/asm/thread_info.h

struct thread_info {
    unsigned long       flags;           /* low level flags */
    unsigned long       syscall_work;    /* SYSCALL_WORK_ flags */
    u32                 status;          /* thread synchronous flags */
#ifdef CONFIG_SMP
    u32                 cpu;             /* current CPU */
#endif
};

struct sched_info {
#ifdef CONFIG_SCHED_INFO
    /* Cumulative counters: */

    /* # of times we have run on this CPU: */
    unsigned long            pcount;

    /* Time spent waiting on a runqueue: */
    unsigned long long        run_delay;

    /* Timestamps: */

    /* When did we last run on a CPU? */
    unsigned long long        last_arrival;

    /* When were we last queued to run? */
    unsigned long long        last_queued;

#endif /* CONFIG_SCHED_INFO */
};

struct task_struct {
    int                 prio;
    int                 static_prio;
    int                 normal_prio;
    unsigned int        rt_priority;
};
```

```c
// file: kernel/sched/sched.h

static inline int idle_policy(int policy)
{
    return policy == SCHED_IDLE;
}

static inline int fair_policy(int policy)
{
    return policy == SCHED_NORMAL || policy == SCHED_BATCH;
}

static inline int rt_policy(int policy)
{
    return policy == SCHED_FIFO || policy == SCHED_RR;
}

static inline int dl_policy(int policy)
{
    return policy == SCHED_DEADLINE;
}

static inline bool valid_policy(int policy)
{
    return idle_policy(policy) || fair_policy(policy) ||
        rt_policy(policy) || dl_policy(policy);
}

static inline int task_has_idle_policy(struct task_struct *p)
{
    return idle_policy(p->policy);
}

static inline int task_has_rt_policy(struct task_struct *p)
{
    return rt_policy(p->policy);
}

static inline int task_has_dl_policy(struct task_struct *p)
{
    return dl_policy(p->policy);
}
```

```c
// file: kernel/sched/clock.c

/*
 * Scheduler clock - returns current time in nanosec units.
 * This is default implementation.
 * Architectures and sub-architectures can override this.
 */
notrace unsigned long long __weak sched_clock(void)
{
    return (unsigned long long)(jiffies - INITIAL_JIFFIES)
                    * (NSEC_PER_SEC / HZ);
}
EXPORT_SYMBOL_GPL(sched_clock);
```

## 调度程序使用的函数

调度程序依靠几个函数来完成调度工作，其中最重要的函数是：

* try_to_wake_up()  唤醒睡眠进程

* schedule()  选择要被执行的新进程

```c
// file: kernel/sched/sched.h

/* Wake flags. The first three directly map to some SD flag value */
#define WF_EXEC               0x02 /* Wakeup after exec; maps to SD_BALANCE_EXEC */
#define WF_FORK               0x04 /* Wakeup after fork; maps to SD_BALANCE_FORK */
#define WF_TTWU               0x08 /* Wakeup;            maps to SD_BALANCE_WAKE */

#define WF_SYNC               0x10 /* Waker goes to sleep after wakeup */
#define WF_MIGRATED           0x20 /* Internal use, task got migrated */
#define WF_CURRENT_CPU        0x40 /* Prefer to move the wakee to the current CPU. */
```

```c
asmlinkage __visible void __sched schedule(void)
{
    struct task_struct *tsk = current;

#ifdef CONFIG_RT_MUTEXES
    lockdep_assert(!tsk->sched_rt_mutex);
#endif

    if (!task_is_running(tsk))
        sched_submit_work(tsk);
    __schedule_loop(SM_NONE);
    sched_update_worker(tsk);
}
EXPORT_SYMBOL(schedule);

#define task_is_running(task)     (READ_ONCE((task)->__state) == TASK_RUNNING)

static __always_inline void __schedule_loop(unsigned int sched_mode)
{
    do {
        preempt_disable();
        __schedule(sched_mode);
        sched_preempt_enable_no_resched();
    } while (need_resched());
}

/*
 * Constants for the sched_mode argument of __schedule().
 *
 * The mode argument allows RT enabled kernels to differentiate a
 * preemption from blocking on an 'sleeping' spin/rwlock. Note that
 * SM_MASK_PREEMPT for !RT has all bits set, which allows the compiler to
 * optimize the AND operation out and just check for zero.
 */
#define SM_NONE            0x0
#define SM_PREEMPT        0x1
#define SM_RTLOCK_WAIT        0x2

#ifndef CONFIG_PREEMPT_RT
# define SM_MASK_PREEMPT    (~0U)
#else
# define SM_MASK_PREEMPT    SM_PREEMPT
#endif

/*
 * __schedule() is the main scheduler function.
 *
 * The main means of driving the scheduler and thus entering this function are:
 *
 *   1. Explicit blocking: mutex, semaphore, waitqueue, etc.
 *
 *   2. TIF_NEED_RESCHED flag is checked on interrupt and userspace return
 *      paths. For example, see arch/x86/entry_64.S.
 *
 *      To drive preemption between tasks, the scheduler sets the flag in timer
 *      interrupt handler sched_tick().
 *
 *   3. Wakeups don't really cause entry into schedule(). They add a
 *      task to the run-queue and that's it.
 *
 *      Now, if the new task added to the run-queue preempts the current
 *      task, then the wakeup sets TIF_NEED_RESCHED and schedule() gets
 *      called on the nearest possible occasion:
 *
 *       - If the kernel is preemptible (CONFIG_PREEMPTION=y):
 *
 *         - in syscall or exception context, at the next outmost
 *           preempt_enable(). (this might be as soon as the wake_up()'s
 *           spin_unlock()!)
 *
 *         - in IRQ context, return from interrupt-handler to
 *           preemptible context
 *
 *       - If the kernel is not preemptible (CONFIG_PREEMPTION is not set)
 *         then at the next:
 *
 *          - cond_resched() call
 *          - explicit schedule() call
 *          - return from syscall or exception to user-space
 *          - return from interrupt-handler to user-space
 *
 * WARNING: must be called with preemption disabled!
 */
static void __sched notrace __schedule(unsigned int sched_mode)     { }

/*
 * {de,en}queue flags:
 *
 * DEQUEUE_SLEEP  - task is no longer runnable
 * ENQUEUE_WAKEUP - task just became runnable
 *
 * SAVE/RESTORE - an otherwise spurious dequeue/enqueue, done to ensure tasks
 *                are in a known state which allows modification. Such pairs
 *                should preserve as much state as possible.
 *
 * MOVE - paired with SAVE/RESTORE, explicitly does not preserve the location
 *        in the runqueue.
 *
 * NOCLOCK - skip the update_rq_clock() (avoids double updates)
 *
 * MIGRATION - p->on_rq == TASK_ON_RQ_MIGRATING (used for DEADLINE)
 *
 * ENQUEUE_HEAD      - place at front of runqueue (tail if not specified)
 * ENQUEUE_REPLENISH - CBS (replenish runtime and postpone deadline)
 * ENQUEUE_MIGRATED  - the task was migrated during wakeup
 *
 */

#define DEQUEUE_SLEEP        0x01
#define DEQUEUE_SAVE         0x02 /* Matches ENQUEUE_RESTORE */
#define DEQUEUE_MOVE         0x04 /* Matches ENQUEUE_MOVE */
#define DEQUEUE_NOCLOCK      0x08 /* Matches ENQUEUE_NOCLOCK */
#define DEQUEUE_MIGRATING    0x100 /* Matches ENQUEUE_MIGRATING */

#define ENQUEUE_WAKEUP       0x01
#define ENQUEUE_RESTORE      0x02
#define ENQUEUE_MOVE         0x04
#define ENQUEUE_NOCLOCK      0x08

#define ENQUEUE_HEAD         0x10
#define ENQUEUE_REPLENISH    0x20
#ifdef CONFIG_SMP
#define ENQUEUE_MIGRATED     0x40
#else
#define ENQUEUE_MIGRATED     0x00
#endif
#define ENQUEUE_INITIAL      0x80
#define ENQUEUE_MIGRATING    0x100

struct sched_class {

#ifdef CONFIG_UCLAMP_TASK
	int uclamp_enabled;
#endif

	void (*enqueue_task) (struct rq *rq, struct task_struct *p, int flags);
	void (*dequeue_task) (struct rq *rq, struct task_struct *p, int flags);
	void (*yield_task)   (struct rq *rq);
	bool (*yield_to_task)(struct rq *rq, struct task_struct *p);

	void (*wakeup_preempt)(struct rq *rq, struct task_struct *p, int flags);

	struct task_struct *(*pick_next_task)(struct rq *rq);

	void (*put_prev_task)(struct rq *rq, struct task_struct *p);
	void (*set_next_task)(struct rq *rq, struct task_struct *p, bool first);

#ifdef CONFIG_SMP
	int (*balance)(struct rq *rq, struct task_struct *prev, struct rq_flags *rf);
	int  (*select_task_rq)(struct task_struct *p, int task_cpu, int flags);

	struct task_struct * (*pick_task)(struct rq *rq);

	void (*migrate_task_rq)(struct task_struct *p, int new_cpu);

	void (*task_woken)(struct rq *this_rq, struct task_struct *task);

	void (*set_cpus_allowed)(struct task_struct *p, struct affinity_context *ctx);

	void (*rq_online)(struct rq *rq);
	void (*rq_offline)(struct rq *rq);

	struct rq *(*find_lock_rq)(struct task_struct *p, struct rq *rq);
#endif

	void (*task_tick)(struct rq *rq, struct task_struct *p, int queued);
	void (*task_fork)(struct task_struct *p);
	void (*task_dead)(struct task_struct *p);

	/*
	 * The switched_from() call is allowed to drop rq->lock, therefore we
	 * cannot assume the switched_from/switched_to pair is serialized by
	 * rq->lock. They are however serialized by p->pi_lock.
	 */
	void (*switched_from)(struct rq *this_rq, struct task_struct *task);
	void (*switched_to)  (struct rq *this_rq, struct task_struct *task);
	void (*prio_changed) (struct rq *this_rq, struct task_struct *task,
			      int oldprio);

	unsigned int (*get_rr_interval)(struct rq *rq,
					struct task_struct *task);

	void (*update_curr)(struct rq *rq);

#ifdef CONFIG_FAIR_GROUP_SCHED
	void (*task_change_group)(struct task_struct *p);
#endif

#ifdef CONFIG_SCHED_CORE
	int (*task_is_throttled)(struct task_struct *p, int cpu);
#endif
};
```

```c
static inline void set_tsk_need_resched(struct task_struct *tsk)
{
	set_tsk_thread_flag(tsk,TIF_NEED_RESCHED);
}

static inline void set_tsk_thread_flag(struct task_struct *tsk, int flag)
{
	set_ti_thread_flag(task_thread_info(tsk), flag);
}

static inline void set_ti_thread_flag(struct thread_info *ti, int flag)
{
	set_bit(flag, (unsigned long *)&ti->flags);
}

#ifdef CONFIG_THREAD_INFO_IN_TASK
# define task_thread_info(task)	(&(task)->thread_info)
#elif !defined(__HAVE_THREAD_FUNCTIONS)
# define task_thread_info(task)	((struct thread_info *)(task)->stack)
#endif
```

#### schedule() 函数

函数 schedule() 实现调度程序，

它的任务是从运行队列的链表中找到一个进程，并随后将 CPU 分配给这个进程

schedule() 可以由几个内核控制路径调用，可以采取直接调用或延迟调用 (可延迟的) 的方式

##### 直接调用

如果 current 进程因不能获得必须的资源而要立刻被阻塞，就直接调用调度程序。

内核反复检查进程需要的资源是否可用，如果不可用，就调用 schedule() 把 CPU 分配给其他进程

##### 进程切换之前 schedule() 所执行的操作

schedule() 函数的任务之一是用另外一个进程来替换当前正在执行的进程

schedule() 函数在一开始先禁用内核抢占

##### schedule() 完成进程切换时所执行的操作

```c
/*
 * context_switch - switch to the new MM and the new thread's register state.
 */
static __always_inline struct rq *
context_switch(struct rq *rq, struct task_struct *prev,
	       struct task_struct *next, struct rq_flags *rf)
```

context_switch() 函数建立 next 的地址空间，而内核线程的 mm 字段总是被设置为 NULL

如果 next 是内核线程，schedule() 函数把进程设置为懒惰 TLB 模式

如果 next 是普通进程，context_switch() 函数用 next 的地址空间替换 prev 的地址空间

##### 进程切换后 schedule() 所执行的操作

```c
static inline void mmdrop(struct mm_struct *mm)
{
	/*
	 * The implicit full barrier implied by atomic_dec_and_test() is
	 * required by the membarrier system call before returning to
	 * user-space, after storing to rq->curr.
	 */
	if (unlikely(atomic_dec_and_test(&mm->mm_count)))
		__mmdrop(mm);
}

/*
 * Called when the last reference to the mm
 * is dropped: either by a lazy thread or by
 * mmput. Free the page directory and the mm.
 */
void __mmdrop(struct mm_struct *mm)
{
	BUG_ON(mm == &init_mm);
	WARN_ON_ONCE(mm == current->mm);

	/* Ensure no CPUs are using this as their lazy tlb mm */
	cleanup_lazy_tlbs(mm);

	WARN_ON_ONCE(mm == current->active_mm);
	mm_free_pgd(mm);
	destroy_context(mm);
	mmu_notifier_subscriptions_destroy(mm);
	check_mm(mm);
	put_user_ns(mm->user_ns);
	mm_pasid_drop(mm);
	mm_destroy_cid(mm);
	percpu_counter_destroy_many(mm->rss_stat, NR_MM_COUNTERS);

	free_mm(mm);
}
EXPORT_SYMBOL_GPL(__mmdrop);
```

mmdrop() 减少内存描述符的使用计数器，

如果该计数器等于 0 了，函数还要释放与页表相关的所有描述符和虚拟存储区

## 多处理器系统中运行队列的平衡

schedule() 函数从本地 CPU 的运行队列挑选新进程运行

一个指定的 CPU 只能执行其相应的运行队列中的可运行进程

任何一个可运行进程都不可能同时出现在两个或多个运行队列中

为了从多处理器系统获得最佳性能，负载平衡算法应该考虑系统中 CPU 的拓扑结构

Linux 提出了一种基于 "调度域" 概念的复杂的运行队列平衡算法

### Scheduling Domains (调度域)

每个调度域由一个 sched_domain 描述符表示

```c
struct sched_domain {
	/* These fields must be setup */
	struct sched_domain __rcu *parent;	/* top domain must be null terminated */
	struct sched_domain __rcu *child;	/* bottom domain must be null terminated */
	struct sched_group *groups;	/* the balancing groups of the domain */
	unsigned long min_interval;	/* Minimum balance interval ms */
	unsigned long max_interval;	/* Maximum balance interval ms */
	unsigned int busy_factor;	/* less balancing by factor if busy */
	unsigned int imbalance_pct;	/* No balance until over watermark */
	unsigned int cache_nice_tries;	/* Leave cache hot tasks for # tries */
	unsigned int imb_numa_nr;	/* Nr running tasks that allows a NUMA imbalance */

	int nohz_idle;			/* NOHZ IDLE status */
	int flags;			/* See SD_* */
	int level;
    ...
};
```

```c
void enqueue_task(struct rq *rq, struct task_struct *p, int flags)
{
	if (!(flags & ENQUEUE_NOCLOCK))
		update_rq_clock(rq);

	if (!(flags & ENQUEUE_RESTORE)) {
		sched_info_enqueue(rq, p);
		psi_enqueue(p, (flags & ENQUEUE_WAKEUP) && !(flags & ENQUEUE_MIGRATED));
	}

	uclamp_rq_inc(rq, p);
	p->sched_class->enqueue_task(rq, p, flags);

	if (sched_core_enabled(rq))
		sched_core_enqueue(rq, p);
}

void dequeue_task(struct rq *rq, struct task_struct *p, int flags)
{
	if (sched_core_enabled(rq))
		sched_core_dequeue(rq, p, flags);

	if (!(flags & DEQUEUE_NOCLOCK))
		update_rq_clock(rq);

	if (!(flags & DEQUEUE_SAVE)) {
		sched_info_dequeue(rq, p);
		psi_dequeue(p, flags & DEQUEUE_SLEEP);
	}

	uclamp_rq_dec(rq, p);
	p->sched_class->dequeue_task(rq, p, flags);
}
```

## System Calls Related to Scheduling

### nice() 系统调用

```c
/*
 * sys_nice - change the priority of the current process.
 * @increment: priority increment
 *
 * sys_setpriority is a more generic, but much slower function that
 * does similar things.
 */
SYSCALL_DEFINE1(nice, int, increment)
{
	long nice, retval;

	/*
	 * Setpriority might change our priority at the same moment.
	 * We don't have to worry. Conceptually one call occurs first
	 * and we have a single winner.
	 */
	increment = clamp(increment, -NICE_WIDTH, NICE_WIDTH);
	nice = task_nice(current) + increment;

	nice = clamp_val(nice, MIN_NICE, MAX_NICE);
	if (increment < 0 && !can_nice(current, nice))
		return -EPERM;

	retval = security_task_setnice(current, nice);
	if (retval)
		return retval;

	set_user_nice(current, nice);
	return 0;
}

#define MAX_NICE	19
#define MIN_NICE	-20
#define NICE_WIDTH	(MAX_NICE - MIN_NICE + 1)
```

### getpriority() 和 setpriority() 系统调用

```c
SYSCALL_DEFINE3(setpriority, int, which, int, who, int, niceval) { }

/*
 * Ugh. To avoid negative return values, "getpriority()" will
 * not return the normal nice-value, but a negated value that
 * has been offset by 20 (ie it returns 40..1 instead of -20..19)
 * to stay compatible.
 */
SYSCALL_DEFINE2(getpriority, int, which, int, who) { }

#define	PRIO_MIN	(-20)
#define	PRIO_MAX	20

#define	PRIO_PROCESS	0
#define	PRIO_PGRP	1
#define	PRIO_USER	2
```

* PRIO_PROCESS 根据进程的 ID 选择进程 (进程描述符的 pid 字段)

* PRIO_PGRP    根据组 ID 选择进程 (进程描述符的 pgrp 字段)

* PRIO_USER    根据用户 ID 选择进程 (进程描述符的 uid 字段)

### sched_getaffinity() 和 sched_setaffinity() 系统调用

```c
/**
 * sys_sched_getaffinity - get the CPU affinity of a process
 * @pid: pid of the process
 * @len: length in bytes of the bitmask pointed to by user_mask_ptr
 * @user_mask_ptr: user-space pointer to hold the current CPU mask
 *
 * Return: size of CPU mask copied to user_mask_ptr on success. An
 * error code otherwise.
 */
SYSCALL_DEFINE3(sched_getaffinity, pid_t, pid, unsigned int, len,
		unsigned long __user *, user_mask_ptr)
{
	int ret;
	cpumask_var_t mask;

	if ((len * BITS_PER_BYTE) < nr_cpu_ids)
		return -EINVAL;
	if (len & (sizeof(unsigned long)-1))
		return -EINVAL;

	if (!zalloc_cpumask_var(&mask, GFP_KERNEL))
		return -ENOMEM;

	ret = sched_getaffinity(pid, mask);
	if (ret == 0) {
		unsigned int retlen = min(len, cpumask_size());

		if (copy_to_user(user_mask_ptr, cpumask_bits(mask), retlen))
			ret = -EFAULT;
		else
			ret = retlen;
	}
	free_cpumask_var(mask);

	return ret;
}

typedef struct cpumask { DECLARE_BITMAP(bits, NR_CPUS); } cpumask_t;

/**
 * sys_sched_setaffinity - set the CPU affinity of a process
 * @pid: pid of the process
 * @len: length in bytes of the bitmask pointed to by user_mask_ptr
 * @user_mask_ptr: user-space pointer to the new CPU mask
 *
 * Return: 0 on success. An error code otherwise.
 */
SYSCALL_DEFINE3(sched_setaffinity, pid_t, pid, unsigned int, len,
		unsigned long __user *, user_mask_ptr)
{
	cpumask_var_t new_mask;
	int retval;

	if (!alloc_cpumask_var(&new_mask, GFP_KERNEL))
		return -ENOMEM;

	retval = get_user_cpu_mask(user_mask_ptr, len, new_mask);
	if (retval == 0)
		retval = sched_setaffinity(pid, new_mask);
	free_cpumask_var(new_mask);
	return retval;
}
```

### sched_getscheduler() 和 sched_setscheduler() 系统调用

```c
/**
 * sys_sched_getscheduler - get the policy (scheduling class) of a thread
 * @pid: the pid in question.
 *
 * Return: On success, the policy of the thread. Otherwise, a negative error
 * code.
 */
SYSCALL_DEFINE1(sched_getscheduler, pid_t, pid)
{
	struct task_struct *p;
	int retval;

	if (pid < 0)
		return -EINVAL;

	guard(rcu)();
	p = find_process_by_pid(pid);
	if (!p)
		return -ESRCH;

	retval = security_task_getscheduler(p);
	if (!retval) {
		retval = p->policy;
		if (p->sched_reset_on_fork)
			retval |= SCHED_RESET_ON_FORK;
	}
	return retval;
}

/**
 * sys_sched_setscheduler - set/change the scheduler policy and RT priority
 * @pid: the pid in question.
 * @policy: new policy.
 * @param: structure containing the new RT priority.
 *
 * Return: 0 on success. An error code otherwise.
 */
SYSCALL_DEFINE3(sched_setscheduler, pid_t, pid, int, policy, struct sched_param __user *, param)
{
	if (policy < 0)
		return -EINVAL;

	return do_sched_setscheduler(pid, policy, param);
}

struct sched_param {
	int sched_priority;
};
```

### sched_getparam() 和 sched_setparam() 系统调用

```c
/**
 * sys_sched_getparam - get the RT priority of a thread
 * @pid: the pid in question.
 * @param: structure containing the RT priority.
 *
 * Return: On success, 0 and the RT priority is in @param. Otherwise, an error
 * code.
 */
SYSCALL_DEFINE2(sched_getparam, pid_t, pid, struct sched_param __user *, param)
{
	struct sched_param lp = { .sched_priority = 0 };
	struct task_struct *p;
	int retval;

	if (!param || pid < 0)
		return -EINVAL;

	scoped_guard (rcu) {
		p = find_process_by_pid(pid);
		if (!p)
			return -ESRCH;

		retval = security_task_getscheduler(p);
		if (retval)
			return retval;

		if (task_has_rt_policy(p))
			lp.sched_priority = p->rt_priority;
	}

	/*
	 * This one might sleep, we cannot do it with a spinlock held ...
	 */
	return copy_to_user(param, &lp, sizeof(*param)) ? -EFAULT : 0;
}

/**
 * sys_sched_setparam - set/change the RT priority of a thread
 * @pid: the pid in question.
 * @param: structure containing the new RT priority.
 *
 * Return: 0 on success. An error code otherwise.
 */
SYSCALL_DEFINE2(sched_setparam, pid_t, pid, struct sched_param __user *, param)
{
	return do_sched_setscheduler(pid, SETPARAM_POLICY, param);
}
```

### sched_yield() 系统调用

```c
/**
 * sys_sched_yield - yield the current processor to other threads.
 *
 * This function yields the current CPU to other tasks. If there are no
 * other threads running on this CPU then this function will return.
 *
 * Return: 0.
 */
SYSCALL_DEFINE0(sched_yield)
{
	do_sched_yield();
	return 0;
}

static void do_sched_yield(void)
{
	struct rq_flags rf;
	struct rq *rq;

	rq = this_rq_lock_irq(&rf);

	schedstat_inc(rq->yld_count);
	current->sched_class->yield_task(rq);

	preempt_disable();
	rq_unlock_irq(rq, &rf);
	sched_preempt_enable_no_resched();

	schedule();
}
```

### sched_rr_get_interval() 系统调用

```c
/**
 * sys_sched_rr_get_interval - return the default time-slice of a process.
 * @pid: pid of the process.
 * @interval: userspace pointer to the time-slice value.
 *
 * this syscall writes the default time-slice value of a given process
 * into the user-space timespec buffer. A value of '0' means infinity.
 *
 * Return: On success, 0 and the time-slice is in @interval. Otherwise,
 * an error code.
 */
SYSCALL_DEFINE2(sched_rr_get_interval, pid_t, pid,
		struct __kernel_timespec __user *, interval)
{
	struct timespec64 t;
	int retval = sched_rr_get_interval(pid, &t);

	if (retval == 0)
		retval = put_timespec64(&t, interval);

	return retval;
}
```
