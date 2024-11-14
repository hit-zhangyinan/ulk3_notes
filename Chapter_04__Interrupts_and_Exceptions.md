# 第 4 章 中断和异常

中断通常分为同步中断和异步中断：

* 同步中断是当指令执行时由 CPU 控制单元产生的

* 异步中断是由其他硬件设备产生的

Intel 处理器手册把同步和异步中断分别称为异常 (exception) 和中断 (interrupt)

## 中断信号的作用

中断处理与进程切换有一个明显的差异：中断或异常处理程序执行的代码不是一个进程

中断处理程序比一个进程要轻（中断的上下文很少，中断处理需要的时间很少）

中断处理必须满足下列约束：

* 内核响应中断后需要进行的操作分为两部分：

  关键而紧急的部分，内核立即执行；推迟的部分，内核随后执行

* kernel should run most of the time with the interrupts enabled

## 中断和异常

Intel 的文档把中断和异常分为以下几类：

* 中断：

  可屏蔽中断：I/O 设备发出的所有中断请求都产生可屏蔽中断

  非屏蔽中断：只有几个危急事件（如硬件故障）才引起非屏蔽中断

* 异常：

  处理器探测异常，进一步分成三组：

    故障（fault）：通常可以纠正

    陷阱（trap）：陷阱的主要用途是调试程序

    异常中止（abort）：发生严重的错误

  编程异常：控制单元把编程异常当作陷阱来处理，编程异常通常也叫做软中断

中断和异常是由 0~255 之间的一个数来标识

非屏蔽中断的向量和异常向量是固定的，而可屏蔽中断的向量可以通过对中断控制器的编程来改变

### IRQ 和中断

每个能够发出中断请求的硬件设备控制器都有一条名为 IRQ 的输出线

复杂一些的设备可能有好几条 IRQ 线

所有的 IRQ 线都与可编程中断控制器 (programmable interrupt controller, PIC) 上的输入引脚相连

PIC 执行下列动作：

* 监视 IRQ 线，如果触发信号出现在 IRQ 线上

* 把触发信号转换成对应的中断向量，把向量存放在 I/O 端口，允许 CPU 读取

* 向处理器的 INTR 引脚发送信号

* 等待 CPU 确认中断，然后 clear INTR line

* 返回最开始，重复此流程

传统的 PIC 是由 Intel 8259A 连接组成的

(Intel 8259 是为 8085 和 8086 处理器设计的)

### 高级可编程中断控制器

Intel 从 Pentium III 开始引入了名为高级可编程中断控制器 (Advanced PIC, APIC) 的新组件

### 异常

内核必须为每种异常提供一个专门的异常处理程序

### 中断描述符表 (Interrupt Descriptor Table)

### 中断和异常的硬件处理

## 中断和异常处理程序的嵌套执行

在内核态能触发的唯一异常是缺页异常 (page fault)

## 初始化中断描述符表

## 异常处理

### 进入和离开异常处理程序

```c
// file: arch/x86/kernel/dumpstack.c

/*
 * This is gone through when something in the kernel has done something bad
 * and is about to be terminated:
 */
void die(const char *str, struct pt_regs *regs, long err)
{
    unsigned long flags = oops_begin();
    int sig = SIGSEGV;

    if (__die(str, regs, err))
        sig = 0;
    oops_end(flags, regs, sig);
}

int __die(const char *str, struct pt_regs *regs, long err)
{
    __die_header(str, regs, err);
    return __die_body(str, regs, err);
}
NOKPROBE_SYMBOL(__die);
```

## 中断处理

中断处理依赖于中断类型，讨论三种主要的中断类型：

* I/O 中断

* 时钟中断

* 处理器间中断

### I/O 中断处理

不管引起中断的电路种类如何，所有的 I/O 中断处理程序都执行四个相同的基本操作：

* 在内核态 stack 保存 IRQ 的值和寄存器的内容

* 为正在给 IRQ 线服务的 PIC 发送一个应答，这允许 PIC 进一步发出中断

* 执行共享这个 IRQ 的所有设备的中断服务例程（interrupt service routines, ISR）

* 跳到 ret_from_intr() 的地址后终止

物理 IRQ 可以分配给 32 ~ 238 范围内的任何向量 (Linux 使用向量 128 实现系统调用)

内核必须在启用中断前发现 IRQ 号与 I/O 设备之间的对应

IRQ 号与 I/O 设备之间的对应是在初始化每个设备驱动程序时建立的 (参阅第十三章)

### IRQ 数据结构

```c
// file: include/linux/irqdesc.h

struct irq_desc {
    ...    // many members
} ____cacheline_internodealigned_in_smp;
```

```c
// file: include/linux/interrupt.h

typedef irqreturn_t (*irq_handler_t)(int, void *);    // pointer to function, store addr of func

struct irqaction {
    irq_handler_t            handler;
    void                     *dev_id;
    void __percpu            *percpu_dev_id;
    struct irqaction         *next;
    irq_handler_t            thread_fn;
    struct task_struct       *thread;
    struct irqaction         *secondary;
    unsigned int             irq;
    unsigned int             flags;
    unsigned long            thread_flags;
    unsigned long            thread_mask;
    const char               *name;
    struct proc_dir_entry    *dir;
} ____cacheline_internodealigned_in_smp;

extern void disable_irq_nosync(unsigned int irq);
extern bool disable_hardirq(unsigned int irq);
extern void disable_irq(unsigned int irq);
extern void disable_percpu_irq(unsigned int irq);

extern void enable_irq(unsigned int irq);
extern void enable_percpu_irq(unsigned int irq, unsigned int type);
```

```c
// file: kernel/irq/manage.c
void disable_irq(unsigned int irq)
{
    might_sleep();
    if (!__disable_irq_nosync(irq))
        synchronize_irq(irq);
}
EXPORT_SYMBOL(disable_irq);
```

```c
// file: include/linux/irqreturn.h

enum irqreturn {
    IRQ_NONE              = (0 << 0),
    IRQ_HANDLED           = (1 << 0),
    IRQ_WAKE_THREAD       = (1 << 1),
};

typedef enum irqreturn irqreturn_t;
```

```c
// file: arch/x86/include/asm/hardirq.h

typedef struct {
    ...    // many members
} ____cacheline_aligned irq_cpustat_t;
```

```c
// file: include/linux/cache.h

#if !defined(____cacheline_internodealigned_in_smp)
#if defined(CONFIG_SMP)
#define ____cacheline_internodealigned_in_smp \
    __attribute__((__aligned__(1 << (INTERNODE_CACHE_SHIFT))))
#else
#define ____cacheline_internodealigned_in_smp
#endif
#endif

#ifndef ____cacheline_aligned
#define ____cacheline_aligned __attribute__((__aligned__(SMP_CACHE_BYTES)))
#endif
```

### IRQ 在多处理器系统上的分发

```c
// file: arch/x86/kernel/apic/apic.c

/**
 * setup_local_APIC - setup the local APIC
 *
 * Used to setup local APIC while initializing BSP or bringing up APs.
 * Always called with preemption disabled.
 */
static void setup_local_APIC(void)
{
    ...
}
```

### IRQ 线的动态分配

在激活一个准备利用 IRQ 线的设备之前，相应的驱动程序调用 request_irq()

这个函数建立一个新的 irqaction 描述符，并用参数值初始化它

```c
// file: include/linux/interrupt.h

/**
 * request_irq - Add a handler for an interrupt line
 * @irq:        The interrupt line to allocate
 * @handler:    Function to be called when the IRQ occurs.
 *              Primary handler for threaded interrupts
 *              If NULL, the default primary handler is installed
 * @flags:      Handling flags
 * @name:       Name of the device generating this interrupt
 * @dev:        A cookie passed to the handler function
 *
 * This call allocates an interrupt and establishes a handler; see
 * the documentation for request_threaded_irq() for details.
 */
static inline int __must_check
request_irq(unsigned int irq, irq_handler_t handler, unsigned long flags,
        const char *name, void *dev)
{
    return request_threaded_irq(irq, handler, NULL, flags, name, dev);
}
```

当设备操作结束时，驱动程序调用 free_irq() 函数从 IRQ 链表中删除这个描述符，并释放相应的内存区

```c
// file: kernel/irq/manage.c

/**
 *    free_irq - free an interrupt allocated with request_irq
 *    @irq:    Interrupt line to free
 *    @dev_id: Device identity to free
 *
 *    Remove an interrupt handler. The handler is removed and if the
 *    interrupt line is no longer in use by any driver it is disabled.
 *    On a shared IRQ the caller must ensure the interrupt is disabled
 *    on the card it drives before calling this function. The function
 *    does not return until any executing interrupts for this IRQ
 *    have completed.
 *
 *    This function must not be called from interrupt context.
 *
 *    Returns the devname argument passed to request_irq.
 */
const void *free_irq(unsigned int irq, void *dev_id)
{
    struct irq_desc *desc = irq_to_desc(irq);
    struct irqaction *action;
    const char *devname;

    if (!desc || WARN_ON(irq_settings_is_per_cpu_devid(desc)))
        return NULL;

#ifdef CONFIG_SMP
    if (WARN_ON(desc->affinity_notify))
        desc->affinity_notify = NULL;
#endif

    action = __free_irq(desc, dev_id);

    if (!action)
        return NULL;

    devname = action->name;
    kfree(action);
    return devname;
}
EXPORT_SYMBOL(free_irq);
```

## 软中断及 tasklet (Softirqs and Tasklets)

把可延迟中断从中断处理程序中抽出来有助于内核保持较短的响应时间

Linux 2.6 通过两种机制来实现上述目标：

* 可延迟函数 (软中断与 tasklets)

* 通过工作队列来执行的函数

软中断和 tasklet 有密切的关系，tasklet 是在软中断之上实现

软中断的分配是静态的（即在编译时定义），

而 tasklet 的分配和初始化可以在运行时进行（例如：安装一个内核模块时）

软中断可以并发地运行在多个 CPU 上，因此，

软中断是可重入的，而且必须使用自旋锁保护其数据结构

相同类型的 tasklet 总是被串行执行，不能在两个 CPU 上同时运行相同类型的 tasklet

类型不同的 tasklet 可以在几个 CPU 上并发执行

tasklet 的串行化使得 tasklet 函数不必是可重入的，简化了驱动程序开发者的工作

### 软中断 (Softirqs)

Linux 只定义了很少的软中断，因为在很多场合 tasklet 足够用而且更容易编写

```c
// file: include/linux/interrupt.h

/* PLEASE, avoid to allocate new softirqs, if you need not _really_ high
   frequency threaded job scheduling. For almost all the purposes
   tasklets are more than enough. F.e. all serial device BHs et
   al. should be converted to tasklets, not to softirqs.
 */

enum
{
    HI_SOFTIRQ=0,
    TIMER_SOFTIRQ,
    NET_TX_SOFTIRQ,
    NET_RX_SOFTIRQ,
    BLOCK_SOFTIRQ,
    IRQ_POLL_SOFTIRQ,
    TASKLET_SOFTIRQ,
    SCHED_SOFTIRQ,
    HRTIMER_SOFTIRQ,
    RCU_SOFTIRQ,    /* Preferable RCU should always be the last softirq */

    NR_SOFTIRQS
};
```

软中断的下标越低优先级越高

```c
// file: kernel/softirq.c

void __init softirq_init(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		per_cpu(tasklet_vec, cpu).tail =
			&per_cpu(tasklet_vec, cpu).head;
		per_cpu(tasklet_hi_vec, cpu).tail =
			&per_cpu(tasklet_hi_vec, cpu).head;
	}

	open_softirq(TASKLET_SOFTIRQ, tasklet_action);
	open_softirq(HI_SOFTIRQ, tasklet_hi_action);
}
```

```c
// file: kernel/time/hrtimer.c

void __init hrtimers_init(void)
{
	hrtimers_prepare_cpu(smp_processor_id());
	open_softirq(HRTIMER_SOFTIRQ, hrtimer_run_softirq);
}
```

### 软中断所使用的数据结构

表示软中断的主要数据结构是 softirq_vec 数组

```c
// file: kernel/softirq.c

static struct softirq_action softirq_vec[NR_SOFTIRQS] __cacheline_aligned_in_smp;
```

```c
// file: include/linux/interrupt.h

struct softirq_action
{
    void    (*action)(struct softirq_action *);
};
```

### 处理软中断

```c
// file: kernel/softirq.c

void open_softirq(int nr, void (*action)(struct softirq_action *))
{
    softirq_vec[nr].action = action;
}

void raise_softirq(unsigned int nr)
{
    unsigned long flags;

    local_irq_save(flags);
    raise_softirq_irqoff(nr);
    local_irq_restore(flags);
}
```

raise_softirq 函数用来激活软中断，接受软中断下标 nr 作为参数

### do_softirq() 函数

```c
// file: kernel/softirq.c

asmlinkage __visible void do_softirq(void)
{
    __u32 pending;
    unsigned long flags;

    if (in_interrupt())
        return;

    local_irq_save(flags);

    pending = local_softirq_pending();

    if (pending)
        do_softirq_own_stack();

    local_irq_restore(flags);
}
```

```c
// file: arch/x86/include/asm/irq_stack.h

#define do_softirq_own_stack()                                   \
{                                                                \
    __this_cpu_write(pcpu_hot.hardirq_stack_inuse, true);        \
    call_on_irqstack(__do_softirq, ASM_CALL_ARG0);               \
    __this_cpu_write(pcpu_hot.hardirq_stack_inuse, false);       \
}
```

```c
// file: kernel/softirq.c

asmlinkage __visible void __softirq_entry __do_softirq(void)
{
    handle_softirqs(false);
}

static void handle_softirqs(bool ksirqd)
{
    ...
}
```

### ksoftirqd 内核线程

```c
// file: kernel/softirq.c

static void wakeup_softirqd(void)
{
    /* Interrupts are disabled: no need to stop preemption */
    struct task_struct *tsk = __this_cpu_read(ksoftirqd);

    if (tsk)
        wake_up_process(tsk);
}
```

### tasklet

tasklet 是 I/O 驱动程序中实现可延迟函数的首选方法

```c
// file: kernel/softirq.c

/*
 * Tasklets
 */
struct tasklet_head {
    struct tasklet_struct *head;
    struct tasklet_struct **tail;
};

static DEFINE_PER_CPU(struct tasklet_head, tasklet_vec);
static DEFINE_PER_CPU(struct tasklet_head, tasklet_hi_vec);
```

```c
// file: include/linux/interrupt.h

struct tasklet_struct
{
    struct tasklet_struct *next;
    unsigned long state;
    atomic_t count;
    bool use_callback;
    union {
        void (*func)(unsigned long data);
        void (*callback)(struct tasklet_struct *t);
    };
    unsigned long data;
};
```

```c
// file: kernel/softirq.c

void tasklet_init(struct tasklet_struct *t,
          void (*func)(unsigned long), unsigned long data)
{
    t->next = NULL;
    t->state = 0;
    atomic_set(&t->count, 0);
    t->func = func;
    t->use_callback = false;
    t->data = data;
}
EXPORT_SYMBOL(tasklet_init);
```

```c
// file: include/linux/interrupt.h

static inline void tasklet_enable(struct tasklet_struct *t)
{
    smp_mb__before_atomic();
    atomic_dec(&t->count);
}

static inline void tasklet_schedule(struct tasklet_struct *t)
{
    if (!test_and_set_bit(TASKLET_STATE_SCHED, &t->state))
        __tasklet_schedule(t);
}
```

```c
// file: kernel/softirq.c

static __latent_entropy void tasklet_action(struct softirq_action *a)
{
    workqueue_softirq_action(false);
    tasklet_action_common(a, this_cpu_ptr(&tasklet_vec), TASKLET_SOFTIRQ);
}
```

## 工作队列 (Work Queues)

Linux 2.6 中引入了工作队列用来代替任务队列

可延迟函数运行在中断上下文中，工作队列中的函数运行在进程上下文中

执行可阻塞函数（例如：需要访问磁盘数据块的函数）的唯一方式是在进程上下文中运行

在中断上下文中不可能发生进程切换

工作队列中的函数是由内核线程来执行的，根本不存在它要访问的用户态地址空间

### 工作队列的数据结构

```c
// file: kernel/workqueue.c

struct workqueue_struct {
    ...
};
```

### 工作队列函数

```c
// file: include/linux/workqueue.h

#define create_workqueue(name)                                        \
    alloc_workqueue("%s", __WQ_LEGACY | WQ_MEM_RECLAIM, 1, (name))

#define create_singlethread_workqueue(name)                           \
    alloc_ordered_workqueue("%s", __WQ_LEGACY | WQ_MEM_RECLAIM, name)

extern void destroy_workqueue(struct workqueue_struct *wq);
```

create_workqueue() 函数创建 n 个工作者线程 (n 是当前系统中有效运行的 CPU 个数)

create_singlethread_workqueue() 函数只创建一个工作者线程

```c
// file: kernel/workqueue.c

static int worker_thread(void *__worker);
```

### 预定义工作队列

内核引入了叫做 events 的预定义工作队列

```c
// file: include/linux/workqueue.h

static inline bool schedule_work(struct work_struct *work)
{
    return queue_work(system_wq, work);
}

static inline bool schedule_delayed_work(struct delayed_work *dwork,
                    unsigned long delay)
{
    return queue_delayed_work(system_wq, dwork, delay);
}

static inline bool schedule_delayed_work_on(int cpu, struct delayed_work *dwork,
                    unsigned long delay)
{
    return queue_delayed_work_on(cpu, system_wq, dwork, delay);
}

/* Please stop using this function, for this function will be removed in near future. */
#define flush_scheduled_work()                      \
({                                                  \
    __warn_flushing_systemwide_wq();                \
    __flush_workqueue(system_wq);                   \
})
```
