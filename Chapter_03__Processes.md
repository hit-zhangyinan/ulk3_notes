# 第 3 章 进程

通常把进程定义为程序执行的一个实例

如果 16 个用户同时运行 vi，那么就有 16 个独立的进程 (尽管它们共享同一个可执行代码)

## 进程、轻量级进程和线程 (Processes, Lightweight Processes, and Threads)

进程是分配系统资源 (CPU 时间、内存等) 的实体

Linux 内核的早期版本并没有提供多线程应用的支持

Linux 使用轻量级进程对多线程应用程序提供更好的支持

轻量级进程可以共享一些资源，例如地址空间、打开的文件等

## 进程描述符 (Process Descriptor)

进程描述符是 task_struct 类型，它的成员包含了与进程相关的所有信息

```c
// header: include/linux/sched.h

struct task_struct {
    struct thread_info     thread_info;   // 进程的基本信息
    ...
    struct mm_struct       *mm;           // 指向内存区描述符的指针
    ...
    struct fs_struct       *fs;           // Filesystem information
    ...
    struct files_struct    *files;        // Open file information
    ...
    struct signal_struct   *signal;       // 所接收的信号
};

```

### 进程状态

进程可能的状态：

* TASK_RUNNING

  进程要么在 CPU 上执行，要么准备执行

* TASK_INTERRUPTIBLE

  进程被挂起(睡眠)，直到某个条件变为真

* TASK_UNINTERRUPTIBLE

  把信号传递给睡眠进程不能改变它的状态，这种状态在一些情况下很有用

  例如：与硬件设备交互的驱动程序

* TASK_STOPPED

  进程的执行被暂停

* TASK_TRACED

  进程的执行已由 debugger 程序暂停

当进程的执行被终止时，进程的状态变为下面两种状态的一种：

* EXIT_ZOMBIE

* EXIT_DEAD

在 [bootlin](https://elixir.bootlin.com/) 平台的相关代码：

```c
// header: include/linux/sched.h

/*
 * Task state bitmask. NOTE! These bits are also
 * encoded in fs/proc/array.c: get_task_state().
 *
 * We have two separate sets of flags: task->__state
 * is about runnability, while task->exit_state are
 * about the task exiting. Confusing, but this way
 * modifying one set can't modify the other one by
 * mistake.
 */

/* Used in tsk->__state: */
#define TASK_RUNNING            0x00000000
#define TASK_INTERRUPTIBLE      0x00000001
#define TASK_UNINTERRUPTIBLE    0x00000002
#define __TASK_STOPPED          0x00000004
#define __TASK_TRACED           0x00000008
/* Used in tsk->exit_state: */
#define EXIT_DEAD               0x00000010
#define EXIT_ZOMBIE             0x00000020
#define EXIT_TRACE              (EXIT_ZOMBIE | EXIT_DEAD)
```

```c
// file: fs/proc/array.c

static const char * const task_state_array[] = {

    /* states in TASK_REPORT: */
    "R (running)",         /* 0x00 */
    "S (sleeping)",        /* 0x01 */
    "D (disk sleep)",      /* 0x02 */
    "T (stopped)",         /* 0x04 */
    "t (tracing stop)",    /* 0x08 */
    "X (dead)",            /* 0x10 */
    "Z (zombie)",          /* 0x20 */
    "P (parked)",          /* 0x40 */

    /* states beyond TASK_REPORT: */
    "I (idle)",            /* 0x80 */
};

static inline const char *get_task_state(struct task_struct *tsk)
{
    BUILD_BUG_ON(1 + ilog2(TASK_REPORT_MAX) != ARRAY_SIZE(task_state_array));
    return task_state_array[task_state_index(tsk)];
}
```

### 标识一个进程 (Identifying a Process)

能被独立调度的每个执行上下文都必须拥有进程描述符

轻量级进程也有自己的 task_struct 结构

内核对进程的大部分引用是通过进程描述符指针进行的

另外，用户可以使用进程标识符 process ID (PID) 来标识进程

PID 存放在进程描述符的 pid 字段中

PID 被顺序编号，但是有一个上限值

POSIX 标准规定一个多线程应用程序的所有线程都必须有相同的 PID

Linux 引入了线程组，线程组中的所有线程使用和这个线程组的领头线程相同的 PID

领头线程(组中第一个轻量级进程)的 PID 被存入进程描述符的 tgid 字段中

getpid() 系统调用返回当前进程的 tgid 值而不是 pid 的值

线程组的领头线程其 tgid 的值与 pid 的值相同

```c
// file: kernel/sys.c

/**
 * sys_getpid - return the thread group id of the current process
 *
 * Note, despite the name, this returns the tgid not the pid.  The tgid and
 * the pid are identical unless CLONE_THREAD was specified on clone() in
 * which case the tgid is the same in all threads of the same group.
 *
 * This is SMP safe as current->tgid does not change.
 */
SYSCALL_DEFINE0(getpid)
{
    return task_tgid_vnr(current);
}

/* Thread ID - the internal kernel "pid" */
SYSCALL_DEFINE0(gettid)
{
    return task_pid_vnr(current);
}
```

```c
// include/linux/pid.h

static inline pid_t task_tgid_vnr(struct task_struct *tsk)
{
    return __task_pid_nr_ns(tsk, PIDTYPE_TGID, NULL);
}

static inline pid_t task_pid_vnr(struct task_struct *tsk)
{
    return __task_pid_nr_ns(tsk, PIDTYPE_PID, NULL);
}
```

### 标识当前进程

```c
// file: arch/x86/include/asm/current.h

static __always_inline struct task_struct *get_current(void)
{
    if (IS_ENABLED(CONFIG_USE_X86_SEG_SUPPORT))
        return this_cpu_read_const(const_pcpu_hot.current_task);

    return this_cpu_read_stable(pcpu_hot.current_task);
}

#define current get_current()
```

current 宏经常作为进程描述符的前缀出现在内核代码中

例如，current->pid 返回在 CPU 上正在执行的进程的 PID

### 进程链表

进程链表把所有进程的描述符链接起来

每个 task_struct 结构都包含一个 list_head 类型的 tasks 字段

这个类型的 prev 和 next 字段分别指向前面和后面的 task_struct 元素

进程链表的头是 init_task 描述符，它是所谓的 0 进程的进程描述符

```c
// file: include/linux/sched/signal.h

#define for_each_process(p) \
    for (p = &init_task ; (p = next_task(p)) != &init_task ; )
```

for_each_process 扫描整个进程链表

### TASK_RUNNING 状态的进程链表

当内核寻找一个新进程在 CPU 上运行时，必须只考虑可运行进程 (处在 TASK_RUNNING 状态)

提高调度程序运行速度的诀窍是建立多个可运行进程链表，每种进程优先级对应一个不同的链表

enqueue_task 函数把进程描述符插入某个运行队列的链表

```c
// file: kernel/sched/core.c

static inline void enqueue_task(struct rq *rq, struct task_struct *p, int flags);
```

### 进程间的关系

进程 0 和进程 1 是由内核创建的，进程 1 (init) 是所有进程的祖先

### 如何组织进程

运行队列链表把处于 TASK_RUNNING 状态的所有进程组织在一起

当要把其他状态的进程分组时，Linux 采用下列方式：

* 没有对处于 TASK_STOPPED、EXIT_ZOMBIE、EXIT_DEAD 状态的进程进行分组

* 处于 TASK_INTERRUPTIBLE 或 TASK_UNTERRUPTIBLE 状态的进程被细分为许多类，每个类对应一个特定事件。

  在这种情况下，进程状态无法提供足够的信息来快速检索进程，因此有必要引入额外的进程列表。

  这些列表被称为等待队列（wait queues）

### 等待队列

等待队列在内核中有很多用途，尤其用在中断处理、进程同步以及定时

等待队列表示一组睡眠的进程，当某一条件变为真时，由内核唤醒它们

等待队列由双向链表实现，元素包括指向进程描述符的指针

每个等待队列都有一个等待队列头，它是一个类型为 wait_queue_head_t 的数据结构

```c
// file: include/linux/wait.h

struct wait_queue_head {
    spinlock_t          lock;
    struct list_head    head;
};
typedef struct wait_queue_head wait_queue_head_t;
```

等待队列是由中断处理程序和主要内核函数修改的，必须对双向链表进行保护避免同时访问

等待队列链表中的元素类型为 wait_queue_entry_t

```c
// file: include/linux/wait.h

typedef struct wait_queue_entry wait_queue_entry_t;

/*
 * A single wait-queue entry structure:
 */
struct wait_queue_entry {
    unsigned int        flags;
    void                *private;
    wait_queue_func_t   func;
    struct list_head    entry;
};
```

等待队列链表中的每个元素代表一个睡眠进程，该进程等待某一事件的发生

如果多个进程正在等待互斥访问某一个要释放的资源，仅唤醒等待队列中一个进程才有意义

这个进程占有资源，其他进程继续睡眠

因此，有两种睡眠进程：互斥进程（元素的 flags 为 1）和 非互斥进程（flags 为 0）

等待访问临界资源的进程就是互斥进程的典型例子

等待队列元素的 func 字段表示等待队列中的睡眠进程应该用什么方式来唤醒

### 等待队列的操作

```c
// file: include/linux/wait.h

static inline void init_waitqueue_entry(struct wait_queue_entry *wq_entry, struct task_struct *p)
{
    wq_entry->flags        = 0;
    wq_entry->private      = p;
    wq_entry->func         = default_wake_function;
}
```

非互斥进程 p 由 default_wake_function 唤醒

```c
// file: include/linux/wait.h

typedef int (*wait_queue_func_t)(struct wait_queue_entry *wq_entry, unsigned mode, int flags, void *key);

int default_wake_function(struct wait_queue_entry *wq_entry, unsigned mode, int flags, void *key);
```

```c
// file: kernel/sched/core.c

int default_wake_function(wait_queue_entry_t *curr, unsigned mode, int wake_flags,
              void *key)
{
    WARN_ON_ONCE(IS_ENABLED(CONFIG_SCHED_DEBUG) && wake_flags & ~(WF_SYNC|WF_CURRENT_CPU));
    return try_to_wake_up(curr->private, mode, wake_flags);
}
EXPORT_SYMBOL(default_wake_function);
```

一旦定义了一个元素，必须把它插入等待队列

add_wait_queue 把一个非互斥进程插入等待队列的第一个位置

还有一些其他的函数：add_wait_queue_exclusive 等

内核通过 wake_up 系列的宏唤醒等待队列中的进程并把状态置为 TASK_RUNNING

对于 wake_up 系列的宏：

* 名字中有 nr 的唤醒给定数量的进程

* 名字中有 all 的唤醒所有进程

* 名字中不含 nr 也不含 all 的只唤醒一个进程

所有的非互斥进程总是在双向链表的开始位置，所有的互斥进程在双向链表的尾部

函数总是先唤醒非互斥进程然后再唤醒互斥进程

### 进程资源限制

每个进程都有一组相关的资源限制，避免用户过度使用系统资源

## 进程切换（Process Switch）

为了控制进程执行，内核必须有能力挂起正在 CPU 上运行的进程，并恢复以前挂起的进程

这种行为称为进程切换、任务切换或上下文切换

### 硬件上下文

尽管每个进程有属于自己的地址空间，但所有进程必须共享 CPU 寄存器

进程恢复执行前必须装入寄存器的数据称为硬件上下文

硬件上下文的一部分存放在进程描述符中，其余部分放在内核态的栈上

进程切换需要保存换出的进程的硬件上下文，并使用换入的进程的硬件上下文

进程切换只发生在内核态

### Task State Segment (任务状态段)

### 执行进程切换

进程切换由两步组成：

* 切换页全局目录以安装一个新的地址空间

* 切换内核态的栈和硬件上下文

### 保存和加载 FPU, MMX 及 XMM 寄存器

从 486 开始，浮点单元 (FPU) 已被集成到 CPU 中

x86 处理器并不在 TSS 中自动保存 FPU, MMX 及 XMM 寄存器

cr0 寄存器中的 TS 标志使得内核只在真正需要时才保存和恢复这些浮点寄存器

内核只在有限的场合使用浮点单元，如计算校验和函数的时候

### clone, fork 及 vfork 系统调用

Linux 中的轻量级进程是由 clone 函数创建的

clone 是在 C 库中定义的一个封装函数，它调用 sys_clone 服务例程

```c
// file: include/linux/syscalls.h

#ifdef CONFIG_CLONE_BACKWARDS
asmlinkage long sys_clone(unsigned long, unsigned long, int __user *, unsigned long,
           int __user *);
#else
#ifdef CONFIG_CLONE_BACKWARDS3
asmlinkage long sys_clone(unsigned long, unsigned long, int, int __user *,
              int __user *, unsigned long);
#else
asmlinkage long sys_clone(unsigned long, unsigned long, int __user *,
           int __user *, unsigned long);
#endif
#endif
```

copy_process 创建进程描述符以及子进程执行所需要的其他所有数据结构

```c
// file: include/linux/sched/task.h

struct task_struct *copy_process(struct pid *pid, int trace, int node,
                 struct kernel_clone_args *args);
```

```c
// file: arch/x86/kernel/process.c

int copy_thread(struct task_struct *p, const struct kernel_clone_args *args)
```

### 内核线程

在 Linux 中，内核线程只运行在内核态

```c
// file: kernel/fork.c

/*
 * Create a kernel thread.
 */
pid_t kernel_thread(int (*fn)(void *), void *arg, const char *name,
            unsigned long flags)
{
    struct kernel_clone_args args = {
        .flags          = ((lower_32_bits(flags) | CLONE_VM |
                            CLONE_UNTRACED) & ~CSIGNAL),
        .exit_signal    = (lower_32_bits(flags) & CSIGNAL),
        .fn             = fn,
        .fn_arg         = arg,
        .name           = name,
        .kthread        = 1,
    };

    return kernel_clone(&args);
}


/*
 * Create a user mode thread.
 */
pid_t user_mode_thread(int (*fn)(void *), void *arg, unsigned long flags)
{
    struct kernel_clone_args args = {
        .flags          = ((lower_32_bits(flags) | CLONE_VM |
                            CLONE_UNTRACED) & ~CSIGNAL),
        .exit_signal    = (lower_32_bits(flags) & CSIGNAL),
        .fn             = fn,
        .fn_arg         = arg,
    };

    return kernel_clone(&args);
}


/*
 *  Ok, this is the main fork-routine.
 *
 * It copies the process, and if successful kick-starts
 * it and waits for it to finish using the VM if required.
 *
 * args->exit_signal is expected to be checked for sanity by the caller.
 */
pid_t kernel_clone(struct kernel_clone_args *args)
```

### 进程 0

所有进程的祖先叫做进程 0，idle 进程 (swapper 进程)

它是在 Linux 的初始化阶段创建的一个内核线程，使用静态分配的数据结构

### 进程 1

进程 1 的内核线程叫做 init 进程

在系统关闭之前，init 进程一直存活，监控在操作系统外层执行的所有进程的活动

## 撤销进程

当进程终止时，内核必须释放进程所拥有的资源，包括内存、打开的文件、信号量等

### 进程终止

所有进程的终止都是由 do_exit 函数处理的，它从内核数据结构中删除进程的大部分引用

```c
// file: kernel/exit.c

void __noreturn do_exit(long code)
```


********

2024 年 11 月 7 日

```c
// file: kernel/fork.c

// sys_fork
SYSCALL_DEFINE0(fork)
{
#ifdef CONFIG_MMU
    struct kernel_clone_args args = {
        .exit_signal = SIGCHLD,
    };

    return kernel_clone(&args);
#else
    /* can not support in nommu mode */
    return -EINVAL;
#endif
}

// sys_vfork
SYSCALL_DEFINE0(vfork)
{
    struct kernel_clone_args args = {
        .flags          = CLONE_VFORK | CLONE_VM,
        .exit_signal    = SIGCHLD,
    };

    return kernel_clone(&args);
}

// sys_clone has many prototypes, annoying!!
SYSCALL_DEFINEx(clone, ...)
{
    struct kernel_clone_args args = {
        .flags          = (lower_32_bits(clone_flags) & ~CSIGNAL),
        .pidfd          = parent_tidptr,
        .child_tid      = child_tidptr,
        .parent_tid     = parent_tidptr,
        .exit_signal    = (lower_32_bits(clone_flags) & CSIGNAL),
        .stack          = newsp,
        .tls            = tls,
    };

    return kernel_clone(&args);
}

// header file: include/linux/sched/task.h
struct kernel_clone_args {
    u64 flags;
    int __user *pidfd;
    int __user *child_tid;
    int __user *parent_tid;
    const char *name;
    int exit_signal;
    u32 kthread:1;          // bit-field
    u32 io_thread:1;
    u32 user_worker:1;
    u32 no_files:1;
    unsigned long stack;
    unsigned long stack_size;
    unsigned long tls;
    pid_t *set_tid;
    /* Number of elements in *set_tid */
    size_t set_tid_size;
    int cgroup;
    int idle;
    int (*fn)(void *);
    void *fn_arg;
    struct cgroup *cgrp;
    struct css_set *cset;
};

// header file: include/uapi/linux/sched.h

/*
 * cloning flags:
 */
#define CSIGNAL                 0x000000ff    /* signal mask to be sent at exit */
#define CLONE_VM                0x00000100    /* set if VM shared between processes */
#define CLONE_FS                0x00000200    /* set if fs info shared between processes */
#define CLONE_FILES             0x00000400    /* set if open files shared between processes */
#define CLONE_SIGHAND           0x00000800    /* set if signal handlers and blocked signals shared */
#define CLONE_PIDFD             0x00001000    /* set if a pidfd should be placed in parent */
#define CLONE_PTRACE            0x00002000    /* set if we want to let tracing continue on the child too */
#define CLONE_VFORK             0x00004000    /* set if the parent wants the child to wake it up on mm_release */
#define CLONE_PARENT            0x00008000    /* set if we want to have the same parent as the cloner */
#define CLONE_THREAD            0x00010000    /* Same thread group? */
#define CLONE_NEWNS             0x00020000    /* New mount namespace group */
#define CLONE_SYSVSEM           0x00040000    /* share system V SEM_UNDO semantics */
#define CLONE_SETTLS            0x00080000    /* create a new TLS for the child */
#define CLONE_PARENT_SETTID     0x00100000    /* set the TID in the parent */
#define CLONE_CHILD_CLEARTID    0x00200000    /* clear the TID in the child */
#define CLONE_DETACHED          0x00400000    /* Unused, ignored */
#define CLONE_UNTRACED          0x00800000    /* set if the tracing process can't force CLONE_PTRACE on this clone */
#define CLONE_CHILD_SETTID      0x01000000    /* set the TID in the child */
#define CLONE_NEWCGROUP         0x02000000    /* New cgroup namespace */
#define CLONE_NEWUTS            0x04000000    /* New utsname namespace */
#define CLONE_NEWIPC            0x08000000    /* New ipc namespace */
#define CLONE_NEWUSER           0x10000000    /* New user namespace */
#define CLONE_NEWPID            0x20000000    /* New pid namespace */
#define CLONE_NEWNET            0x40000000    /* New network namespace */
#define CLONE_IO                0x80000000    /* Clone io context */
```

各个 macro 的含义可以查看 [Linux manual page](https://www.man7.org/linux/man-pages/man2/clone.2.html)

`CLONE_VM` 的作用是让父进程和子进程共享同一个内存地址空间

`CLONE_VFORK` 使得子进程在执行 execve 或 exit 之前，父进程会被阻塞。
