# 第 5 章 内核同步

## 内核抢占

抢占内核的主要特点是：一个在内核态运行的进程，可能在执行内核函数期间被另外一个进程取代

只有当内核正在执行异常处理程序 (尤其是系统调用)，而且内核抢占没有被显式地禁用时，才可能抢占内核

## 什么时候同步是必需的 (When Synchronization Is Necessary)

## 同步原语

表 5.2 内核中使用的不同种类的同步技术

|     Technique             |                  Description                                  |
|     ---------             |                    --------                                   |
|     Per-CPU variables     |  Duplicate a data structure among the CPUs                    |
|      Atomic operation     |  Atomic read-modify-write instruction to a counter            |
|      Memory barrier       |  Avoid instruction reordering                                 |
|       Spin lock           |  Lock with busy wait                                          |
|        Semaphore          |  Lock with blocking wait (sleep)                              |
|         Seqlocks          |  Lock based on an access counter                              |
| Local interrupt disabling |  Forbid interrupt handling on a single CPU                    |
|  Local softirq disabling  |  Forbid deferrable function handling on a single CPU          |
|  Read-copy-update (RCU)   |  Lock-free access to shared data structures through pointers  |

### Per-CPU Variables

### Atomic Operations

操作码前缀是 lock 字节 (0xf0) 的 "读 -- 修改 -- 写" 汇编语言指令即使在多处理器系统中也是原子的

当控制单元检测到这个前缀时，就锁定内存总线，直到这条指令执行完成为止

因此，当加锁的指令执行时，其他处理器不能访问这个内存单元

Linux 内核提供了 `atomic_t` 类型和一些专门的操作，这些函数和宏会当作原子的汇编语言指令来使用

在多处理器系统中，每条这样的指令都有一个 lock 字节的前缀

在 Intel 64 and IA-32 Architectures Software Developer's Manual 的 Volume 2A 中有相关的描述：

> 2.1 Instruction Format for Protected Mode, Real-Address Mode, and Virtual-8086 Mode
>
> 2.1.1 Instruction Prefixes
>
> Instruction prefixes are divided into four groups, each with a set of allowable prefix codes.
>
> LOCK prefix is encoded using F0H.
>
> The LOCK prefix (F0H) forces an operation that ensures exclusive use of shared memory in a multiprocessor environment.
>
> See “LOCK—Assert LOCK# Signal Prefix” in Chapter 3, “Instruction Set Reference, A-L,” for a description of this prefix.
>
> LOCK—Assert LOCK# Signal Prefix

```c
// header file: include/linux/atomic/atomic-instrumented.h

static __always_inline int
atomic_read(const atomic_t *v)
{
    instrument_atomic_read(v, sizeof(*v));
    return raw_atomic_read(v);
}

static __always_inline int
raw_atomic_read(const atomic_t *v)
{
    return arch_atomic_read(v);
}
```

### Optimization and Memory Barriers

编译器可能重新安排汇编指令来使寄存器以最优的方式使用

当处理同步时，必须避免指令重新排序

所有的同步原语起到优化和内存屏障的作用

优化屏障 (optimization barrier) 保证编译程序不会混淆原语操作之前的汇编指令和原语操作之后的汇编指令

在 Linux 中，优化屏障就是 `barrier()` 宏

内存屏障 (memory barrier) 保证 "在原语之后的操作开始执行之前，原语之前的操作已经完成"

在 x86 处理器中，下列汇编指令起到内存屏障的作用：

* 对 I/O 端口进行操作的所有指令

* 有 lock 前缀的所有指令 (前面的原子操作指令)

* 写控制寄存器、系统寄存器或调试寄存器的所有指令

* 汇编指令 lfence, sfence, mfence

* 少数专门的汇编语言指令

> LFENCE: Load Fence, Performs a serializing operation on all load-from-memory instructions
>
> MFENCE: Memory Fence,  Performs a serializing operation on all load-from-memory and store-to-memory instructions
>
> SFENCE: Store Fence, Orders processor execution relative to all memory stores prior to the SFENCE instruction

Linux 使用六个内存屏障原语，参考以下头文件：

[memory barrier](https://elixir.bootlin.com/linux/v6.10.6/source/include/asm-generic/barrier.h#L103)

内存屏障的实现依赖于 CPU

### Spin Locks (自旋锁)

等待自旋锁释放的进程有可能被更高优先级的进程替代

由自旋锁保护的每个临界区都是禁止内核抢占的

在 Linux 中，自旋锁用 `spinlock_t` 结构表示

#### Read/Write Spin Locks (读/写自旋锁)

读/写自旋锁是 `rwlock_t` 结构，参考以下头文件：

[rwlock_types.h](https://elixir.bootlin.com/linux/v6.10.6/source/include/linux/rwlock_types.h#L34)

### Seqlocks (顺序锁)

Linux 2.6 中引入了顺序锁，它与读/写自旋锁非常相似，但写者拥有较高的优先级

顺序锁是 `seqlock_t` 结构，如下：

```c
// header file: include/linux/seqlock_types.h

typedef struct {
    /*
     * Make sure that readers don't starve writers on PREEMPT_RT: use
     * seqcount_spinlock_t instead of seqcount_t. Check __SEQ_LOCK().
     */
    seqcount_spinlock_t seqcount;
    spinlock_t lock;
} seqlock_t;
```

顺序锁中的 writer 永远不会等待 (除非有另一个 writer 正在写)，但有时候 reader 必须反复多次读相同的数据直到获得有效的副本

每个 reader 都必须在读数据前后两次读顺序计数器，并检查两次读到的值是否相同

如果不相同，说明 writer 已经开始写并增加了顺序计数器，因此说明 reader 刚读到的数据是无效的

reader 的临界区代码应该简短，writer 应该不常获取顺序锁，否则，反复的读访问会引起严重的开销

### Read-Copy Update (RCU)

RCU 具有如下特点：

* RCU 只保护被动态分配并通过指针引用的数据结构

* 在被 RCU 保护的临界区中，任何内核控制路径都不能睡眠

RCU 是 Linux 2.6 中新加的功能，用在网络层和虚拟文件系统中

### Semaphores

只有可以睡眠的函数才能获取内核信号量，中断处理程序和可延迟函数都不能使用内核信号量

```c
// header file: include/linux/semaphore.h

/* Please don't access any members of this structure directly */
struct semaphore {
    raw_spinlock_t        lock;
    unsigned int          count;
    struct list_head      wait_list;
};
```

```c
// header file: include/linux/types.h

struct list_head {
    struct list_head *next, *prev;
};
```

当进程希望释放内核信号量锁时，就调用 `up()` 函数

当进程希望获取内核信号量锁时，就调用 `down()` 函数

`__down()` 函数把当前进程的状态从 `TASK_RUNNING` 改变为 `TASK_UNINTERRUPTIBLE`，并把进程放在信号量的等待队列

`__down()` 函数的主要任务是挂起当前进程，直到信号量被释放

`down_interruptible()` 函数广泛地用在设备驱动程序中，在返回值是 `-EINTR` 时，设备驱动程序可以放弃 I/O 操作

```c
// header file: include/uapi/asm-generic/errno-base.h

#define    EPERM          1    /* Operation not permitted */
#define    ENOENT         2    /* No such file or directory */
#define    ESRCH          3    /* No such process */
#define    EINTR          4    /* Interrupted system call */
#define    EIO            5    /* I/O error */
#define    ENXIO          6    /* No such device or address */
#define    E2BIG          7    /* Argument list too long */
#define    ENOEXEC        8    /* Exec format error */
#define    EBADF          9    /* Bad file number */
#define    ECHILD        10    /* No child processes */
#define    EAGAIN        11    /* Try again */
#define    ENOMEM        12    /* Out of memory */
#define    EACCES        13    /* Permission denied */
#define    EFAULT        14    /* Bad address */
#define    ENOTBLK       15    /* Block device required */
#define    EBUSY         16    /* Device or resource busy */
#define    EEXIST        17    /* File exists */
#define    EXDEV         18    /* Cross-device link */
#define    ENODEV        19    /* No such device */
#define    ENOTDIR       20    /* Not a directory */
#define    EISDIR        21    /* Is a directory */
#define    EINVAL        22    /* Invalid argument */
#define    ENFILE        23    /* File table overflow */
#define    EMFILE        24    /* Too many open files */
#define    ENOTTY        25    /* Not a typewriter */
#define    ETXTBSY       26    /* Text file busy */
#define    EFBIG         27    /* File too large */
#define    ENOSPC        28    /* No space left on device */
#define    ESPIPE        29    /* Illegal seek */
#define    EROFS         30    /* Read-only file system */
#define    EMLINK        31    /* Too many links */
#define    EPIPE         32    /* Broken pipe */
#define    EDOM          33    /* Math argument out of domain of func */
#define    ERANGE        34    /* Math result not representable */
```

```c
// header file: include/linux/errno.h

#define ERESTARTSYS       512
#define ERESTARTNOINTR    513
#define ERESTARTNOHAND    514    /* restart if no handler.. */
#define ENOIOCTLCMD       515    /* No ioctl command */
#define ERESTART_RESTARTBLOCK 516 /* restart by calling sys_restart_syscall */
#define EPROBE_DEFER      517    /* Driver requests probe retry */
#define EOPENSTALE        518    /* open found a stale dentry */
#define ENOPARAM          519    /* Parameter not supported */
```

I guess `ERESTARTSYS` means "restart syscall"

### 读/写信号量

读/写信号量是由 `rw_semaphore` 结构描述的

### 禁止本地中断

`local_irq_disable()` 使用 cli 汇编指令关闭本地 CPU 上的中断

`local_irq_enable()` 使用 sti 汇编指令打开被关闭的中断

汇编指令 cli 和 sti 分别清除和设置 eflags 控制寄存器的 IF 标志

当内核进入临界区时，通过把 eflags 寄存器的 IF 标志清 0 关闭中断

中断可以以嵌套的方式执行，在这种情况下，控制路径必须保存先前赋给该标志的值，并在执行结束时恢复它

`local_irq_save()` 把 eflags 寄存器的内容拷贝到一个局部变量中，随后用 cli 汇编指令把 IF 标志清 0

`local_irq_restore()` 恢复 eflags 原来的内容

## 对内核数据结构的同步访问

为了使 I/O 吞吐量最大化，应该使中断禁止保持在很短的时间

为了有效地利用 CPU，应该尽可能避免使用基于自旋锁的同步原语

## 在自旋锁、信号量和中断禁止之间选择

只要内核控制路径获得自旋锁 (还有读/写锁、顺序锁或 RCU 的 "读锁")，就禁用本地中断或本地软中断、自动禁用内核抢占

信号量的工作方式在单处理器和多处理器系统上完全相同

### The Big Kernel Lock (大内核锁)

在早期的 Linux 版本中，大内核锁被广泛使用。在 2.0 版本中，这个锁是相对粗粒度的自旋锁，确保每次只有一个进程能运行在内核态
