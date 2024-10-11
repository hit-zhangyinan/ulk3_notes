# 第 11 章  信号

## 信号的作用

使用信号的两个主要目的是：

* 让进程知道已经发生了一个特定的事件

* 强迫进程执行它自己代码中的信号处理程序

```c
// header file: arch/x86/include/uapi/asm/signal.h

#define SIGHUP           1
#define SIGINT           2
#define SIGQUIT          3
#define SIGILL           4
#define SIGTRAP          5
#define SIGABRT          6
#define SIGIOT           6
#define SIGBUS           7
#define SIGFPE           8
#define SIGKILL          9
#define SIGUSR1         10
#define SIGSEGV         11
#define SIGUSR2         12
#define SIGPIPE         13
#define SIGALRM         14
#define SIGTERM         15
#define SIGSTKFLT       16
#define SIGCHLD         17
#define SIGCONT         18
#define SIGSTOP         19
#define SIGTSTP         20
#define SIGTTIN         21
#define SIGTTOU         22
#define SIGURG          23
#define SIGXCPU         24
#define SIGXFSZ         25
#define SIGVTALRM       26
#define SIGPROF         27
#define SIGWINCH        28
#define SIGIO           29
#define SIGPOLL         SIGIO
```

POSIX 标准还引入了一类新的信号，叫做实时信号，在 Linux 中它们的编码范围是 32 ~ 64

尽管 Linux 内核并不使用实时信号，它还是通过几个特定的系统调用完全实现了 POSIX 标准

发送给非运行进程的信号必须由内核保存，直到进程恢复执行

内核区分信号传递的两个不同阶段：

* 信号产生：内核更新目标进程的数据结构以表示一个新信号已被发送

* 信号传递：内核强迫目标进程通过以下方式对信号做出反应：

  或改变目标进程的执行状态，或开始执行一个特定的信号处理程序，或两者都是

只要信号被传递出去，进程描述符中有关这个信号的所有信息都被取消

已经产生但还没有传递的信号称为挂起信号 (pending signal)

> pending: about to happen or waiting to happen
>
> pending: going to happen soon

尽管信号的表示比较直观，但内核的实现相当复杂，内核必须：

* 记住每个进程阻塞哪些信号

* 当从内核态切换到用户态时，对任何一个进程都要检查是否有一个信号已到达。

  这几乎在每个定时中断时都发生

* 确定是否可以忽略信号。这发生在下列所有的条件都满足时：

  目标进程没有被另一个进程跟踪

  信号没有被目标进程阻塞

  信号被目标进程忽略

* Handle the signal, which may require switching the process

  to a handler function at any point during its execution and

  restoring the original execution context after the function returns.

### 传递信号之前所执行的操作

进程以三种方式对一个信号做出应答：

* 显式地忽略信号

* 执行与信号相关的默认操作

* 通过调用相应的信号处理函数捕获信号

对一个信号的阻塞和忽略是不同的：

只要信号被阻塞，它就不被传递，只有在信号解除阻塞后才传递它

而一个被忽略的信号总是被传递，只是没有进一步的操作

SIGKILL 和 SIGSTOP 信号不可以被显式忽略、捕获或阻塞

SIGKILL 和 SIGSTOP 允许具有特权的用户分别终止并停止任何进程，但有两个例外：

不可能给进程 0 (swapper) 发送信号，而发送给进程 1 (init) 的信号在捕获到它们之前也总被丢弃

因此，进程 0 永不死亡，进程 1 只有当 init 程序终止时才死亡

### POSIX 信号和多线程应用

POSIX 1003.1 标准对多线程应用的信号处理有一些严格的要求：

* 信号处理程序必须在多线程应用的所有线程之间共享；不过，每个线程必须有自己的挂起信号掩码和阻塞信号掩码

* POSIX 库函数 kill() 和 sigqueue() 必须向所有的多线程应用而不是某个特殊的线程发送信号

* 每个发送给多线程应用的信号仅传送给一个线程，这个线程是由内核在从不会阻塞该信号的线程中随意选择出来的

* 如果向多线程应用发送了一个致命的信号，那么内核将杀死该应用的所有线程，而不仅是杀死接收信号的那个线程

### 与信号相关的数据结构

```c
// header file: include/linux/sched.h
struct task_struct {
    ...
    /* Signal handlers: */
    struct signal_struct               *signal;
    struct sighand_struct __rcu        *sighand;
    sigset_t                           blocked;
    sigset_t                           real_blocked;
    /* Restored if set_restore_sigmask() was used: */
    sigset_t                           saved_sigmask;
    struct sigpending                  pending;
    unsigned long                      sas_ss_sp;
    size_t                             sas_ss_size;
    unsigned int                       sas_ss_flags;
    ...
};

// header file: include/uapi/asm-generic/signal.h
#define _NSIG           64
#define _NSIG_BPW       __BITS_PER_LONG
#define _NSIG_WORDS     (_NSIG / _NSIG_BPW)
typedef struct {
    unsigned long sig[_NSIG_WORDS];
} sigset_t;

// header file: include/linux/sched/signal.h
struct sighand_struct {
    spinlock_t            siglock;
    refcount_t            count;
    wait_queue_head_t     signalfd_wqh;
    struct k_sigaction    action[_NSIG];
};

// header file: include/linux/signal_types.h
struct sigpending {
    struct list_head list;
    sigset_t signal;
};
```

`blocked` 字段存放进程当前屏蔽的信号

因为没有值为 0 的信号，因此信号的编号对应 `sigset_t` 类型变量中的相应位下标加 1

#### 信号描述符和信号处理程序描述符

进程描述符的 signal 字段指向信号描述符 (signal descriptor)，这是一个 `signal_struct` 类型的结构体

信号描述符被属于同一线程组的所有线程共享，对属于同一线程组的每个线程而言，信号描述符中的字段必须都是相同的

除了信号描述符以外，每个进程还引用一个信号处理程序描述符 (signal handler descriptor)，

这是一个 `sighand_struct` 类型的结构体，用来描述每个信号必须怎样被线程组处理

#### `sigaction` 数据结构

```c
// header file: include/linux/signal_types.h
struct k_sigaction {
    struct sigaction sa;
#ifdef __ARCH_HAS_KA_RESTORER
    __sigrestore_t ka_restorer;
#endif
};

struct sigaction {
    ...
    __sighandler_t    sa_handler;
    ...
    unsigned int      sa_flags;
    ...
    sigset_t          sa_mask;
    ...
};

// header file: include/uapi/asm-generic/signal-defs.h
typedef void __signalfn_t(int);
typedef __signalfn_t __user *__sighandler_t;

// equals to

typedef void (*__sighandler_t)(int);

#define SIG_DFL    ((__force __sighandler_t)0)    /* default signal handling */
#define SIG_IGN    ((__force __sighandler_t)1)    /* ignore signal */
#define SIG_ERR    ((__force __sighandler_t)-1)    /* error return from signal */
```

`k_sigaction` 结构既包含对用户态进程隐藏的特性，也包含 `sigaction` 结构，

`sigaction` 结构保存了用户态进程能看见的所有特性

在 x86 平台上，信号的所有特性对用户态的进程都是可见的

#### The pending signal queues (挂起信号队列)

in order to keep track of what signals are currently pending, the kernel

associates two pending signal queues to each process:

* The shared pending signal queue, rooted at the shared_pending field

  of the signal descriptor, stores the pending signals of the whole thread group.

* The private pending signal queue, rooted at the pending field of the

  process descriptor, stores the pending signals of the specific (lightweight) process.

A pending signal queue consists of a sigpending data structure

```c
struct sigqueue {
    struct list_head list;
    int flags;
    kernel_siginfo_t info;
    struct ucounts *ucounts;
};

typedef struct kernel_siginfo {
    __SIGINFO;
} kernel_siginfo_t;

#ifndef __ARCH_HAS_SWAPPED_SIGINFO
#define __SIGINFO            \
struct {                     \
    int si_signo;            \
    int si_errno;            \
    int si_code;             \
    union __sifields _sifields;    \
}
#else
#define __SIGINFO            \
struct {                     \
    int si_signo;            \
    int si_code;             \
    int si_errno;            \
    union __sifields _sifields;    \
}
#endif /* __ARCH_HAS_SWAPPED_SIGINFO */

typedef struct siginfo {
    union {
        __SIGINFO;
        int _si_pad[SI_MAX_SIZE/sizeof(int)];
    };
} __ARCH_SI_ATTRIBUTES siginfo_t;

/*
 * si_code values
 * Digital reserves positive values for kernel-generated signals.
 */
#define SI_USER         0        /* sent by kill, sigsend, raise */
#define SI_KERNEL    0x80        /* sent by the kernel from somewhere */
#define SI_QUEUE       -1        /* sent by sigqueue */
#define SI_TIMER       -2        /* sent by timer expiration */
#define SI_MESGQ       -3        /* sent by real time mesq state change */
#define SI_ASYNCIO     -4        /* sent by AIO completion */
#define SI_SIGIO       -5        /* sent by queued SIGIO */
#define SI_TKILL       -6        /* sent by tkill system call */
#define SI_DETHREAD    -7        /* sent by execve() killing subsidiary threads */
#define SI_ASYNCNL    -60        /* sent by glibc async name lookup completion */
```

### 在信号数据结构上的操作

内核使用几个函数和宏来处理信号

```c
// header file: include/linux/sched/signal.h
static inline int signal_pending(struct task_struct *p)
{
    /*
     * TIF_NOTIFY_SIGNAL isn't really a signal, but it requires the same
     * behavior in terms of ensuring that we break out of wait loops
     * so that notify signal callbacks can be processed.
     */
    if (unlikely(test_tsk_thread_flag(p, TIF_NOTIFY_SIGNAL)))
        return 1;
    return task_sigpending(p);
}

static inline int task_sigpending(struct task_struct *p)
{
    return unlikely(test_tsk_thread_flag(p,TIF_SIGPENDING));
}

// header file: include/linux/sched.h
static inline int test_tsk_thread_flag(struct task_struct *tsk, int flag)
{
    return test_ti_thread_flag(task_thread_info(tsk), flag);
}

// header file: include/linux/thread_info.h
static inline int test_ti_thread_flag(struct thread_info *ti, int flag)
{
    return test_bit(flag, (unsigned long *)&ti->flags);
}

// header file: include/linux/bitops.h
#define test_bit(nr, addr)        bitop(_test_bit, nr, addr)

// header file: arch/x86/include/asm/thread_info.h
#define TIF_SIGPENDING        2    /* signal pending */
#define TIF_NOTIFY_SIGNAL    17    /* signal notifications exist */
```

## 产生信号

内核通过调用下列函数来产生信号

```c
// file: kernel/signal.c

int send_sig(int sig, struct task_struct *p, int priv)
{
    return send_sig_info(sig, __si_special(priv), p);
}
EXPORT_SYMBOL(send_sig);

#define __si_special(priv) \
    ((priv) ? SEND_SIG_PRIV : SEND_SIG_NOINFO)

int send_sig_info(int sig, struct kernel_siginfo *info, struct task_struct *p)
{
    /*
     * Make sure legacy kernel users don't send in bad values
     * (normal paths check this in check_kill_permission).
     */
    if (!valid_signal(sig))
        return -EINVAL;

    return do_send_sig_info(sig, info, p, PIDTYPE_PID);
}
EXPORT_SYMBOL(send_sig_info);

enum pid_type {
    PIDTYPE_PID,
    PIDTYPE_TGID,
    PIDTYPE_PGID,
    PIDTYPE_SID,
    PIDTYPE_MAX,
};

int do_send_sig_info(int sig, struct kernel_siginfo *info, struct task_struct *p,
            enum pid_type type)
{
    unsigned long flags;
    int ret = -ESRCH;

    if (lock_task_sighand(p, &flags)) {
        ret = send_signal_locked(sig, info, p, type);
        unlock_task_sighand(p, &flags);
    }

    return ret;
}

int send_signal_locked(int sig, struct kernel_siginfo *info,
               struct task_struct *t, enum pid_type type)
{
    // body
    return __send_signal_locked(sig, info, t, type, force);
}

static int __send_signal_locked(int sig, struct kernel_siginfo *info,
                struct task_struct *t, enum pid_type type, bool force)
{ }
```

## 传递信号

```c
/*
 * Dequeue a signal and return the element to the caller, which is
 * expected to free it.
 *
 * All callers have to hold the siglock.
 */
int dequeue_signal(struct task_struct *tsk, sigset_t *mask,
            kernel_siginfo_t *info, enum pid_type *type)
{ }
```

### 执行信号的默认操作

```c
// file: arch/x86/kernel/signal.c

/*
 * Note that 'init' is a special process: it doesn't get signals it doesn't
 * want to handle. Thus you cannot kill init even with a SIGKILL even by
 * mistake.
 */
void arch_do_signal_or_restart(struct pt_regs *regs)
{
    struct ksignal ksig;

    if (get_signal(&ksig)) {
        /* Whee! Actually deliver the signal.  */
        handle_signal(&ksig, regs);
        return;
    }

    /* Did we come from a system call? */
    if (syscall_get_nr(current, regs) != -1) {
        /* Restart the system call - no handlers present */
        switch (syscall_get_error(current, regs)) {
        case -ERESTARTNOHAND:
        case -ERESTARTSYS:
        case -ERESTARTNOINTR:
            regs->ax = regs->orig_ax;
            regs->ip -= 2;
            break;

        case -ERESTART_RESTARTBLOCK:
            regs->ax = get_nr_restart_syscall(regs);
            regs->ip -= 2;
            break;
        }
    }

    /*
     * If there's no signal to deliver, we just put the saved sigmask
     * back.
     */
    restore_saved_sigmask();
}

bool get_signal(struct ksignal *ksig)
{ }

static void handle_signal(struct ksignal *ksig, struct pt_regs *regs)
{
    failed = (setup_rt_frame(ksig, regs) < 0);
}
```

### 捕获信号

信号处理程序是用户态进程所定义的函数，并包含在用户态的代码段中

`handle_signal` 函数运行在内核态，而信号处理程序运行在用户态

```c
// file: arch/x86/kernel/signal_64.c

/*
 * Do a signal return; undo the signal stack.
 */
SYSCALL_DEFINE0(rt_sigreturn)
{
    if (!restore_sigcontext(regs, &frame->uc.uc_mcontext, uc_flags))
        goto badframe;

badframe:
    signal_fault(regs, frame, "rt_sigreturn");
    return 0;
}

static bool restore_sigcontext(struct pt_regs *regs,
                   struct sigcontext __user *usc,
                   unsigned long uc_flags)
{ }
```

#### Setting up the frame

```c
// header file: arch/x86/um/signal.c

struct sigframe
{
    char __user *pretcode;
    int sig;
    struct sigcontext sc;
    struct _xstate fpstate;
    unsigned long extramask[_NSIG_WORDS-1];
    char retcode[8];
};

struct rt_sigframe
{
    char __user *pretcode;
    int sig;
    struct siginfo __user *pinfo;
    void __user *puc;
    struct siginfo info;
    struct ucontext uc;
    struct _xstate fpstate;
    char retcode[8];
};

// header file: arch/x86/include/uapi/asm/sigcontext.h

# ifdef __i386__
struct sigcontext {
    __u16                gs, __gsh;
    __u16                fs, __fsh;
    __u16                es, __esh;
    __u16                ds, __dsh;
    __u32                edi;
    __u32                esi;
    __u32                ebp;
    __u32                esp;
    __u32                ebx;
    __u32                edx;
    __u32                ecx;
    __u32                eax;
    struct _fpstate __user        *fpstate;
    // some other registers
};
# else /* __x86_64__: */
struct sigcontext {
    __u64                r8;
    __u64                r9;
    __u64                r10;
    __u64                r11;
    __u64                r12;
    __u64                r13;
    __u64                r14;
    __u64                r15;
    __u64                rdi;
    __u64                rsi;
    __u64                rbp;
    __u64                rbx;
    __u64                rdx;
    __u64                rax;
    __u64                rcx;
    __u64                rsp;
    __u64                rip;
    // some other registers
    struct _fpstate __user        *fpstate;    /* Zero when no FPU context */
#  ifdef __ILP32__
    __u32                __fpstate_pad;
#  endif
    __u64                reserved1[8];
};
# endif /* __x86_64__ */
```

### 系统调用的重新执行

如果进程处于 TASK_INTERRUPTIBLE 状态，并且某个进程向它发送了一个信号，

那么，内核不完成系统调用就把进程置为 TASK_RUNNING 状态，当切换回用户态时信号被传递给进程

Error codes and their impact on system call execution

|  Signal Action  |    EINTR    | ERESTARTSYS |
| :-------------: | :---------: | :---------: |
|    Default      |  Terminate  |  Reexecute  |
|    Ignore       |  Terminate  |  Reexecute  |
|    Catch        |  Terminate  |   Depends   |

* Terminate:

  不会自动重新执行系统调用，进程在 `int $0x80` 或者 `sysenter` 指令紧接着的那条指令处

  将恢复它在用户态的执行，这时 eax 寄存器包含的值为 -EINTR

* Reexecute:

  内核强迫用户态进程把系统调用号重新装入 eax 寄存器，并重新执行 `int $0x80` 或者 `sysenter` 指令

  进程意识不到这种重新执行，因此出错码也不传递给进程

* Depends:

  只有被传递信号的 SA_RESTART 标志被设置，才重新执行系统调用

  否则，系统调用以 -EINTR 出错码结束

```c
// header file: arch/x86/include/uapi/asm/ptrace.h

/* this struct defines the way the registers are stored on the
   stack during a system call. */

#ifndef __KERNEL__

struct pt_regs {
    long ebx;
    long ecx;
    long edx;
    long esi;
    long edi;
    long ebp;
    long eax;
    int  xds;
    int  xes;
    int  xfs;
    int  xgs;
    long orig_eax;
    long eip;
    int  xcs;
    long eflags;
    long esp;
    int  xss;
};

#endif /* __KERNEL__ */
```

## 与信号处理相关的系统调用

```c
// header file: include/linux/syscalls.h

asmlinkage long sys_kill(pid_t pid, int sig);
asmlinkage long sys_tkill(pid_t pid, int sig);
asmlinkage long sys_tgkill(pid_t tgid, pid_t pid, int sig);

// file: kernel/signal.c

/**
 *  sys_kill - send a signal to a process
 *  @pid: the PID of the process
 *  @sig: signal to be sent
 */
SYSCALL_DEFINE2(kill, pid_t, pid, int, sig)
{
    struct kernel_siginfo info;

    prepare_kill_siginfo(sig, &info, PIDTYPE_TGID);

    return kill_something_info(sig, &info, pid);
}
```

```c
// header file: include/linux/syscalls.h

#ifndef CONFIG_ODD_RT_SIGACTION
asmlinkage long sys_rt_sigaction(int,
                const struct sigaction __user *,
                struct sigaction __user *,
                size_t);
#endif

#ifdef CONFIG_OLD_SIGACTION
asmlinkage long sys_sigaction(int, const struct old_sigaction __user *,
                struct old_sigaction __user *);
#endif

asmlinkage long sys_rt_sigpending(sigset_t __user *set, size_t sigsetsize);

/* obsolete */
asmlinkage long sys_sigpending(old_sigset_t __user *uset);
```
