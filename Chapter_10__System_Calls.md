# 第 10 章  系统调用

Unix 系统通过向内核发出系统调用 (system call) 实现了用户态进程和硬件设备之间的大部分接口

## POSIX APIs and System Calls

POSIX 标准针对 API 而不针对系统调用

判断一个系统是否与 POSIX 兼容要看它是否提供了一组合适的 API，而不管对应的函数是如何实现的

## System Call Handler and Service Routines

当用户态的进程调用一个系统调用时，CPU 切换到内核态并开始执行一个内核函数

在 x86 体系结构中，可以用两种不同的方式调用 Linux 的系统调用

两种方式的最终结果都是跳转到所谓系统调用处理程序的汇编语言函数

因为内核实现了很多不同的系统调用，因此进程必须传递一个名为系统调用号 (system call number)

的参数来识别所需的系统调用，`eax` 寄存器就用作此目的

在内核中，正数或 0 表示系统调用成功结束，而负数表示一个出错条件

`xyz()` 系统调用对应的服务例程的名字通常是 `sys_xyz()`

为了把系统调用号与相应的服务例程关联起来，内核利用了一个系统调用分派表

这个表存放在 `sys_call_table` 数组中，有 `NR_syscalls` 个表项，

第 n 个表项包含系统调用号为 n 的服务例程的地址

```c
// header file: arch/x86/include/asm/unistd.h
# define NR_syscalls (__NR_syscalls)


// header file: include/uapi/asm-generic/unistd.h

#define __NR_io_setup 0
__SC_COMP(__NR_io_setup, sys_io_setup, compat_sys_io_setup)

#define __NR_io_destroy 1
__SYSCALL(__NR_io_destroy, sys_io_destroy)

#define __NR_io_submit 2
__SC_COMP(__NR_io_submit, sys_io_submit, compat_sys_io_submit)

#define __NR_io_cancel 3
__SYSCALL(__NR_io_cancel, sys_io_cancel)

...

#define __NR_lsm_set_self_attr 460
__SYSCALL(__NR_lsm_set_self_attr, sys_lsm_set_self_attr)

#define __NR_lsm_list_modules 461
__SYSCALL(__NR_lsm_list_modules, sys_lsm_list_modules)

#define __NR_mseal 462
__SYSCALL(__NR_mseal, sys_mseal)

#undef __NR_syscalls
#define __NR_syscalls 463
```

```c
// file: arch/x86/entry/syscall_64.c

const sys_call_ptr_t sys_call_table[] = {
#include <asm/syscalls_64.h>
};

// file: arch/x86/um/asm/syscall.h

typedef asmlinkage long (*sys_call_ptr_t)(unsigned long, unsigned long,
                                          unsigned long, unsigned long,
                                          unsigned long, unsigned long);
```

## 进入和退出系统调用

进入系统调用的两种不同方式：

* 执行 `int $0x80` 汇编指令。在 Linux 内核的老版本中，这是从用户态切换到内核态的唯一方式

* 执行 `sysenter` 汇编指令。在 Intel Pentium II 芯片中引入了这条指令

内核可以通过两种方式从系统调用退出，从而使 CPU 回到用户态：

* 执行 `iret` 汇编指令

* 执行 `sysexit` 汇编指令，它和 `sysenter` 是同时在 Pentium II 中引入的

### 通过 `int $0x80` 发出系统调用

用户态进程将在 `eax` 中找到系统调用的返回码

### 通过 `sysenter` 发出系统调用

汇编指令 `int $0x80` 由于要执行几个一致性和安全性检查，所以速度较慢

`sysenter` 提供了一种从用户态到内核态的快速切换方法

汇编指令 `sysenter` 使用三种特殊的寄存器，它们必须装入下面的信息：

* SYSENTER_CS_MSR  -- 内核代码段的段选择符

* SYSENTER_EIP_MSR -- 内核入口点的线性地址

* SYSENTER_ESP_MSR -- 内核堆栈指针

执行 `sysenter` 指令时，CPU 控制单元：

* 把 SYSENTER_CS_MSR 的内容复制到 cs

* 把 SYSENTER_EIP_MSR 的内容复制到 eip

* 把 SYSENTER_ESP_MSR 的内容复制到 esp

* 把 SYSENTER_CS_MSR 加 8 的值装入 ss

> MSR 是 Model-Specific Register 的缩写，表示仅在当前一些 x86 处理器中存在的某个寄存器

在内核初始化期间，一旦执行 `enable_sep_cpu()`，三个特定于模型的寄存器就由该函数初始化了

```c
// file: arch/x86/kernel/cpu/common.c

/*
 * Set up the CPU state needed to execute SYSENTER/SYSEXIT instructions
 * on 32-bit kernels:
 */
#ifdef CONFIG_X86_32
void enable_sep_cpu(void)
{
    struct tss_struct *tss;
    int cpu;

    if (!boot_cpu_has(X86_FEATURE_SEP))
        return;

    cpu = get_cpu();
    tss = &per_cpu(cpu_tss_rw, cpu);

    /*
     * We cache MSR_IA32_SYSENTER_CS's value in the TSS's ss1 field --
     * see the big comment in struct x86_hw_tss's definition.
     */

    tss->x86_tss.ss1 = __KERNEL_CS;
    wrmsr(MSR_IA32_SYSENTER_CS, tss->x86_tss.ss1, 0);
    wrmsr(MSR_IA32_SYSENTER_ESP, (unsigned long)(cpu_entry_stack(cpu) + 1), 0);
    wrmsr(MSR_IA32_SYSENTER_EIP, (unsigned long)entry_SYSENTER_32, 0);

    put_cpu();
}
#endif
```

当用 `sysenter` 发出系统调用时，标准库中的封装例程

把系统调用号装入 eax 寄存器，并调用 __kernel_vsyscall() 函数

```asm
__kernel_vsyscall:
    CFI_STARTPROC
    pushl    %ecx
    CFI_ADJUST_CFA_OFFSET    4
    CFI_REL_OFFSET        ecx, 0
    pushl    %edx
    CFI_ADJUST_CFA_OFFSET    4
    CFI_REL_OFFSET        edx, 0
    pushl    %ebp
    CFI_ADJUST_CFA_OFFSET    4
    CFI_REL_OFFSET        ebp, 0

    #define SYSENTER_SEQUENCE    "movl %esp, %ebp; sysenter"
    #define SYSCALL_SEQUENCE    "movl %ecx, %ebp; syscall"

#ifdef CONFIG_X86_64
    /* If SYSENTER (Intel) or SYSCALL32 (AMD) is available, use it. */
    ALTERNATIVE_2 "", SYSENTER_SEQUENCE, X86_FEATURE_SYSENTER32, \
                      SYSCALL_SEQUENCE,  X86_FEATURE_SYSCALL32
#else
    ALTERNATIVE "", SYSENTER_SEQUENCE, X86_FEATURE_SEP
#endif

    /* Enter using int $0x80 */
    int    $0x80
SYM_INNER_LABEL(int80_landing_pad, SYM_L_GLOBAL)

    /*
     * Restore EDX and ECX in case they were clobbered.  EBP is not
     * clobbered (the kernel restores it), but it's cleaner and
     * probably faster to pop it than to adjust ESP using addl.
     */
    popl    %ebp
    CFI_RESTORE        ebp
    CFI_ADJUST_CFA_OFFSET    -4
    popl    %edx
    CFI_RESTORE        edx
    CFI_ADJUST_CFA_OFFSET    -4
    popl    %ecx
    CFI_RESTORE        ecx
    CFI_ADJUST_CFA_OFFSET    -4
    RET
    CFI_ENDPROC
```

## 参数传递

如果一个应用程序调用 `fork()` 封装例程，那么在执行 `int $0x80` 或 `sysenter` 指令之前

就把 eax 寄存器置为 `__NR_fork`

这个寄存器的设置是由 libc 库中的封装例程进行的，程序员通常并不用关心系统调用号

普通 C 函数的参数传递是通过把参数值写入程序栈 (用户态栈或者内核态栈) 实现的

系统调用是横跨用户和内核的特殊函数，所以即不能使用用户态栈也不能使用内核态栈

在发出系统调用之前，系统调用的参数被写入 CPU 寄存器

然后在调用系统调用服务例程之前，内核再把存放在 CPU 中的参数拷贝到内核态栈中

系统调用服务例程是普通的 C 函数

为了用寄存器传递参数，必须满足两个条件：

* 每个参数的长度不能超过寄存器的长度

* 参数的个数不能超过 6 个 (除了 eax 中传递的系统调用号)，因为 x86 处理器的寄存器数量是有限的

用于存放系统调用号和系统调用参数的寄存器是：eax (存放系统调用号)，ebx，ecx，edx，esi，edi，ebp

`SAVE_ALL` 宏把这些寄存器的值保存在内核态栈中

```asm
.macro SAVE_ALL pt_regs_ax=%eax switch_stacks=0 skip_gs=0 unwind_espfix=0
    cld
.if \skip_gs == 0
    pushl    $0
.endif
    pushl    %fs

    pushl    %eax
    movl    $(__KERNEL_PERCPU), %eax
    movl    %eax, %fs
.if \unwind_espfix > 0
    UNWIND_ESPFIX_STACK
.endif
    popl    %eax

    FIXUP_FRAME
    pushl    %es
    pushl    %ds
    pushl    \pt_regs_ax
    pushl    %ebp
    pushl    %edi
    pushl    %esi
    pushl    %edx
    pushl    %ecx
    pushl    %ebx
    movl    $(__USER_DS), %edx
    movl    %edx, %ds
    movl    %edx, %es
    /* Switch to kernel stack if necessary */
.if \switch_stacks > 0
    SWITCH_TO_KERNEL_STACK
.endif
.endm
```

### 验证参数

在内核打算满足用户的请求之前，必须仔细地检查所有的系统调用参数

如果一个参数指定的是地址，那么内核必须检查它是否在这个进程的地址空间之内

对系统调用所传递地址的检查是通过 `access_ok` 宏实现的

### 访问进程地址空间

访问进程地址空间的函数和宏

|        函数      |            操作           |
|  :------------:  |      :------------:      |
|    `get_user`    |    从用户空间读一个整数     |
|    `put_user`    |    向用户空间写一个整数     |
| `copy_from_user` |  从用户空间复制任意大小的块  |
|  `copy_to_user`  |  向用户空间复制任意大小的块  |
|   `clear_user`   |  用 0 填充用户空间的内存区  |

### 动态地址检查：修正代码

```c
// header file: include/asm-generic/extable.h

struct exception_table_entry
{
    unsigned long insn, fixup;
};
```

* insn: 访问进程地址空间的指令的线性地址

* fixup: 当存放在 `insn` 单元中的指令触发缺页异常时，`fixup` 就是要调用的汇编代码的地址

`search_exception_tables` 函数用来在所有异常表中查找一个指定地址

```c
// file: kernel/extable.c

/* Given an address, look for it in the exception tables. */
const struct exception_table_entry *search_exception_tables(unsigned long addr)
{
    const struct exception_table_entry *e;

    e = search_kernel_exception_table(addr);
    if (!e)
        e = search_module_extables(addr);
    if (!e)
        e = search_bpf_extables(addr);
    return e;
}
```

## 内核封装例程

为了简化相应封装例程的声明，Linux 定义了 7 个

从 `SYSCALL_DEFINE0` 到 `SYSCALL_DEFINE6` 的一组宏

```c
// header file: include/linux/syscalls.h

#ifndef SYSCALL_DEFINE0
#define SYSCALL_DEFINE0(sname)                    \
    SYSCALL_METADATA(_##sname, 0);                \
    asmlinkage long sys_##sname(void);            \
    ALLOW_ERROR_INJECTION(sys_##sname, ERRNO);        \
    asmlinkage long sys_##sname(void)
#endif /* SYSCALL_DEFINE0 */

#define SYSCALL_DEFINE1(name, ...) SYSCALL_DEFINEx(1, _##name, __VA_ARGS__)
#define SYSCALL_DEFINE2(name, ...) SYSCALL_DEFINEx(2, _##name, __VA_ARGS__)
#define SYSCALL_DEFINE3(name, ...) SYSCALL_DEFINEx(3, _##name, __VA_ARGS__)
#define SYSCALL_DEFINE4(name, ...) SYSCALL_DEFINEx(4, _##name, __VA_ARGS__)
#define SYSCALL_DEFINE5(name, ...) SYSCALL_DEFINEx(5, _##name, __VA_ARGS__)
#define SYSCALL_DEFINE6(name, ...) SYSCALL_DEFINEx(6, _##name, __VA_ARGS__)

#define SYSCALL_DEFINE_MAXARGS    6

#define SYSCALL_DEFINEx(x, sname, ...)                \
    SYSCALL_METADATA(sname, x, __VA_ARGS__)            \
    __SYSCALL_DEFINEx(x, sname, __VA_ARGS__)
```

每个宏名字中的数字 0~6 对应着系统调用所用的参数个数 (系统调用号除外)

每个宏严格的需要 `2n + 1` 个参数，n 是系统调用的参数个数

第一个参数是系统调用的名字，剩下的每一对参数是相应的系统调用参数的类型和名字

```c
// file: fs/read_write.c

SYSCALL_DEFINE3(write, unsigned int, fd, const char __user *, buf,
        size_t, count)
{
    return ksys_write(fd, buf, count);
}

ssize_t ksys_write(unsigned int fd, const char __user *buf, size_t count)
{ }

// file: fs/open.c

SYSCALL_DEFINE2(chmod, const char __user *, filename, umode_t, mode)
{
    return do_fchmodat(AT_FDCWD, filename, mode, 0);
}

// file: kernel/fork.c

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
```
