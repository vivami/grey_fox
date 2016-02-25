//
//  hooker.c
//  grey_fox
//
//  Hooks all the relevant system calls and logs them tot system.log for later analysis.
//
//  Created by vivami on 04/11/15.
//  Copyright © 2015 vivami. All rights reserved.
//

#include "cpu_protections.h"
#include "hooker.h"

#include <sys/syslimits.h>
#include <sys/proc.h>
#include <kern/clock.h>


typedef int (*kern_f)(struct proc *, struct args *, int *);
static kern_f kernel_functions[SYS_MAXSYSCALL+1] = {0};

extern const int version_major;

/* Change this depedning on which OSX you want to run grey fox. Yosemite by default */
struct sysent_yosemite *sysent;
//struct sysent_mavericks *sysent;
//struct sysent *sysent;

kern_return_t hook_all_syscalls(void *sysent_addr) {

    enable_kernel_write();
    // SYS_MAXSYSCALL is the last syscall
    for (int32_t i = SYS_fork; i <= SYS_MAXSYSCALL; i++) {
        hook_syscall(sysent_addr, i);
    }
    
    disable_kernel_write();
    return KERN_SUCCESS;
}

kern_return_t unhook_all_syscalls(void *sysent_addr) {
    
    enable_kernel_write();
    
    for (int32_t i = SYS_fork; i <= SYS_MAXSYSCALL; i++) {
        unhook_syscall(sysent_addr, i);
    }
    
    disable_kernel_write();
    return KERN_SUCCESS;
}

/* Replaces (based on relevant system call), the syscall function pointer to the original syscall function,
   with an implementation of my own (see bottom). Original pointer is stored in a buffer for unhooking. */
kern_return_t hook_syscall(void *sysent_addr, int32_t syscall) {
    switch (version_major) {
        case EL_CAPITAN:
            sysent = (struct sysent_yosemite*)sysent_addr;
            break;
        case YOSEMITE:
            sysent = (struct sysent_yosemite*)sysent_addr;
            break;
        case MAVERICKS:
            sysent = (struct sysent_mavericks*)sysent_addr;
            break;
        default:
            sysent = (struct sysent*)sysent_addr;
            break;
        }

    /* This is also extremely ugly (and was automatically generated using a Python script).
       Although I'm too dumb to come up with something more elegant */
    switch (syscall) {
        case SYS_read:
            kernel_functions[SYS_read] = (void*)sysent[SYS_read].sy_call;
            sysent[SYS_read].sy_call = hook_read;
            printf("[GREY FOX] Hooked SYS_read\n");
            break;
        case SYS_write:
            kernel_functions[SYS_write] = (void*)sysent[SYS_write].sy_call;
            sysent[SYS_write].sy_call = hook_write;
            printf("[GREY FOX] Hooked SYS_write\n");
            break;
        case SYS_open:
            kernel_functions[SYS_open] = (void*)sysent[SYS_open].sy_call;
            sysent[SYS_open].sy_call = hook_open;
            printf("[GREY FOX] Hooked SYS_open\n");
            break;
        case SYS_link:
            kernel_functions[SYS_link] = (void*)sysent[SYS_link].sy_call;
            sysent[SYS_link].sy_call = hook_link;
            printf("[GREY FOX] Hooked SYS_link\n");
            break;
        case SYS_unlink:
            kernel_functions[SYS_unlink] = (void*)sysent[SYS_unlink].sy_call;
            sysent[SYS_unlink].sy_call = hook_unlink;
            printf("[GREY FOX] Hooked SYS_unlink\n");
            break;
        case SYS_fork:
            kernel_functions[SYS_fork] = (void*)sysent[SYS_fork].sy_call;
            sysent[SYS_fork].sy_call = hook_fork;
            printf("[GREY FOX] Hooked SYS_fork\n");
            break;
        case SYS_mknod:
            kernel_functions[SYS_mknod] = (void*)sysent[SYS_mknod].sy_call;
            sysent[SYS_mknod].sy_call = hook_mknod;
            printf("[GREY FOX] Hooked SYS_mknod\n");
            break;
        case SYS_chmod:
            kernel_functions[SYS_chmod] = (void*)sysent[SYS_chmod].sy_call;
            sysent[SYS_chmod].sy_call = hook_chmod;
            printf("[GREY FOX] Hooked SYS_chmod\n");
            break;
        case SYS_chown:
            kernel_functions[SYS_chown] = (void*)sysent[SYS_chown].sy_call;
            sysent[SYS_chown].sy_call = hook_chown;
            printf("[GREY FOX] Hooked SYS_chown\n");
            break;
        case SYS_getfsstat:
            kernel_functions[SYS_getfsstat] = (void*)sysent[SYS_getfsstat].sy_call;
            sysent[SYS_getfsstat].sy_call = hook_getfsstat;
            printf("[GREY FOX] Hooked SYS_getfsstat\n");
            break;
        case SYS_setuid:
            kernel_functions[SYS_setuid] = (void*)sysent[SYS_setuid].sy_call;
            sysent[SYS_setuid].sy_call = hook_setuid;
            printf("[GREY FOX] Hooked SYS_setuid\n");
            break;
        case SYS_ptrace:
            kernel_functions[SYS_ptrace] = (void*)sysent[SYS_ptrace].sy_call;
            sysent[SYS_ptrace].sy_call = hook_ptrace;
            printf("[GREY FOX] Hooked SYS_ptrace\n");
            break;
        case SYS_access:
            kernel_functions[SYS_access] = (void*)sysent[SYS_access].sy_call;
            sysent[SYS_access].sy_call = hook_access;
            printf("[GREY FOX] Hooked SYS_access\n");
            break;
        case SYS_chflags:
            kernel_functions[SYS_chflags] = (void*)sysent[SYS_chflags].sy_call;
            sysent[SYS_chflags].sy_call = hook_chflags;
            printf("[GREY FOX] Hooked SYS_chflags\n");
            break;
        case SYS_fchflags:
            kernel_functions[SYS_fchflags] = (void*)sysent[SYS_fchflags].sy_call;
            sysent[SYS_fchflags].sy_call = hook_fchflags;
            printf("[GREY FOX] Hooked SYS_fchflags\n");
            break;
        case SYS_getppid:
            kernel_functions[SYS_getppid] = (void*)sysent[SYS_getppid].sy_call;
            sysent[SYS_getppid].sy_call = hook_getppid;
            printf("[GREY FOX] Hooked SYS_getppid\n");
            break;
        case SYS_pipe:
            kernel_functions[SYS_pipe] = (void*)sysent[SYS_pipe].sy_call;
            sysent[SYS_pipe].sy_call = hook_pipe;
            printf("[GREY FOX] Hooked SYS_pipe\n");
            break;
        case SYS_getegid:
            kernel_functions[SYS_getegid] = (void*)sysent[SYS_getegid].sy_call;
            sysent[SYS_getegid].sy_call = hook_getegid;
            printf("[GREY FOX] Hooked SYS_getegid\n");
            break;
        case SYS_sigaction:
            kernel_functions[SYS_sigaction] = (void*)sysent[SYS_sigaction].sy_call;
            sysent[SYS_sigaction].sy_call = hook_sigaction;
            printf("[GREY FOX] Hooked SYS_sigaction\n");
            break;
        case SYS_getlogin:
            kernel_functions[SYS_getlogin] = (void*)sysent[SYS_getlogin].sy_call;
            sysent[SYS_getlogin].sy_call = hook_getlogin;
            printf("[GREY FOX] Hooked SYS_getlogin\n");
            break;
        case SYS_setlogin:
            kernel_functions[SYS_setlogin] = (void*)sysent[SYS_setlogin].sy_call;
            sysent[SYS_setlogin].sy_call = hook_setlogin;
            printf("[GREY FOX] Hooked SYS_setlogin\n");
            break;
        case SYS_acct:
            kernel_functions[SYS_acct] = (void*)sysent[SYS_acct].sy_call;
            sysent[SYS_acct].sy_call = hook_acct;
            printf("[GREY FOX] Hooked SYS_acct\n");
            break;
        case SYS_sigpending:
            kernel_functions[SYS_sigpending] = (void*)sysent[SYS_sigpending].sy_call;
            sysent[SYS_sigpending].sy_call = hook_sigpending;
            printf("[GREY FOX] Hooked SYS_sigpending\n");
            break;
        case SYS_reboot:
            kernel_functions[SYS_reboot] = (void*)sysent[SYS_reboot].sy_call;
            sysent[SYS_reboot].sy_call = hook_reboot;
            printf("[GREY FOX] Hooked SYS_reboot\n");
            break;
        case SYS_revoke:
            kernel_functions[SYS_revoke] = (void*)sysent[SYS_revoke].sy_call;
            sysent[SYS_revoke].sy_call = hook_revoke;
            printf("[GREY FOX] Hooked SYS_revoke\n");
            break;
        case SYS_symlink:
            kernel_functions[SYS_symlink] = (void*)sysent[SYS_symlink].sy_call;
            sysent[SYS_symlink].sy_call = hook_symlink;
            printf("[GREY FOX] Hooked SYS_symlink\n");
            break;
        case SYS_execve:
            kernel_functions[SYS_execve] = (void*)sysent[SYS_execve].sy_call;
            sysent[SYS_execve].sy_call = hook_execve;
            printf("[GREY FOX] Hooked SYS_execve\n");
            break;
        case SYS_umask:
            kernel_functions[SYS_umask] = (void*)sysent[SYS_umask].sy_call;
            sysent[SYS_umask].sy_call = hook_umask;
            printf("[GREY FOX] Hooked SYS_umask\n");
            break;
        case SYS_chroot:
            kernel_functions[SYS_chroot] = (void*)sysent[SYS_chroot].sy_call;
            sysent[SYS_chroot].sy_call = hook_chroot;
            printf("[GREY FOX] Hooked SYS_chroot\n");
            break;
        case SYS_msync:
            kernel_functions[SYS_msync] = (void*)sysent[SYS_msync].sy_call;
            sysent[SYS_msync].sy_call = hook_msync;
            printf("[GREY FOX] Hooked SYS_msync\n");
            break;
        case SYS_vfork:
            kernel_functions[SYS_vfork] = (void*)sysent[SYS_vfork].sy_call;
            sysent[SYS_vfork].sy_call = hook_vfork;
            printf("[GREY FOX] Hooked SYS_vfork\n");
            break;
        case SYS_mincore:
            kernel_functions[SYS_mincore] = (void*)sysent[SYS_mincore].sy_call;
            sysent[SYS_mincore].sy_call = hook_mincore;
            printf("[GREY FOX] Hooked SYS_mincore\n");
            break;
        case SYS_getgroups:
            kernel_functions[SYS_getgroups] = (void*)sysent[SYS_getgroups].sy_call;
            sysent[SYS_getgroups].sy_call = hook_getgroups;
            printf("[GREY FOX] Hooked SYS_getgroups\n");
            break;
        case SYS_setgroups:
            kernel_functions[SYS_setgroups] = (void*)sysent[SYS_setgroups].sy_call;
            sysent[SYS_setgroups].sy_call = hook_setgroups;
            printf("[GREY FOX] Hooked SYS_setgroups\n");
            break;
        case SYS_getpgrp:
            kernel_functions[SYS_getpgrp] = (void*)sysent[SYS_getpgrp].sy_call;
            sysent[SYS_getpgrp].sy_call = hook_getpgrp;
            printf("[GREY FOX] Hooked SYS_getpgrp\n");
            break;
        case SYS_setpgid:
            kernel_functions[SYS_setpgid] = (void*)sysent[SYS_setpgid].sy_call;
            sysent[SYS_setpgid].sy_call = hook_setpgid;
            printf("[GREY FOX] Hooked SYS_setpgid\n");
            break;
        case SYS_swapon:
            kernel_functions[SYS_swapon] = (void*)sysent[SYS_swapon].sy_call;
            sysent[SYS_swapon].sy_call = hook_swapon;
            printf("[GREY FOX] Hooked SYS_swapon\n");
            break;
        case SYS_getitimer:
            kernel_functions[SYS_getitimer] = (void*)sysent[SYS_getitimer].sy_call;
            sysent[SYS_getitimer].sy_call = hook_getitimer;
            printf("[GREY FOX] Hooked SYS_getitimer\n");
            break;
        case SYS_getdtablesize:
            kernel_functions[SYS_getdtablesize] = (void*)sysent[SYS_getdtablesize].sy_call;
            sysent[SYS_getdtablesize].sy_call = hook_getdtablesize;
            printf("[GREY FOX] Hooked SYS_getdtablesize\n");
            break;
        case SYS_dup2:
            kernel_functions[SYS_dup2] = (void*)sysent[SYS_dup2].sy_call;
            sysent[SYS_dup2].sy_call = hook_dup2;
            printf("[GREY FOX] Hooked SYS_dup2\n");
            break;
        case SYS_setpriority:
            kernel_functions[SYS_setpriority] = (void*)sysent[SYS_setpriority].sy_call;
            sysent[SYS_setpriority].sy_call = hook_setpriority;
            printf("[GREY FOX] Hooked SYS_setpriority\n");
            break;
        case SYS_socket:
            kernel_functions[SYS_socket] = (void*)sysent[SYS_socket].sy_call;
            sysent[SYS_socket].sy_call = hook_socket;
            printf("[GREY FOX] Hooked SYS_socket\n");
            break;
        case SYS_connect:
            kernel_functions[SYS_connect] = (void*)sysent[SYS_connect].sy_call;
            sysent[SYS_connect].sy_call = hook_connect;
            printf("[GREY FOX] Hooked SYS_connect\n");
            break;
        case SYS_getpriority:
            kernel_functions[SYS_getpriority] = (void*)sysent[SYS_getpriority].sy_call;
            sysent[SYS_getpriority].sy_call = hook_getpriority;
            printf("[GREY FOX] Hooked SYS_getpriority\n");
            break;
        case SYS_bind:
            kernel_functions[SYS_bind] = (void*)sysent[SYS_bind].sy_call;
            sysent[SYS_bind].sy_call = hook_bind;
            printf("[GREY FOX] Hooked SYS_bind\n");
            break;
        case SYS_setsockopt:
            kernel_functions[SYS_setsockopt] = (void*)sysent[SYS_setsockopt].sy_call;
            sysent[SYS_setsockopt].sy_call = hook_setsockopt;
            printf("[GREY FOX] Hooked SYS_setsockopt\n");
            break;
        case SYS_listen:
            kernel_functions[SYS_listen] = (void*)sysent[SYS_listen].sy_call;
            sysent[SYS_listen].sy_call = hook_listen;
            printf("[GREY FOX] Hooked SYS_listen\n");
            break;
        case SYS_getsockopt:
            kernel_functions[SYS_getsockopt] = (void*)sysent[SYS_getsockopt].sy_call;
            sysent[SYS_getsockopt].sy_call = hook_getsockopt;
            printf("[GREY FOX] Hooked SYS_getsockopt\n");
            break;
        case SYS_readv:
            kernel_functions[SYS_readv] = (void*)sysent[SYS_readv].sy_call;
            sysent[SYS_readv].sy_call = hook_readv;
            printf("[GREY FOX] Hooked SYS_readv\n");
            break;
        case SYS_writev:
            kernel_functions[SYS_writev] = (void*)sysent[SYS_writev].sy_call;
            sysent[SYS_writev].sy_call = hook_writev;
            printf("[GREY FOX] Hooked SYS_writev\n");
            break;
        case SYS_settimeofday:
            kernel_functions[SYS_settimeofday] = (void*)sysent[SYS_settimeofday].sy_call;
            sysent[SYS_settimeofday].sy_call = hook_settimeofday;
            printf("[GREY FOX] Hooked SYS_settimeofday\n");
            break;
        case SYS_fchown:
            kernel_functions[SYS_fchown] = (void*)sysent[SYS_fchown].sy_call;
            sysent[SYS_fchown].sy_call = hook_fchown;
            printf("[GREY FOX] Hooked SYS_fchown\n");
            break;
        case SYS_fchmod:
            kernel_functions[SYS_fchmod] = (void*)sysent[SYS_fchmod].sy_call;
            sysent[SYS_fchmod].sy_call = hook_fchmod;
            printf("[GREY FOX] Hooked SYS_fchmod\n");
            break;
        case SYS_setreuid:
            kernel_functions[SYS_setreuid] = (void*)sysent[SYS_setreuid].sy_call;
            sysent[SYS_setreuid].sy_call = hook_setreuid;
            printf("[GREY FOX] Hooked SYS_setreuid\n");
            break;
        case SYS_setregid:
            kernel_functions[SYS_setregid] = (void*)sysent[SYS_setregid].sy_call;
            sysent[SYS_setregid].sy_call = hook_setregid;
            printf("[GREY FOX] Hooked SYS_setregid\n");
            break;
        case SYS_rename:
            kernel_functions[SYS_rename] = (void*)sysent[SYS_rename].sy_call;
            sysent[SYS_rename].sy_call = hook_rename;
            printf("[GREY FOX] Hooked SYS_rename\n");
            break;
        case SYS_flock:
            kernel_functions[SYS_flock] = (void*)sysent[SYS_flock].sy_call;
            sysent[SYS_flock].sy_call = hook_flock;
            printf("[GREY FOX] Hooked SYS_flock\n");
            break;
        case SYS_mkfifo:
            kernel_functions[SYS_mkfifo] = (void*)sysent[SYS_mkfifo].sy_call;
            sysent[SYS_mkfifo].sy_call = hook_mkfifo;
            printf("[GREY FOX] Hooked SYS_mkfifo\n");
            break;
        case SYS_sendto:
            kernel_functions[SYS_sendto] = (void*)sysent[SYS_sendto].sy_call;
            sysent[SYS_sendto].sy_call = hook_sendto;
            printf("[GREY FOX] Hooked SYS_sendto\n");
            break;
        case SYS_shutdown:
            kernel_functions[SYS_shutdown] = (void*)sysent[SYS_shutdown].sy_call;
            sysent[SYS_shutdown].sy_call = hook_shutdown;
            printf("[GREY FOX] Hooked SYS_shutdown\n");
            break;
        case SYS_socketpair:
            kernel_functions[SYS_socketpair] = (void*)sysent[SYS_socketpair].sy_call;
            sysent[SYS_socketpair].sy_call = hook_socketpair;
            printf("[GREY FOX] Hooked SYS_socketpair\n");
            break;
        case SYS_rmdir:
            kernel_functions[SYS_rmdir] = (void*)sysent[SYS_rmdir].sy_call;
            sysent[SYS_rmdir].sy_call = hook_rmdir;
            printf("[GREY FOX] Hooked SYS_rmdir\n");
            break;
        case SYS_utimes:
            kernel_functions[SYS_utimes] = (void*)sysent[SYS_utimes].sy_call;
            sysent[SYS_utimes].sy_call = hook_utimes;
            printf("[GREY FOX] Hooked SYS_utimes\n");
            break;
        case SYS_futimes:
            kernel_functions[SYS_futimes] = (void*)sysent[SYS_futimes].sy_call;
            sysent[SYS_futimes].sy_call = hook_futimes;
            printf("[GREY FOX] Hooked SYS_futimes\n");
            break;
        case SYS_gethostuuid:
            kernel_functions[SYS_gethostuuid] = (void*)sysent[SYS_gethostuuid].sy_call;
            sysent[SYS_gethostuuid].sy_call = hook_gethostuuid;
            printf("[GREY FOX] Hooked SYS_gethostuuid\n");
            break;
        case SYS_setsid:
            kernel_functions[SYS_setsid] = (void*)sysent[SYS_setsid].sy_call;
            sysent[SYS_setsid].sy_call = hook_setsid;
            printf("[GREY FOX] Hooked SYS_setsid\n");
            break;
        case SYS_getpgid:
            kernel_functions[SYS_getpgid] = (void*)sysent[SYS_getpgid].sy_call;
            sysent[SYS_getpgid].sy_call = hook_getpgid;
            printf("[GREY FOX] Hooked SYS_getpgid\n");
            break;
        case SYS_setprivexec:
            kernel_functions[SYS_setprivexec] = (void*)sysent[SYS_setprivexec].sy_call;
            sysent[SYS_setprivexec].sy_call = hook_setprivexec;
            printf("[GREY FOX] Hooked SYS_setprivexec\n");
            break;
        case SYS_pwrite:
            kernel_functions[SYS_pwrite] = (void*)sysent[SYS_pwrite].sy_call;
            sysent[SYS_pwrite].sy_call = hook_pwrite;
            printf("[GREY FOX] Hooked SYS_pwrite\n");
            break;
        case SYS_nfssvc:
            kernel_functions[SYS_nfssvc] = (void*)sysent[SYS_nfssvc].sy_call;
            sysent[SYS_nfssvc].sy_call = hook_nfssvc;
            printf("[GREY FOX] Hooked SYS_nfssvc\n");
            break;
        case SYS_statfs:
            kernel_functions[SYS_statfs] = (void*)sysent[SYS_statfs].sy_call;
            sysent[SYS_statfs].sy_call = hook_statfs;
            printf("[GREY FOX] Hooked SYS_statfs\n");
            break;
        case SYS_fstatfs:
            kernel_functions[SYS_fstatfs] = (void*)sysent[SYS_fstatfs].sy_call;
            sysent[SYS_fstatfs].sy_call = hook_fstatfs;
            printf("[GREY FOX] Hooked SYS_fstatfs\n");
            break;
        case SYS_unmount:
            kernel_functions[SYS_unmount] = (void*)sysent[SYS_unmount].sy_call;
            sysent[SYS_unmount].sy_call = hook_unmount;
            printf("[GREY FOX] Hooked SYS_unmount\n");
            break;
        case SYS_getfh:
            kernel_functions[SYS_getfh] = (void*)sysent[SYS_getfh].sy_call;
            sysent[SYS_getfh].sy_call = hook_getfh;
            printf("[GREY FOX] Hooked SYS_getfh\n");
            break;
        case SYS_quotactl:
            kernel_functions[SYS_quotactl] = (void*)sysent[SYS_quotactl].sy_call;
            sysent[SYS_quotactl].sy_call = hook_quotactl;
            printf("[GREY FOX] Hooked SYS_quotactl\n");
            break;
        case SYS_mount:
            kernel_functions[SYS_mount] = (void*)sysent[SYS_mount].sy_call;
            sysent[SYS_mount].sy_call = hook_mount;
            printf("[GREY FOX] Hooked SYS_mount\n");
            break;
        case SYS_waitid:
            kernel_functions[SYS_waitid] = (void*)sysent[SYS_waitid].sy_call;
            sysent[SYS_waitid].sy_call = hook_waitid;
            printf("[GREY FOX] Hooked SYS_waitid\n");
            break;
        case SYS_kdebug_trace:
            kernel_functions[SYS_kdebug_trace] = (void*)sysent[SYS_kdebug_trace].sy_call;
            sysent[SYS_kdebug_trace].sy_call = hook_kdebug_trace;
            printf("[GREY FOX] Hooked SYS_kdebug_trace\n");
            break;
        case SYS_setgid:
            kernel_functions[SYS_setgid] = (void*)sysent[SYS_setgid].sy_call;
            sysent[SYS_setgid].sy_call = hook_setgid;
            printf("[GREY FOX] Hooked SYS_setgid\n");
            break;
        case SYS_setegid:
            kernel_functions[SYS_setegid] = (void*)sysent[SYS_setegid].sy_call;
            sysent[SYS_setegid].sy_call = hook_setegid;
            printf("[GREY FOX] Hooked SYS_setegid\n");
            break;
        case SYS_seteuid:
            kernel_functions[SYS_seteuid] = (void*)sysent[SYS_seteuid].sy_call;
            sysent[SYS_seteuid].sy_call = hook_seteuid;
            printf("[GREY FOX] Hooked SYS_seteuid\n");
            break;
        case SYS_chud:
            kernel_functions[SYS_chud] = (void*)sysent[SYS_chud].sy_call;
            sysent[SYS_chud].sy_call = hook_chud;
            printf("[GREY FOX] Hooked SYS_chud\n");
            break;
        case SYS_fdatasync:
            kernel_functions[SYS_fdatasync] = (void*)sysent[SYS_fdatasync].sy_call;
            sysent[SYS_fdatasync].sy_call = hook_fdatasync;
            printf("[GREY FOX] Hooked SYS_fdatasync\n");
            break;
        case SYS_stat:
            kernel_functions[SYS_stat] = (void*)sysent[SYS_stat].sy_call;
            sysent[SYS_stat].sy_call = hook_stat;
            printf("[GREY FOX] Hooked SYS_stat\n");
            break;
        case SYS_fstat:
            kernel_functions[SYS_fstat] = (void*)sysent[SYS_fstat].sy_call;
            sysent[SYS_fstat].sy_call = hook_fstat;
            printf("[GREY FOX] Hooked SYS_fstat\n");
            break;
        case SYS_lstat:
            kernel_functions[SYS_lstat] = (void*)sysent[SYS_lstat].sy_call;
            sysent[SYS_lstat].sy_call = hook_lstat;
            printf("[GREY FOX] Hooked SYS_lstat\n");
            break;
        case SYS_pathconf:
            kernel_functions[SYS_pathconf] = (void*)sysent[SYS_pathconf].sy_call;
            sysent[SYS_pathconf].sy_call = hook_pathconf;
            printf("[GREY FOX] Hooked SYS_pathconf\n");
            break;
        case SYS_fpathconf:
            kernel_functions[SYS_fpathconf] = (void*)sysent[SYS_fpathconf].sy_call;
            sysent[SYS_fpathconf].sy_call = hook_fpathconf;
            printf("[GREY FOX] Hooked SYS_fpathconf\n");
            break;
        case SYS_getrlimit:
            kernel_functions[SYS_getrlimit] = (void*)sysent[SYS_getrlimit].sy_call;
            sysent[SYS_getrlimit].sy_call = hook_getrlimit;
            printf("[GREY FOX] Hooked SYS_getrlimit\n");
            break;
        case SYS_setrlimit:
            kernel_functions[SYS_setrlimit] = (void*)sysent[SYS_setrlimit].sy_call;
            sysent[SYS_setrlimit].sy_call = hook_setrlimit;
            printf("[GREY FOX] Hooked SYS_setrlimit\n");
            break;
        case SYS_getdirentries:
            kernel_functions[SYS_getdirentries] = (void*)sysent[SYS_getdirentries].sy_call;
            sysent[SYS_getdirentries].sy_call = hook_getdirentries;
            printf("[GREY FOX] Hooked SYS_getdirentries\n");
            break;
        case SYS_truncate:
            kernel_functions[SYS_truncate] = (void*)sysent[SYS_truncate].sy_call;
            sysent[SYS_truncate].sy_call = hook_truncate;
            printf("[GREY FOX] Hooked SYS_truncate\n");
            break;
        case SYS_ftruncate:
            kernel_functions[SYS_ftruncate] = (void*)sysent[SYS_ftruncate].sy_call;
            sysent[SYS_ftruncate].sy_call = hook_ftruncate;
            printf("[GREY FOX] Hooked SYS_ftruncate\n");
            break;
        case SYS___sysctl:
            kernel_functions[SYS___sysctl] = (void*)sysent[SYS___sysctl].sy_call;
            sysent[SYS___sysctl].sy_call = hook___sysctl;
            printf("[GREY FOX] Hooked SYS___sysctl\n");
            break;
        case SYS_mlock:
            kernel_functions[SYS_mlock] = (void*)sysent[SYS_mlock].sy_call;
            sysent[SYS_mlock].sy_call = hook_mlock;
            printf("[GREY FOX] Hooked SYS_mlock\n");
            break;
        case SYS_munlock:
            kernel_functions[SYS_munlock] = (void*)sysent[SYS_munlock].sy_call;
            sysent[SYS_munlock].sy_call = hook_munlock;
            printf("[GREY FOX] Hooked SYS_munlock\n");
            break;
        case SYS_undelete:
            kernel_functions[SYS_undelete] = (void*)sysent[SYS_undelete].sy_call;
            sysent[SYS_undelete].sy_call = hook_undelete;
            printf("[GREY FOX] Hooked SYS_undelete\n");
            break;
        case SYS_setattrlist:
            kernel_functions[SYS_setattrlist] = (void*)sysent[SYS_setattrlist].sy_call;
            sysent[SYS_setattrlist].sy_call = hook_setattrlist;
            printf("[GREY FOX] Hooked SYS_setattrlist\n");
            break;
        case SYS_getdirentriesattr:
            kernel_functions[SYS_getdirentriesattr] = (void*)sysent[SYS_getdirentriesattr].sy_call;
            sysent[SYS_getdirentriesattr].sy_call = hook_getdirentriesattr;
            printf("[GREY FOX] Hooked SYS_getdirentriesattr\n");
            break;
        case SYS_exchangedata:
            kernel_functions[SYS_exchangedata] = (void*)sysent[SYS_exchangedata].sy_call;
            sysent[SYS_exchangedata].sy_call = hook_exchangedata;
            printf("[GREY FOX] Hooked SYS_exchangedata\n");
            break;
        case SYS_searchfs:
            kernel_functions[SYS_searchfs] = (void*)sysent[SYS_searchfs].sy_call;
            sysent[SYS_searchfs].sy_call = hook_searchfs;
            printf("[GREY FOX] Hooked SYS_searchfs\n");
            break;
        case SYS_delete:
            kernel_functions[SYS_delete] = (void*)sysent[SYS_delete].sy_call;
            sysent[SYS_delete].sy_call = hook_delete;
            printf("[GREY FOX] Hooked SYS_delete\n");
            break;
        case SYS_copyfile:
            kernel_functions[SYS_copyfile] = (void*)sysent[SYS_copyfile].sy_call;
            sysent[SYS_copyfile].sy_call = hook_copyfile;
            printf("[GREY FOX] Hooked SYS_copyfile\n");
            break;
        case SYS_fgetattrlist:
            kernel_functions[SYS_fgetattrlist] = (void*)sysent[SYS_fgetattrlist].sy_call;
            sysent[SYS_fgetattrlist].sy_call = hook_fgetattrlist;
            printf("[GREY FOX] Hooked SYS_fgetattrlist\n");
            break;
        case SYS_fsetattrlist:
            kernel_functions[SYS_fsetattrlist] = (void*)sysent[SYS_fsetattrlist].sy_call;
            sysent[SYS_fsetattrlist].sy_call = hook_fsetattrlist;
            printf("[GREY FOX] Hooked SYS_fsetattrlist\n");
            break;
        case SYS_poll:
            kernel_functions[SYS_poll] = (void*)sysent[SYS_poll].sy_call;
            sysent[SYS_poll].sy_call = hook_poll;
            printf("[GREY FOX] Hooked SYS_poll\n");
            break;
        case SYS_watchevent:
            kernel_functions[SYS_watchevent] = (void*)sysent[SYS_watchevent].sy_call;
            sysent[SYS_watchevent].sy_call = hook_watchevent;
            printf("[GREY FOX] Hooked SYS_watchevent\n");
            break;
        case SYS_waitevent:
            kernel_functions[SYS_waitevent] = (void*)sysent[SYS_waitevent].sy_call;
            sysent[SYS_waitevent].sy_call = hook_waitevent;
            printf("[GREY FOX] Hooked SYS_waitevent\n");
            break;
        case SYS_modwatch:
            kernel_functions[SYS_modwatch] = (void*)sysent[SYS_modwatch].sy_call;
            sysent[SYS_modwatch].sy_call = hook_modwatch;
            printf("[GREY FOX] Hooked SYS_modwatch\n");
            break;
        case SYS_fgetxattr:
            kernel_functions[SYS_fgetxattr] = (void*)sysent[SYS_fgetxattr].sy_call;
            sysent[SYS_fgetxattr].sy_call = hook_fgetxattr;
            printf("[GREY FOX] Hooked SYS_fgetxattr\n");
            break;
        case SYS_setxattr:
            kernel_functions[SYS_setxattr] = (void*)sysent[SYS_setxattr].sy_call;
            sysent[SYS_setxattr].sy_call = hook_setxattr;
            printf("[GREY FOX] Hooked SYS_setxattr\n");
            break;
        case SYS_fsetxattr:
            kernel_functions[SYS_fsetxattr] = (void*)sysent[SYS_fsetxattr].sy_call;
            sysent[SYS_fsetxattr].sy_call = hook_fsetxattr;
            printf("[GREY FOX] Hooked SYS_fsetxattr\n");
            break;
        case SYS_removexattr:
            kernel_functions[SYS_removexattr] = (void*)sysent[SYS_removexattr].sy_call;
            sysent[SYS_removexattr].sy_call = hook_removexattr;
            printf("[GREY FOX] Hooked SYS_removexattr\n");
            break;
        case SYS_fremovexattr:
            kernel_functions[SYS_fremovexattr] = (void*)sysent[SYS_fremovexattr].sy_call;
            sysent[SYS_fremovexattr].sy_call = hook_fremovexattr;
            printf("[GREY FOX] Hooked SYS_fremovexattr\n");
            break;
        case SYS_listxattr:
            kernel_functions[SYS_listxattr] = (void*)sysent[SYS_listxattr].sy_call;
            sysent[SYS_listxattr].sy_call = hook_listxattr;
            printf("[GREY FOX] Hooked SYS_listxattr\n");
            break;
        case SYS_flistxattr:
            kernel_functions[SYS_flistxattr] = (void*)sysent[SYS_flistxattr].sy_call;
            sysent[SYS_flistxattr].sy_call = hook_flistxattr;
            printf("[GREY FOX] Hooked SYS_flistxattr\n");
            break;
        case SYS_fsctl:
            kernel_functions[SYS_fsctl] = (void*)sysent[SYS_fsctl].sy_call;
            sysent[SYS_fsctl].sy_call = hook_fsctl;
            printf("[GREY FOX] Hooked SYS_fsctl\n");
            break;
        case SYS_initgroups:
            kernel_functions[SYS_initgroups] = (void*)sysent[SYS_initgroups].sy_call;
            sysent[SYS_initgroups].sy_call = hook_initgroups;
            printf("[GREY FOX] Hooked SYS_initgroups\n");
            break;
        case SYS_posix_spawn:
            kernel_functions[SYS_posix_spawn] = (void*)sysent[SYS_posix_spawn].sy_call;
            sysent[SYS_posix_spawn].sy_call = hook_posix_spawn;
            printf("[GREY FOX] Hooked SYS_posix_spawn\n");
            break;
        case SYS_ffsctl:
            kernel_functions[SYS_ffsctl] = (void*)sysent[SYS_ffsctl].sy_call;
            sysent[SYS_ffsctl].sy_call = hook_ffsctl;
            printf("[GREY FOX] Hooked SYS_ffsctl\n");
            break;
        case SYS_nfsclnt:
            kernel_functions[SYS_nfsclnt] = (void*)sysent[SYS_nfsclnt].sy_call;
            sysent[SYS_nfsclnt].sy_call = hook_nfsclnt;
            printf("[GREY FOX] Hooked SYS_nfsclnt\n");
            break;
        case SYS_minherit:
            kernel_functions[SYS_minherit] = (void*)sysent[SYS_minherit].sy_call;
            sysent[SYS_minherit].sy_call = hook_minherit;
            printf("[GREY FOX] Hooked SYS_minherit\n");
            break;
        case SYS_semsys:
            kernel_functions[SYS_semsys] = (void*)sysent[SYS_semsys].sy_call;
            sysent[SYS_semsys].sy_call = hook_semsys;
            printf("[GREY FOX] Hooked SYS_semsys\n");
            break;
        case SYS_msgsys:
            kernel_functions[SYS_msgsys] = (void*)sysent[SYS_msgsys].sy_call;
            sysent[SYS_msgsys].sy_call = hook_msgsys;
            printf("[GREY FOX] Hooked SYS_msgsys\n");
            break;
        case SYS_shmsys:
            kernel_functions[SYS_shmsys] = (void*)sysent[SYS_shmsys].sy_call;
            sysent[SYS_shmsys].sy_call = hook_shmsys;
            printf("[GREY FOX] Hooked SYS_shmsys\n");
            break;
        case SYS_semctl:
            kernel_functions[SYS_semctl] = (void*)sysent[SYS_semctl].sy_call;
            sysent[SYS_semctl].sy_call = hook_semctl;
            printf("[GREY FOX] Hooked SYS_semctl\n");
            break;
        case SYS_semget:
            kernel_functions[SYS_semget] = (void*)sysent[SYS_semget].sy_call;
            sysent[SYS_semget].sy_call = hook_semget;
            printf("[GREY FOX] Hooked SYS_semget\n");
            break;
        case SYS_semop:
            kernel_functions[SYS_semop] = (void*)sysent[SYS_semop].sy_call;
            sysent[SYS_semop].sy_call = hook_semop;
            printf("[GREY FOX] Hooked SYS_semop\n");
            break;
        case SYS_msgctl:
            kernel_functions[SYS_msgctl] = (void*)sysent[SYS_msgctl].sy_call;
            sysent[SYS_msgctl].sy_call = hook_msgctl;
            printf("[GREY FOX] Hooked SYS_msgctl\n");
            break;
        case SYS_msgget:
            kernel_functions[SYS_msgget] = (void*)sysent[SYS_msgget].sy_call;
            sysent[SYS_msgget].sy_call = hook_msgget;
            printf("[GREY FOX] Hooked SYS_msgget\n");
            break;
        case SYS_msgsnd:
            kernel_functions[SYS_msgsnd] = (void*)sysent[SYS_msgsnd].sy_call;
            sysent[SYS_msgsnd].sy_call = hook_msgsnd;
            printf("[GREY FOX] Hooked SYS_msgsnd\n");
            break;
        case SYS_msgrcv:
            kernel_functions[SYS_msgrcv] = (void*)sysent[SYS_msgrcv].sy_call;
            sysent[SYS_msgrcv].sy_call = hook_msgrcv;
            printf("[GREY FOX] Hooked SYS_msgrcv\n");
            break;
        case SYS_shmat:
            kernel_functions[SYS_shmat] = (void*)sysent[SYS_shmat].sy_call;
            sysent[SYS_shmat].sy_call = hook_shmat;
            printf("[GREY FOX] Hooked SYS_shmat\n");
            break;
        case SYS_shmctl:
            kernel_functions[SYS_shmctl] = (void*)sysent[SYS_shmctl].sy_call;
            sysent[SYS_shmctl].sy_call = hook_shmctl;
            printf("[GREY FOX] Hooked SYS_shmctl\n");
            break;
        case SYS_shmdt:
            kernel_functions[SYS_shmdt] = (void*)sysent[SYS_shmdt].sy_call;
            sysent[SYS_shmdt].sy_call = hook_shmdt;
            printf("[GREY FOX] Hooked SYS_shmdt\n");
            break;
        case SYS_shmget:
            kernel_functions[SYS_shmget] = (void*)sysent[SYS_shmget].sy_call;
            sysent[SYS_shmget].sy_call = hook_shmget;
            printf("[GREY FOX] Hooked SYS_shmget\n");
            break;
        case SYS_shm_open:
            kernel_functions[SYS_shm_open] = (void*)sysent[SYS_shm_open].sy_call;
            sysent[SYS_shm_open].sy_call = hook_shm_open;
            printf("[GREY FOX] Hooked SYS_shm_open\n");
            break;
        case SYS_shm_unlink:
            kernel_functions[SYS_shm_unlink] = (void*)sysent[SYS_shm_unlink].sy_call;
            sysent[SYS_shm_unlink].sy_call = hook_shm_unlink;
            printf("[GREY FOX] Hooked SYS_shm_unlink\n");
            break;
        case SYS_sem_close:
            kernel_functions[SYS_sem_close] = (void*)sysent[SYS_sem_close].sy_call;
            sysent[SYS_sem_close].sy_call = hook_sem_close;
            printf("[GREY FOX] Hooked SYS_sem_close\n");
            break;
        case SYS_sem_unlink:
            kernel_functions[SYS_sem_unlink] = (void*)sysent[SYS_sem_unlink].sy_call;
            sysent[SYS_sem_unlink].sy_call = hook_sem_unlink;
            printf("[GREY FOX] Hooked SYS_sem_unlink\n");
            break;
        case SYS_sem_wait:
            kernel_functions[SYS_sem_wait] = (void*)sysent[SYS_sem_wait].sy_call;
            sysent[SYS_sem_wait].sy_call = hook_sem_wait;
            printf("[GREY FOX] Hooked SYS_sem_wait\n");
            break;
        case SYS_sem_trywait:
            kernel_functions[SYS_sem_trywait] = (void*)sysent[SYS_sem_trywait].sy_call;
            sysent[SYS_sem_trywait].sy_call = hook_sem_trywait;
            printf("[GREY FOX] Hooked SYS_sem_trywait\n");
            break;
        case SYS_sem_post:
            kernel_functions[SYS_sem_post] = (void*)sysent[SYS_sem_post].sy_call;
            sysent[SYS_sem_post].sy_call = hook_sem_post;
            printf("[GREY FOX] Hooked SYS_sem_post\n");
            break;
        case SYS_sem_init:
            kernel_functions[SYS_sem_init] = (void*)sysent[SYS_sem_init].sy_call;
            sysent[SYS_sem_init].sy_call = hook_sem_init;
            printf("[GREY FOX] Hooked SYS_sem_init\n");
            break;
        case SYS_sem_destroy:
            kernel_functions[SYS_sem_destroy] = (void*)sysent[SYS_sem_destroy].sy_call;
            sysent[SYS_sem_destroy].sy_call = hook_sem_destroy;
            printf("[GREY FOX] Hooked SYS_sem_destroy\n");
            break;
        case SYS_open_extended:
            kernel_functions[SYS_open_extended] = (void*)sysent[SYS_open_extended].sy_call;
            sysent[SYS_open_extended].sy_call = hook_open_extended;
            printf("[GREY FOX] Hooked SYS_open_extended\n");
            break;
        case SYS_umask_extended:
            kernel_functions[SYS_umask_extended] = (void*)sysent[SYS_umask_extended].sy_call;
            sysent[SYS_umask_extended].sy_call = hook_umask_extended;
            printf("[GREY FOX] Hooked SYS_umask_extended\n");
            break;
        case SYS_stat_extended:
            kernel_functions[SYS_stat_extended] = (void*)sysent[SYS_stat_extended].sy_call;
            sysent[SYS_stat_extended].sy_call = hook_stat_extended;
            printf("[GREY FOX] Hooked SYS_stat_extended\n");
            break;
        case SYS_lstat_extended:
            kernel_functions[SYS_lstat_extended] = (void*)sysent[SYS_lstat_extended].sy_call;
            sysent[SYS_lstat_extended].sy_call = hook_lstat_extended;
            printf("[GREY FOX] Hooked SYS_lstat_extended\n");
            break;
        case SYS_fstat_extended:
            kernel_functions[SYS_fstat_extended] = (void*)sysent[SYS_fstat_extended].sy_call;
            sysent[SYS_fstat_extended].sy_call = hook_fstat_extended;
            printf("[GREY FOX] Hooked SYS_fstat_extended\n");
            break;
        case SYS_chmod_extended:
            kernel_functions[SYS_chmod_extended] = (void*)sysent[SYS_chmod_extended].sy_call;
            sysent[SYS_chmod_extended].sy_call = hook_chmod_extended;
            printf("[GREY FOX] Hooked SYS_chmod_extended\n");
            break;
        case SYS_fchmod_extended:
            kernel_functions[SYS_fchmod_extended] = (void*)sysent[SYS_fchmod_extended].sy_call;
            sysent[SYS_fchmod_extended].sy_call = hook_fchmod_extended;
            printf("[GREY FOX] Hooked SYS_fchmod_extended\n");
            break;
        case SYS_access_extended:
            kernel_functions[SYS_access_extended] = (void*)sysent[SYS_access_extended].sy_call;
            sysent[SYS_access_extended].sy_call = hook_access_extended;
            printf("[GREY FOX] Hooked SYS_access_extended\n");
            break;
        case SYS_settid:
            kernel_functions[SYS_settid] = (void*)sysent[SYS_settid].sy_call;
            sysent[SYS_settid].sy_call = hook_settid;
            printf("[GREY FOX] Hooked SYS_settid\n");
            break;
        case SYS_setsgroups:
            kernel_functions[SYS_setsgroups] = (void*)sysent[SYS_setsgroups].sy_call;
            sysent[SYS_setsgroups].sy_call = hook_setsgroups;
            printf("[GREY FOX] Hooked SYS_setsgroups\n");
            break;
        case SYS_getsgroups:
            kernel_functions[SYS_getsgroups] = (void*)sysent[SYS_getsgroups].sy_call;
            sysent[SYS_getsgroups].sy_call = hook_getsgroups;
            printf("[GREY FOX] Hooked SYS_getsgroups\n");
            break;
        case SYS_setwgroups:
            kernel_functions[SYS_setwgroups] = (void*)sysent[SYS_setwgroups].sy_call;
            sysent[SYS_setwgroups].sy_call = hook_setwgroups;
            printf("[GREY FOX] Hooked SYS_setwgroups\n");
            break;
        case SYS_getwgroups:
            kernel_functions[SYS_getwgroups] = (void*)sysent[SYS_getwgroups].sy_call;
            sysent[SYS_getwgroups].sy_call = hook_getwgroups;
            printf("[GREY FOX] Hooked SYS_getwgroups\n");
            break;
        case SYS_mkfifo_extended:
            kernel_functions[SYS_mkfifo_extended] = (void*)sysent[SYS_mkfifo_extended].sy_call;
            sysent[SYS_mkfifo_extended].sy_call = hook_mkfifo_extended;
            printf("[GREY FOX] Hooked SYS_mkfifo_extended\n");
            break;
        case SYS_identitysvc:
            kernel_functions[SYS_identitysvc] = (void*)sysent[SYS_identitysvc].sy_call;
            sysent[SYS_identitysvc].sy_call = hook_identitysvc;
            printf("[GREY FOX] Hooked SYS_identitysvc\n");
            break;
        case SYS_shared_region_check_np:
            kernel_functions[SYS_shared_region_check_np] = (void*)sysent[SYS_shared_region_check_np].sy_call;
            sysent[SYS_shared_region_check_np].sy_call = hook_shared_region_check_np;
            printf("[GREY FOX] Hooked SYS_shared_region_check_np\n");
            break;
        case SYS_vm_pressure_monitor:
            kernel_functions[SYS_vm_pressure_monitor] = (void*)sysent[SYS_vm_pressure_monitor].sy_call;
            sysent[SYS_vm_pressure_monitor].sy_call = hook_vm_pressure_monitor;
            printf("[GREY FOX] Hooked SYS_vm_pressure_monitor\n");
            break;
        case SYS_psynch_rw_longrdlock:
            kernel_functions[SYS_psynch_rw_longrdlock] = (void*)sysent[SYS_psynch_rw_longrdlock].sy_call;
            sysent[SYS_psynch_rw_longrdlock].sy_call = hook_psynch_rw_longrdlock;
            printf("[GREY FOX] Hooked SYS_psynch_rw_longrdlock\n");
            break;
        case SYS_psynch_rw_yieldwrlock:
            kernel_functions[SYS_psynch_rw_yieldwrlock] = (void*)sysent[SYS_psynch_rw_yieldwrlock].sy_call;
            sysent[SYS_psynch_rw_yieldwrlock].sy_call = hook_psynch_rw_yieldwrlock;
            printf("[GREY FOX] Hooked SYS_psynch_rw_yieldwrlock\n");
            break;
        case SYS_psynch_rw_downgrade:
            kernel_functions[SYS_psynch_rw_downgrade] = (void*)sysent[SYS_psynch_rw_downgrade].sy_call;
            sysent[SYS_psynch_rw_downgrade].sy_call = hook_psynch_rw_downgrade;
            printf("[GREY FOX] Hooked SYS_psynch_rw_downgrade\n");
            break;
        case SYS_psynch_rw_upgrade:
            kernel_functions[SYS_psynch_rw_upgrade] = (void*)sysent[SYS_psynch_rw_upgrade].sy_call;
            sysent[SYS_psynch_rw_upgrade].sy_call = hook_psynch_rw_upgrade;
            printf("[GREY FOX] Hooked SYS_psynch_rw_upgrade\n");
            break;
        case SYS_psynch_rw_unlock2:
            kernel_functions[SYS_psynch_rw_unlock2] = (void*)sysent[SYS_psynch_rw_unlock2].sy_call;
            sysent[SYS_psynch_rw_unlock2].sy_call = hook_psynch_rw_unlock2;
            printf("[GREY FOX] Hooked SYS_psynch_rw_unlock2\n");
            break;
        case SYS_getsid:
            kernel_functions[SYS_getsid] = (void*)sysent[SYS_getsid].sy_call;
            sysent[SYS_getsid].sy_call = hook_getsid;
            printf("[GREY FOX] Hooked SYS_getsid\n");
            break;
        case SYS_settid_with_pid:
            kernel_functions[SYS_settid_with_pid] = (void*)sysent[SYS_settid_with_pid].sy_call;
            sysent[SYS_settid_with_pid].sy_call = hook_settid_with_pid;
            printf("[GREY FOX] Hooked SYS_settid_with_pid\n");
            break;
        case SYS_psynch_cvclrprepost:
            kernel_functions[SYS_psynch_cvclrprepost] = (void*)sysent[SYS_psynch_cvclrprepost].sy_call;
            sysent[SYS_psynch_cvclrprepost].sy_call = hook_psynch_cvclrprepost;
            printf("[GREY FOX] Hooked SYS_psynch_cvclrprepost\n");
            break;
        case SYS_aio_fsync:
            kernel_functions[SYS_aio_fsync] = (void*)sysent[SYS_aio_fsync].sy_call;
            sysent[SYS_aio_fsync].sy_call = hook_aio_fsync;
            printf("[GREY FOX] Hooked SYS_aio_fsync\n");
            break;
        case SYS_aio_return:
            kernel_functions[SYS_aio_return] = (void*)sysent[SYS_aio_return].sy_call;
            sysent[SYS_aio_return].sy_call = hook_aio_return;
            printf("[GREY FOX] Hooked SYS_aio_return\n");
            break;
        case SYS_aio_suspend:
            kernel_functions[SYS_aio_suspend] = (void*)sysent[SYS_aio_suspend].sy_call;
            sysent[SYS_aio_suspend].sy_call = hook_aio_suspend;
            printf("[GREY FOX] Hooked SYS_aio_suspend\n");
            break;
        case SYS_aio_cancel:
            kernel_functions[SYS_aio_cancel] = (void*)sysent[SYS_aio_cancel].sy_call;
            sysent[SYS_aio_cancel].sy_call = hook_aio_cancel;
            printf("[GREY FOX] Hooked SYS_aio_cancel\n");
            break;
        case SYS_aio_error:
            kernel_functions[SYS_aio_error] = (void*)sysent[SYS_aio_error].sy_call;
            sysent[SYS_aio_error].sy_call = hook_aio_error;
            printf("[GREY FOX] Hooked SYS_aio_error\n");
            break;
        case SYS_aio_read:
            kernel_functions[SYS_aio_read] = (void*)sysent[SYS_aio_read].sy_call;
            sysent[SYS_aio_read].sy_call = hook_aio_read;
            printf("[GREY FOX] Hooked SYS_aio_read\n");
            break;
        case SYS_aio_write:
            kernel_functions[SYS_aio_write] = (void*)sysent[SYS_aio_write].sy_call;
            sysent[SYS_aio_write].sy_call = hook_aio_write;
            printf("[GREY FOX] Hooked SYS_aio_write\n");
            break;
        case SYS_lio_listio:
            kernel_functions[SYS_lio_listio] = (void*)sysent[SYS_lio_listio].sy_call;
            sysent[SYS_lio_listio].sy_call = hook_lio_listio;
            printf("[GREY FOX] Hooked SYS_lio_listio\n");
            break;
//        extensivly used by com.apple.WebKit
//        case SYS_process_policy:
//            kernel_functions[SYS_process_policy] = (void*)sysent[SYS_process_policy].sy_call;
//            sysent[SYS_process_policy].sy_call = hook_process_policy;
//            printf("[GREY FOX] Hooked SYS_process_policy\n");
//            break;
        case SYS_mlockall:
            kernel_functions[SYS_mlockall] = (void*)sysent[SYS_mlockall].sy_call;
            sysent[SYS_mlockall].sy_call = hook_mlockall;
            printf("[GREY FOX] Hooked SYS_mlockall\n");
            break;
        case SYS_munlockall:
            kernel_functions[SYS_munlockall] = (void*)sysent[SYS_munlockall].sy_call;
            sysent[SYS_munlockall].sy_call = hook_munlockall;
            printf("[GREY FOX] Hooked SYS_munlockall\n");
            break;
        case SYS___pthread_kill:
            kernel_functions[SYS___pthread_kill] = (void*)sysent[SYS___pthread_kill].sy_call;
            sysent[SYS___pthread_kill].sy_call = hook___pthread_kill;
            printf("[GREY FOX] Hooked SYS___pthread_kill\n");
            break;
        case SYS___sigwait:
            kernel_functions[SYS___sigwait] = (void*)sysent[SYS___sigwait].sy_call;
            sysent[SYS___sigwait].sy_call = hook___sigwait;
            printf("[GREY FOX] Hooked SYS___sigwait\n");
            break;
        case SYS___pthread_markcancel:
            kernel_functions[SYS___pthread_markcancel] = (void*)sysent[SYS___pthread_markcancel].sy_call;
            sysent[SYS___pthread_markcancel].sy_call = hook___pthread_markcancel;
            printf("[GREY FOX] Hooked SYS___pthread_markcancel\n");
            break;
        case SYS_sendfile:
            kernel_functions[SYS_sendfile] = (void*)sysent[SYS_sendfile].sy_call;
            sysent[SYS_sendfile].sy_call = hook_sendfile;
            printf("[GREY FOX] Hooked SYS_sendfile\n");
            break;
        case SYS_stat64_extended:
            kernel_functions[SYS_stat64_extended] = (void*)sysent[SYS_stat64_extended].sy_call;
            sysent[SYS_stat64_extended].sy_call = hook_stat64_extended;
            printf("[GREY FOX] Hooked SYS_stat64_extended\n");
            break;
        case SYS_lstat64_extended:
            kernel_functions[SYS_lstat64_extended] = (void*)sysent[SYS_lstat64_extended].sy_call;
            sysent[SYS_lstat64_extended].sy_call = hook_lstat64_extended;
            printf("[GREY FOX] Hooked SYS_lstat64_extended\n");
            break;
        case SYS_fstat64_extended:
            kernel_functions[SYS_fstat64_extended] = (void*)sysent[SYS_fstat64_extended].sy_call;
            sysent[SYS_fstat64_extended].sy_call = hook_fstat64_extended;
            printf("[GREY FOX] Hooked SYS_fstat64_extended\n");
            break;
        case SYS_audit:
            kernel_functions[SYS_audit] = (void*)sysent[SYS_audit].sy_call;
            sysent[SYS_audit].sy_call = hook_audit;
            printf("[GREY FOX] Hooked SYS_audit\n");
            break;
        case SYS_auditon:
            kernel_functions[SYS_auditon] = (void*)sysent[SYS_auditon].sy_call;
            sysent[SYS_auditon].sy_call = hook_auditon;
            printf("[GREY FOX] Hooked SYS_auditon\n");
            break;
        case SYS_getauid:
            kernel_functions[SYS_getauid] = (void*)sysent[SYS_getauid].sy_call;
            sysent[SYS_getauid].sy_call = hook_getauid;
            printf("[GREY FOX] Hooked SYS_getauid\n");
            break;
        case SYS_setauid:
            kernel_functions[SYS_setauid] = (void*)sysent[SYS_setauid].sy_call;
            sysent[SYS_setauid].sy_call = hook_setauid;
            printf("[GREY FOX] Hooked SYS_setauid\n");
            break;
        case SYS_setaudit_addr:
            kernel_functions[SYS_setaudit_addr] = (void*)sysent[SYS_setaudit_addr].sy_call;
            sysent[SYS_setaudit_addr].sy_call = hook_setaudit_addr;
            printf("[GREY FOX] Hooked SYS_setaudit_addr\n");
            break;
        case SYS_auditctl:
            kernel_functions[SYS_auditctl] = (void*)sysent[SYS_auditctl].sy_call;
            sysent[SYS_auditctl].sy_call = hook_auditctl;
            printf("[GREY FOX] Hooked SYS_auditctl\n");
            break;
        case SYS_lchown:
            kernel_functions[SYS_lchown] = (void*)sysent[SYS_lchown].sy_call;
            sysent[SYS_lchown].sy_call = hook_lchown;
            printf("[GREY FOX] Hooked SYS_lchown\n");
            break;
        case SYS_stack_snapshot:
            kernel_functions[SYS_stack_snapshot] = (void*)sysent[SYS_stack_snapshot].sy_call;
            sysent[SYS_stack_snapshot].sy_call = hook_stack_snapshot;
            printf("[GREY FOX] Hooked SYS_stack_snapshot\n");
            break;
        case SYS___mac_execve:
            kernel_functions[SYS___mac_execve] = (void*)sysent[SYS___mac_execve].sy_call;
            sysent[SYS___mac_execve].sy_call = hook___mac_execve;
            printf("[GREY FOX] Hooked SYS___mac_execve\n");
            break;
        case SYS___mac_get_file:
            kernel_functions[SYS___mac_get_file] = (void*)sysent[SYS___mac_get_file].sy_call;
            sysent[SYS___mac_get_file].sy_call = hook___mac_get_file;
            printf("[GREY FOX] Hooked SYS___mac_get_file\n");
            break;
        case SYS___mac_set_file:
            kernel_functions[SYS___mac_set_file] = (void*)sysent[SYS___mac_set_file].sy_call;
            sysent[SYS___mac_set_file].sy_call = hook___mac_set_file;
            printf("[GREY FOX] Hooked SYS___mac_set_file\n");
            break;
        case SYS___mac_get_link:
            kernel_functions[SYS___mac_get_link] = (void*)sysent[SYS___mac_get_link].sy_call;
            sysent[SYS___mac_get_link].sy_call = hook___mac_get_link;
            printf("[GREY FOX] Hooked SYS___mac_get_link\n");
            break;
        case SYS___mac_set_link:
            kernel_functions[SYS___mac_set_link] = (void*)sysent[SYS___mac_set_link].sy_call;
            sysent[SYS___mac_set_link].sy_call = hook___mac_set_link;
            printf("[GREY FOX] Hooked SYS___mac_set_link\n");
            break;
        case SYS___mac_get_proc:
            kernel_functions[SYS___mac_get_proc] = (void*)sysent[SYS___mac_get_proc].sy_call;
            sysent[SYS___mac_get_proc].sy_call = hook___mac_get_proc;
            printf("[GREY FOX] Hooked SYS___mac_get_proc\n");
            break;
        case SYS___mac_set_proc:
            kernel_functions[SYS___mac_set_proc] = (void*)sysent[SYS___mac_set_proc].sy_call;
            sysent[SYS___mac_set_proc].sy_call = hook___mac_set_proc;
            printf("[GREY FOX] Hooked SYS___mac_set_proc\n");
            break;
        case SYS___mac_get_fd:
            kernel_functions[SYS___mac_get_fd] = (void*)sysent[SYS___mac_get_fd].sy_call;
            sysent[SYS___mac_get_fd].sy_call = hook___mac_get_fd;
            printf("[GREY FOX] Hooked SYS___mac_get_fd\n");
            break;
        case SYS___mac_set_fd:
            kernel_functions[SYS___mac_set_fd] = (void*)sysent[SYS___mac_set_fd].sy_call;
            sysent[SYS___mac_set_fd].sy_call = hook___mac_set_fd;
            printf("[GREY FOX] Hooked SYS___mac_set_fd\n");
            break;
        case SYS___mac_get_pid:
            kernel_functions[SYS___mac_get_pid] = (void*)sysent[SYS___mac_get_pid].sy_call;
            sysent[SYS___mac_get_pid].sy_call = hook___mac_get_pid;
            printf("[GREY FOX] Hooked SYS___mac_get_pid\n");
            break;
        case SYS___mac_get_lcid:
            kernel_functions[SYS___mac_get_lcid] = (void*)sysent[SYS___mac_get_lcid].sy_call;
            sysent[SYS___mac_get_lcid].sy_call = hook___mac_get_lcid;
            printf("[GREY FOX] Hooked SYS___mac_get_lcid\n");
            break;
        case SYS___mac_get_lctx:
            kernel_functions[SYS___mac_get_lctx] = (void*)sysent[SYS___mac_get_lctx].sy_call;
            sysent[SYS___mac_get_lctx].sy_call = hook___mac_get_lctx;
            printf("[GREY FOX] Hooked SYS___mac_get_lctx\n");
            break;
        case SYS___mac_set_lctx:
            kernel_functions[SYS___mac_set_lctx] = (void*)sysent[SYS___mac_set_lctx].sy_call;
            sysent[SYS___mac_set_lctx].sy_call = hook___mac_set_lctx;
            printf("[GREY FOX] Hooked SYS___mac_set_lctx\n");
            break;
        case SYS_setlcid:
            kernel_functions[SYS_setlcid] = (void*)sysent[SYS_setlcid].sy_call;
            sysent[SYS_setlcid].sy_call = hook_setlcid;
            printf("[GREY FOX] Hooked SYS_setlcid\n");
            break;
        case SYS_getlcid:
            kernel_functions[SYS_getlcid] = (void*)sysent[SYS_getlcid].sy_call;
            sysent[SYS_getlcid].sy_call = hook_getlcid;
            printf("[GREY FOX] Hooked SYS_getlcid\n");
            break;
        case SYS_wait4_nocancel:
            kernel_functions[SYS_wait4_nocancel] = (void*)sysent[SYS_wait4_nocancel].sy_call;
            sysent[SYS_wait4_nocancel].sy_call = hook_wait4_nocancel;
            printf("[GREY FOX] Hooked SYS_wait4_nocancel\n");
            break;
        case SYS_recvmsg_nocancel:
            kernel_functions[SYS_recvmsg_nocancel] = (void*)sysent[SYS_recvmsg_nocancel].sy_call;
            sysent[SYS_recvmsg_nocancel].sy_call = hook_recvmsg_nocancel;
            printf("[GREY FOX] Hooked SYS_recvmsg_nocancel\n");
            break;
        case SYS_sendmsg_nocancel:
            kernel_functions[SYS_sendmsg_nocancel] = (void*)sysent[SYS_sendmsg_nocancel].sy_call;
            sysent[SYS_sendmsg_nocancel].sy_call = hook_sendmsg_nocancel;
            printf("[GREY FOX] Hooked SYS_sendmsg_nocancel\n");
            break;
        case SYS_recvfrom_nocancel:
            kernel_functions[SYS_recvfrom_nocancel] = (void*)sysent[SYS_recvfrom_nocancel].sy_call;
            sysent[SYS_recvfrom_nocancel].sy_call = hook_recvfrom_nocancel;
            printf("[GREY FOX] Hooked SYS_recvfrom_nocancel\n");
            break;
        case SYS_accept_nocancel:
            kernel_functions[SYS_accept_nocancel] = (void*)sysent[SYS_accept_nocancel].sy_call;
            sysent[SYS_accept_nocancel].sy_call = hook_accept_nocancel;
            printf("[GREY FOX] Hooked SYS_accept_nocancel\n");
            break;
        case SYS_msync_nocancel:
            kernel_functions[SYS_msync_nocancel] = (void*)sysent[SYS_msync_nocancel].sy_call;
            sysent[SYS_msync_nocancel].sy_call = hook_msync_nocancel;
            printf("[GREY FOX] Hooked SYS_msync_nocancel\n");
            break;
        case SYS_select_nocancel:
            kernel_functions[SYS_select_nocancel] = (void*)sysent[SYS_select_nocancel].sy_call;
            sysent[SYS_select_nocancel].sy_call = hook_select_nocancel;
            printf("[GREY FOX] Hooked SYS_select_nocancel\n");
            break;
        case SYS_fsync_nocancel:
            kernel_functions[SYS_fsync_nocancel] = (void*)sysent[SYS_fsync_nocancel].sy_call;
            sysent[SYS_fsync_nocancel].sy_call = hook_fsync_nocancel;
            printf("[GREY FOX] Hooked SYS_fsync_nocancel\n");
            break;
        case SYS_connect_nocancel:
            kernel_functions[SYS_connect_nocancel] = (void*)sysent[SYS_connect_nocancel].sy_call;
            sysent[SYS_connect_nocancel].sy_call = hook_connect_nocancel;
            printf("[GREY FOX] Hooked SYS_connect_nocancel\n");
            break;
        case SYS_sigsuspend_nocancel:
            kernel_functions[SYS_sigsuspend_nocancel] = (void*)sysent[SYS_sigsuspend_nocancel].sy_call;
            sysent[SYS_sigsuspend_nocancel].sy_call = hook_sigsuspend_nocancel;
            printf("[GREY FOX] Hooked SYS_sigsuspend_nocancel\n");
            break;
        case SYS_readv_nocancel:
            kernel_functions[SYS_readv_nocancel] = (void*)sysent[SYS_readv_nocancel].sy_call;
            sysent[SYS_readv_nocancel].sy_call = hook_readv_nocancel;
            printf("[GREY FOX] Hooked SYS_readv_nocancel\n");
            break;
        case SYS_writev_nocancel:
            kernel_functions[SYS_writev_nocancel] = (void*)sysent[SYS_writev_nocancel].sy_call;
            sysent[SYS_writev_nocancel].sy_call = hook_writev_nocancel;
            printf("[GREY FOX] Hooked SYS_writev_nocancel\n");
            break;
        case SYS_sendto_nocancel:
            kernel_functions[SYS_sendto_nocancel] = (void*)sysent[SYS_sendto_nocancel].sy_call;
            sysent[SYS_sendto_nocancel].sy_call = hook_sendto_nocancel;
            printf("[GREY FOX] Hooked SYS_sendto_nocancel\n");
            break;
        case SYS_pread_nocancel:
            kernel_functions[SYS_pread_nocancel] = (void*)sysent[SYS_pread_nocancel].sy_call;
            sysent[SYS_pread_nocancel].sy_call = hook_pread_nocancel;
            printf("[GREY FOX] Hooked SYS_pread_nocancel\n");
            break;
        case SYS_pwrite_nocancel:
            kernel_functions[SYS_pwrite_nocancel] = (void*)sysent[SYS_pwrite_nocancel].sy_call;
            sysent[SYS_pwrite_nocancel].sy_call = hook_pwrite_nocancel;
            printf("[GREY FOX] Hooked SYS_pwrite_nocancel\n");
            break;
        case SYS_waitid_nocancel:
            kernel_functions[SYS_waitid_nocancel] = (void*)sysent[SYS_waitid_nocancel].sy_call;
            sysent[SYS_waitid_nocancel].sy_call = hook_waitid_nocancel;
            printf("[GREY FOX] Hooked SYS_waitid_nocancel\n");
            break;
        case SYS_poll_nocancel:
            kernel_functions[SYS_poll_nocancel] = (void*)sysent[SYS_poll_nocancel].sy_call;
            sysent[SYS_poll_nocancel].sy_call = hook_poll_nocancel;
            printf("[GREY FOX] Hooked SYS_poll_nocancel\n");
            break;
        case SYS_msgsnd_nocancel:
            kernel_functions[SYS_msgsnd_nocancel] = (void*)sysent[SYS_msgsnd_nocancel].sy_call;
            sysent[SYS_msgsnd_nocancel].sy_call = hook_msgsnd_nocancel;
            printf("[GREY FOX] Hooked SYS_msgsnd_nocancel\n");
            break;
        case SYS_msgrcv_nocancel:
            kernel_functions[SYS_msgrcv_nocancel] = (void*)sysent[SYS_msgrcv_nocancel].sy_call;
            sysent[SYS_msgrcv_nocancel].sy_call = hook_msgrcv_nocancel;
            printf("[GREY FOX] Hooked SYS_msgrcv_nocancel\n");
            break;
        case SYS_sem_wait_nocancel:
            kernel_functions[SYS_sem_wait_nocancel] = (void*)sysent[SYS_sem_wait_nocancel].sy_call;
            sysent[SYS_sem_wait_nocancel].sy_call = hook_sem_wait_nocancel;
            printf("[GREY FOX] Hooked SYS_sem_wait_nocancel\n");
            break;
        case SYS_aio_suspend_nocancel:
            kernel_functions[SYS_aio_suspend_nocancel] = (void*)sysent[SYS_aio_suspend_nocancel].sy_call;
            sysent[SYS_aio_suspend_nocancel].sy_call = hook_aio_suspend_nocancel;
            printf("[GREY FOX] Hooked SYS_aio_suspend_nocancel\n");
            break;
        case SYS___sigwait_nocancel:
            kernel_functions[SYS___sigwait_nocancel] = (void*)sysent[SYS___sigwait_nocancel].sy_call;
            sysent[SYS___sigwait_nocancel].sy_call = hook___sigwait_nocancel;
            printf("[GREY FOX] Hooked SYS___sigwait_nocancel\n");
            break;
        case SYS___semwait_signal_nocancel:
            kernel_functions[SYS___semwait_signal_nocancel] = (void*)sysent[SYS___semwait_signal_nocancel].sy_call;
            sysent[SYS___semwait_signal_nocancel].sy_call = hook___semwait_signal_nocancel;
            printf("[GREY FOX] Hooked SYS___semwait_signal_nocancel\n");
            break;
        case SYS___mac_mount:
            kernel_functions[SYS___mac_mount] = (void*)sysent[SYS___mac_mount].sy_call;
            sysent[SYS___mac_mount].sy_call = hook___mac_mount;
            printf("[GREY FOX] Hooked SYS___mac_mount\n");
            break;
        case SYS___mac_get_mount:
            kernel_functions[SYS___mac_get_mount] = (void*)sysent[SYS___mac_get_mount].sy_call;
            sysent[SYS___mac_get_mount].sy_call = hook___mac_get_mount;
            printf("[GREY FOX] Hooked SYS___mac_get_mount\n");
            break;
        case SYS___mac_getfsstat:
            kernel_functions[SYS___mac_getfsstat] = (void*)sysent[SYS___mac_getfsstat].sy_call;
            sysent[SYS___mac_getfsstat].sy_call = hook___mac_getfsstat;
            printf("[GREY FOX] Hooked SYS___mac_getfsstat\n");
            break;
        case SYS_audit_session_self:
            kernel_functions[SYS_audit_session_self] = (void*)sysent[SYS_audit_session_self].sy_call;
            sysent[SYS_audit_session_self].sy_call = hook_audit_session_self;
            printf("[GREY FOX] Hooked SYS_audit_session_self\n");
            break;
        case SYS_audit_session_join:
            kernel_functions[SYS_audit_session_join] = (void*)sysent[SYS_audit_session_join].sy_call;
            sysent[SYS_audit_session_join].sy_call = hook_audit_session_join;
            printf("[GREY FOX] Hooked SYS_audit_session_join\n");
            break;
        case SYS_fileport_makeport:
            kernel_functions[SYS_fileport_makeport] = (void*)sysent[SYS_fileport_makeport].sy_call;
            sysent[SYS_fileport_makeport].sy_call = hook_fileport_makeport;
            printf("[GREY FOX] Hooked SYS_fileport_makeport\n");
            break;
        case SYS_fileport_makefd:
            kernel_functions[SYS_fileport_makefd] = (void*)sysent[SYS_fileport_makefd].sy_call;
            sysent[SYS_fileport_makefd].sy_call = hook_fileport_makefd;
            printf("[GREY FOX] Hooked SYS_fileport_makefd\n");
            break;
        case SYS_audit_session_port:
            kernel_functions[SYS_audit_session_port] = (void*)sysent[SYS_audit_session_port].sy_call;
            sysent[SYS_audit_session_port].sy_call = hook_audit_session_port;
            printf("[GREY FOX] Hooked SYS_audit_session_port\n");
            break;
        case SYS_pid_suspend:
            kernel_functions[SYS_pid_suspend] = (void*)sysent[SYS_pid_suspend].sy_call;
            sysent[SYS_pid_suspend].sy_call = hook_pid_suspend;
            printf("[GREY FOX] Hooked SYS_pid_suspend\n");
            break;
        case SYS_pid_resume:
            kernel_functions[SYS_pid_resume] = (void*)sysent[SYS_pid_resume].sy_call;
            sysent[SYS_pid_resume].sy_call = hook_pid_resume;
            printf("[GREY FOX] Hooked SYS_pid_resume\n");
            break;
        case SYS_shared_region_map_and_slide_np:
            kernel_functions[SYS_shared_region_map_and_slide_np] = (void*)sysent[SYS_shared_region_map_and_slide_np].sy_call;
            sysent[SYS_shared_region_map_and_slide_np].sy_call = hook_shared_region_map_and_slide_np;
            printf("[GREY FOX] Hooked SYS_shared_region_map_and_slide_np\n");
            break;
        case SYS_kas_info:
            kernel_functions[SYS_kas_info] = (void*)sysent[SYS_kas_info].sy_call;
            sysent[SYS_kas_info].sy_call = hook_kas_info;
            printf("[GREY FOX] Hooked SYS_kas_info\n");
            break;
        case SYS_ioctl:
            kernel_functions[SYS_ioctl] = (void*)sysent[SYS_ioctl].sy_call;
            sysent[SYS_ioctl].sy_call = hook_ioctl;
            printf("[GREY FOX] Hooked SYS_ioctl\n");
            break;

        default:
            printf("[GREY FOX] Unknown syscall: %d\n", syscall);
    }
    
    return KERN_SUCCESS;
}



kern_return_t unhook_syscall(void *sysent_addr, int32_t syscall) {
    
    switch (version_major) {
        case EL_CAPITAN:
            sysent = (struct sysent_yosemite*)sysent_addr;
            break;
        case YOSEMITE:
            sysent = (struct sysent_yosemite*)sysent_addr;
            break;
        case MAVERICKS:
            sysent = (struct sysent_mavericks*)sysent_addr;
            break;
        default:
            sysent = (struct sysent*)sysent_addr;
            break;
    }
    
    if (kernel_functions[syscall] != NULL) {
        sysent[syscall].sy_call = (sy_call_t*)kernel_functions[syscall];
        printf("[GREY FOX] Unhooked syscall %d\n", syscall);
    } else {
        printf("[GREY FOX] Syscall %d was not hooked...\n", syscall);
    }
    
    return KERN_SUCCESS;
}

// Prevents deadlocks by checking if the process is not a call from syslogd or kernel.
int should_i_log_this(struct proc *p) {
    char processname[MAXCOMLEN+1];
    pid_t pid = proc_pid(p);
    proc_name(pid, processname, sizeof(processname));
    return (pid != 0
            && (strcmp("syslogd", processname) != 0)
            && (strcmp("vmware-tools-dae", processname) != 0)
            && (strcmp("nsurlsessiond", processname) != 0)
                ) ? 1 : 0;
}

/* Apple Inc. implementation */
char* strstr(string, substring)
register char *string;	/* String to search. */
char *substring;		/* Substring to try to find in string. */
{
    register char *a, *b;
    b = substring;
    if (*b == 0)
        return string;
    for ( ; *string != 0; string += 1) {
        if (*string != *b)
            continue;
        a = string;
        while (1) {
            if (*b == 0)
                return string;
            if (*a++ != *b++)
                break;
        }
        b = substring;
    }
    return (char *) 0;
}

int is_root(struct proc *p) {
    int superusr = proc_suser(p);
    return superusr == 0;
}



/* Logs the imporant features of calling process to output. */
int generic_syscall_log(struct proc *p, struct args *a, char* syscall, kern_f k, int *r) {
    if (should_i_log_this(p)) {
        pid_t pid = proc_pid(p);
        pid_t ppid = proc_ppid(p);
        int superusr = is_root(p);
        char processname[MAXCOMLEN+1];
        proc_name(pid, processname, sizeof(processname));
        uint32_t secs = 0;
        uint32_t microsecs = 0;
        clock_get_system_microtime(&secs, &microsecs);
        uint32_t mins = secs/60;
        secs = secs%60;
        uint32_t hours = mins/60;
        //printf("[GREY FOX] %u, %u\n", secs, microsecs);
        if (strcmp("SYS_open", syscall) == 0) {
            struct open_args* oa = a;
            char path[MAXPATHLEN];
            size_t dummy = 0;
            int error = copyinstr((void *)oa->path, (void *)path, MAXPATHLEN, &dummy);
            if (!error) {
                if (strstr(path, "/.") != NULL) {
                    //printf("[GREY FOX] open hidden file path: %s\n",path);
                    kprintf("[GREY FOX] %u:%u:%u,%u; %s; %d; %d; %s; %d; %s;\n",
                           hours,
                           mins,
                           secs,
                           microsecs,
                           processname,
                           pid,
                           ppid,
                           syscall,
                           superusr,
                           path);
                }
            }
        } else {
            kprintf("[GREY FOX] %u:%u:%u,%u; %s; %d; %d; %s; %d;\n",
                   hours,
                   mins,
                   secs,
                   microsecs,
                   processname,
                   pid,
                   ppid,
                   syscall,
                   superusr);
        }
    }
    return k(p, a, r);
}

/* This crap is also generated automatically ofc.. */
int hook_read(struct proc *p, struct read_args *u, user_ssize_t *r) { return generic_syscall_log(p, u, "SYS_read", kernel_functions[SYS_read], r); }
int hook_write(struct proc *p, struct write_args *u, user_ssize_t *r) { return generic_syscall_log(p, u, "SYS_write", kernel_functions[SYS_write], r); }
int hook_open(struct proc *p, struct open_args *u, int *r) { return generic_syscall_log(p, u, "SYS_open", kernel_functions[SYS_open], r); }
int hook_link(struct proc *p, struct link_args *u, int *r) { return generic_syscall_log(p, u, "SYS_link", kernel_functions[SYS_link], r); }
int hook_unlink(struct proc *p, struct unlink_args *u, int *r) { return generic_syscall_log(p, u, "SYS_unlink", kernel_functions[SYS_unlink], r); }
int hook_fork(struct proc *p, struct fork_args *u, int *r) { return generic_syscall_log(p, u, "SYS_fork", kernel_functions[SYS_fork], r); }
int hook_mknod(struct proc *p, struct mknod_args *u, int *r) { return generic_syscall_log(p, u, "SYS_mknod", kernel_functions[SYS_mknod], r); }
int hook_chmod(struct proc *p, struct chmod_args *u, int *r) { return generic_syscall_log(p, u, "SYS_chmod", kernel_functions[SYS_chmod], r); }
int hook_chown(struct proc *p, struct chown_args *u, int *r) { return generic_syscall_log(p, u, "SYS_chown", kernel_functions[SYS_chown], r); }
int hook_getfsstat(struct proc *p, struct getfsstat_args *u, int *r) { return generic_syscall_log(p, u, "SYS_getfsstat", kernel_functions[SYS_getfsstat], r); }
int hook_setuid(struct proc *p, struct setuid_args *u, int *r) { return generic_syscall_log(p, u, "SYS_setuid", kernel_functions[SYS_setuid], r); }
int hook_geteuid(struct proc *p, struct geteuid_args *u, int *r) { return generic_syscall_log(p, u, "SYS_geteuid", kernel_functions[SYS_geteuid], r); }
int hook_ptrace(struct proc *p, struct ptrace_args *u, int *r) { return generic_syscall_log(p, u, "SYS_ptrace", kernel_functions[SYS_ptrace], r); }
int hook_access(struct proc *p, struct access_args *u, int *r) { return generic_syscall_log(p, u, "SYS_access", kernel_functions[SYS_access], r); }
int hook_chflags(struct proc *p, struct chflags_args *u, int *r) { return generic_syscall_log(p, u, "SYS_chflags", kernel_functions[SYS_chflags], r); }
int hook_fchflags(struct proc *p, struct fchflags_args *u, int *r) { return generic_syscall_log(p, u, "SYS_fchflags", kernel_functions[SYS_fchflags], r); }
int hook_getppid(struct proc *p, struct getppid_args *u, int *r) { return generic_syscall_log(p, u, "SYS_getppid", kernel_functions[SYS_getppid], r); }
int hook_pipe(struct proc *p, struct pipe_args *u, int *r) { return generic_syscall_log(p, u, "SYS_pipe", kernel_functions[SYS_pipe], r); }
int hook_getegid(struct proc *p, struct getegid_args *u, int *r) { return generic_syscall_log(p, u, "SYS_getegid", kernel_functions[SYS_getegid], r); }
int hook_sigaction(struct proc *p, struct sigaction_args *u, int *r) { return generic_syscall_log(p, u, "SYS_sigaction", kernel_functions[SYS_sigaction], r); }
int hook_getlogin(struct proc *p, struct getlogin_args *u, int *r) { return generic_syscall_log(p, u, "SYS_getlogin", kernel_functions[SYS_getlogin], r); }
int hook_setlogin(struct proc *p, struct setlogin_args *u, int *r) { return generic_syscall_log(p, u, "SYS_setlogin", kernel_functions[SYS_setlogin], r); }
int hook_acct(struct proc *p, struct acct_args *u, int *r) { return generic_syscall_log(p, u, "SYS_acct", kernel_functions[SYS_acct], r); }
int hook_sigpending(struct proc *p, struct sigpending_args *u, int *r) { return generic_syscall_log(p, u, "SYS_sigpending", kernel_functions[SYS_sigpending], r); }
int hook_reboot(struct proc *p, struct reboot_args *u, int *r) { return generic_syscall_log(p, u, "SYS_reboot", kernel_functions[SYS_reboot], r); }
int hook_revoke(struct proc *p, struct revoke_args *u, int *r) { return generic_syscall_log(p, u, "SYS_revoke", kernel_functions[SYS_revoke], r); }
int hook_symlink(struct proc *p, struct symlink_args *u, int *r) { return generic_syscall_log(p, u, "SYS_symlink", kernel_functions[SYS_symlink], r); }
int hook_execve(struct proc *p, struct execve_args *u, int *r) { return generic_syscall_log(p, u, "SYS_execve", kernel_functions[SYS_execve], r); }
int hook_umask(struct proc *p, struct umask_args *u, int *r) { return generic_syscall_log(p, u, "SYS_umask", kernel_functions[SYS_umask], r); }
int hook_chroot(struct proc *p, struct chroot_args *u, int *r) { return generic_syscall_log(p, u, "SYS_chroot", kernel_functions[SYS_chroot], r); }
int hook_msync(struct proc *p, struct msync_args *u, int *r) { return generic_syscall_log(p, u, "SYS_msync", kernel_functions[SYS_msync], r); }
int hook_vfork(struct proc *p, struct vfork_args *u, int *r) { return generic_syscall_log(p, u, "SYS_vfork", kernel_functions[SYS_vfork], r); }
int hook_mincore(struct proc *p, struct mincore_args *u, int *r) { return generic_syscall_log(p, u, "SYS_mincore", kernel_functions[SYS_mincore], r); }
int hook_getgroups(struct proc *p, struct getgroups_args *u, int *r) { return generic_syscall_log(p, u, "SYS_getgroups", kernel_functions[SYS_getgroups], r); }
int hook_setgroups(struct proc *p, struct setgroups_args *u, int *r) { return generic_syscall_log(p, u, "SYS_setgroups", kernel_functions[SYS_setgroups], r); }
int hook_getpgrp(struct proc *p, struct getpgrp_args *u, int *r) { return generic_syscall_log(p, u, "SYS_getpgrp", kernel_functions[SYS_getpgrp], r); }
int hook_setpgid(struct proc *p, struct setpgid_args *u, int *r) { return generic_syscall_log(p, u, "SYS_setpgid", kernel_functions[SYS_setpgid], r); }
int hook_swapon(struct proc *p, struct swapon_args *u, int *r) { return generic_syscall_log(p, u, "SYS_swapon", kernel_functions[SYS_swapon], r); }
int hook_getitimer(struct proc *p, struct getitimer_args *u, int *r) { return generic_syscall_log(p, u, "SYS_getitimer", kernel_functions[SYS_getitimer], r); }
int hook_getdtablesize(struct proc *p, struct getdtablesize_args *u, int *r) { return generic_syscall_log(p, u, "SYS_getdtablesize", kernel_functions[SYS_getdtablesize], r); }
int hook_dup2(struct proc *p, struct dup2_args *u, int *r) { return generic_syscall_log(p, u, "SYS_dup2", kernel_functions[SYS_dup2], r); }
int hook_setpriority(struct proc *p, struct setpriority_args *u, int *r) { return generic_syscall_log(p, u, "SYS_setpriority", kernel_functions[SYS_setpriority], r); }
int hook_socket(struct proc *p, struct socket_args *u, int *r) { return generic_syscall_log(p, u, "SYS_socket", kernel_functions[SYS_socket], r); }
int hook_connect(struct proc *p, struct connect_args *u, int *r) { return generic_syscall_log(p, u, "SYS_connect", kernel_functions[SYS_connect], r); }
int hook_getpriority(struct proc *p, struct getpriority_args *u, int *r) { return generic_syscall_log(p, u, "SYS_getpriority", kernel_functions[SYS_getpriority], r); }
int hook_bind(struct proc *p, struct bind_args *u, int *r) { return generic_syscall_log(p, u, "SYS_bind", kernel_functions[SYS_bind], r); }
int hook_setsockopt(struct proc *p, struct setsockopt_args *u, int *r) { return generic_syscall_log(p, u, "SYS_setsockopt", kernel_functions[SYS_setsockopt], r); }
int hook_listen(struct proc *p, struct listen_args *u, int *r) { return generic_syscall_log(p, u, "SYS_listen", kernel_functions[SYS_listen], r); }
int hook_getsockopt(struct proc *p, struct getsockopt_args *u, int *r) { return generic_syscall_log(p, u, "SYS_getsockopt", kernel_functions[SYS_getsockopt], r); }
int hook_readv(struct proc *p, struct readv_args *u, user_ssize_t *r) { return generic_syscall_log(p, u, "SYS_readv", kernel_functions[SYS_readv], r); }
int hook_writev(struct proc *p, struct writev_args *u, user_ssize_t *r) { return generic_syscall_log(p, u, "SYS_writev", kernel_functions[SYS_writev], r); }
int hook_settimeofday(struct proc *p, struct settimeofday_args *u, int *r) { return generic_syscall_log(p, u, "SYS_settimeofday", kernel_functions[SYS_settimeofday], r); }
int hook_fchown(struct proc *p, struct fchown_args *u, int *r) { return generic_syscall_log(p, u, "SYS_fchown", kernel_functions[SYS_fchown], r); }
int hook_fchmod(struct proc *p, struct fchmod_args *u, int *r) { return generic_syscall_log(p, u, "SYS_fchmod", kernel_functions[SYS_fchmod], r); }
int hook_setreuid(struct proc *p, struct setreuid_args *u, int *r) { return generic_syscall_log(p, u, "SYS_setreuid", kernel_functions[SYS_setreuid], r); }
int hook_setregid(struct proc *p, struct setregid_args *u, int *r) { return generic_syscall_log(p, u, "SYS_setregid", kernel_functions[SYS_setregid], r); }
int hook_rename(struct proc *p, struct rename_args *u, int *r) { return generic_syscall_log(p, u, "SYS_rename", kernel_functions[SYS_rename], r); }
int hook_flock(struct proc *p, struct flock_args *u, int *r) { return generic_syscall_log(p, u, "SYS_flock", kernel_functions[SYS_flock], r); }
int hook_mkfifo(struct proc *p, struct mkfifo_args *u, int *r) { return generic_syscall_log(p, u, "SYS_mkfifo", kernel_functions[SYS_mkfifo], r); }
int hook_sendto(struct proc *p, struct sendto_args *u, int *r) { return generic_syscall_log(p, u, "SYS_sendto", kernel_functions[SYS_sendto], r); }
int hook_shutdown(struct proc *p, struct shutdown_args *u, int *r) { return generic_syscall_log(p, u, "SYS_shutdown", kernel_functions[SYS_shutdown], r); }
int hook_socketpair(struct proc *p, struct socketpair_args *u, int *r) { return generic_syscall_log(p, u, "SYS_socketpair", kernel_functions[SYS_socketpair], r); }
int hook_rmdir(struct proc *p, struct rmdir_args *u, int *r) { return generic_syscall_log(p, u, "SYS_rmdir", kernel_functions[SYS_rmdir], r); }
int hook_utimes(struct proc *p, struct utimes_args *u, int *r) { return generic_syscall_log(p, u, "SYS_utimes", kernel_functions[SYS_utimes], r); }
int hook_futimes(struct proc *p, struct futimes_args *u, int *r) { return generic_syscall_log(p, u, "SYS_futimes", kernel_functions[SYS_futimes], r); }
int hook_gethostuuid(struct proc *p, struct gethostuuid_args *u, int *r) { return generic_syscall_log(p, u, "SYS_gethostuuid", kernel_functions[SYS_gethostuuid], r); }
int hook_setsid(struct proc *p, struct setsid_args *u, int *r) { return generic_syscall_log(p, u, "SYS_setsid", kernel_functions[SYS_setsid], r); }
int hook_getpgid(struct proc *p, struct getpgid_args *u, int *r) { return generic_syscall_log(p, u, "SYS_getpgid", kernel_functions[SYS_getpgid], r); }
int hook_setprivexec(struct proc *p, struct setprivexec_args *u, int *r) { return generic_syscall_log(p, u, "SYS_setprivexec", kernel_functions[SYS_setprivexec], r); }
int hook_pwrite(struct proc *p, struct pwrite_args *u, user_ssize_t *r) { return generic_syscall_log(p, u, "SYS_pwrite", kernel_functions[SYS_pwrite], r); }
int hook_nfssvc(struct proc *p, struct nfssvc_args *u, int *r) { return generic_syscall_log(p, u, "SYS_nfssvc", kernel_functions[SYS_nfssvc], r); }
int hook_statfs(struct proc *p, struct statfs_args *u, int *r) { return generic_syscall_log(p, u, "SYS_statfs", kernel_functions[SYS_statfs], r); }
int hook_fstatfs(struct proc *p, struct fstatfs_args *u, int *r) { return generic_syscall_log(p, u, "SYS_fstatfs", kernel_functions[SYS_fstatfs], r); }
int hook_unmount(struct proc *p, struct unmount_args *u, int *r) { return generic_syscall_log(p, u, "SYS_unmount", kernel_functions[SYS_unmount], r); }
int hook_getfh(struct proc *p, struct getfh_args *u, int *r) { return generic_syscall_log(p, u, "SYS_getfh", kernel_functions[SYS_getfh], r); }
int hook_quotactl(struct proc *p, struct quotactl_args *u, int *r) { return generic_syscall_log(p, u, "SYS_quotactl", kernel_functions[SYS_quotactl], r); }
int hook_mount(struct proc *p, struct mount_args *u, int *r) { return generic_syscall_log(p, u, "SYS_mount", kernel_functions[SYS_mount], r); }
int hook_waitid(struct proc *p, struct waitid_args *u, int *r) { return generic_syscall_log(p, u, "SYS_waitid", kernel_functions[SYS_waitid], r); }
int hook_kdebug_trace(struct proc *p, struct kdebug_trace_args *u, int *r) { return generic_syscall_log(p, u, "SYS_kdebug_trace", kernel_functions[SYS_kdebug_trace], r); }
int hook_setgid(struct proc *p, struct setgid_args *u, int *r) { return generic_syscall_log(p, u, "SYS_setgid", kernel_functions[SYS_setgid], r); }
int hook_setegid(struct proc *p, struct setegid_args *u, int *r) { return generic_syscall_log(p, u, "SYS_setegid", kernel_functions[SYS_setegid], r); }
int hook_seteuid(struct proc *p, struct seteuid_args *u, int *r) { return generic_syscall_log(p, u, "SYS_seteuid", kernel_functions[SYS_seteuid], r); }
int hook_chud(struct proc *p, struct chud_args *u, int *r) { return generic_syscall_log(p, u, "SYS_chud", kernel_functions[SYS_chud], r); }
int hook_fdatasync(struct proc *p, struct fdatasync_args *u, int *r) { return generic_syscall_log(p, u, "SYS_fdatasync", kernel_functions[SYS_fdatasync], r); }
int hook_stat(struct proc *p, struct stat_args *u, int *r) { return generic_syscall_log(p, u, "SYS_stat", kernel_functions[SYS_stat], r); }
int hook_fstat(struct proc *p, struct fstat_args *u, int *r) { return generic_syscall_log(p, u, "SYS_fstat", kernel_functions[SYS_fstat], r); }
int hook_lstat(struct proc *p, struct lstat_args *u, int *r) { return generic_syscall_log(p, u, "SYS_lstat", kernel_functions[SYS_lstat], r); }
int hook_pathconf(struct proc *p, struct pathconf_args *u, int *r) { return generic_syscall_log(p, u, "SYS_pathconf", kernel_functions[SYS_pathconf], r); }
int hook_fpathconf(struct proc *p, struct fpathconf_args *u, int *r) { return generic_syscall_log(p, u, "SYS_fpathconf", kernel_functions[SYS_fpathconf], r); }
int hook_getrlimit(struct proc *p, struct getrlimit_args *u, int *r) { return generic_syscall_log(p, u, "SYS_getrlimit", kernel_functions[SYS_getrlimit], r); }
int hook_setrlimit(struct proc *p, struct setrlimit_args *u, int *r) { return generic_syscall_log(p, u, "SYS_setrlimit", kernel_functions[SYS_setrlimit], r); }
int hook_getdirentries(struct proc *p, struct getdirentries_args *u, int *r) { return generic_syscall_log(p, u, "SYS_getdirentries", kernel_functions[SYS_getdirentries], r); }
int hook_truncate(struct proc *p, struct truncate_args *u, int *r) { return generic_syscall_log(p, u, "SYS_truncate", kernel_functions[SYS_truncate], r); }
int hook_ftruncate(struct proc *p, struct ftruncate_args *u, int *r) { return generic_syscall_log(p, u, "SYS_ftruncate", kernel_functions[SYS_ftruncate], r); }
int hook___sysctl(struct proc *p, struct __sysctl_args *u, int *r) { return generic_syscall_log(p, u, "SYS___sysctl", kernel_functions[SYS___sysctl], r); }
int hook_mlock(struct proc *p, struct mlock_args *u, int *r) { return generic_syscall_log(p, u, "SYS_mlock", kernel_functions[SYS_mlock], r); }
int hook_munlock(struct proc *p, struct munlock_args *u, int *r) { return generic_syscall_log(p, u, "SYS_munlock", kernel_functions[SYS_munlock], r); }
int hook_undelete(struct proc *p, struct undelete_args *u, int *r) { return generic_syscall_log(p, u, "SYS_undelete", kernel_functions[SYS_undelete], r); }
int hook_setattrlist(struct proc *p, struct setattrlist_args *u, int *r) { return generic_syscall_log(p, u, "SYS_setattrlist", kernel_functions[SYS_setattrlist], r); }
int hook_getdirentriesattr(struct proc *p, struct getdirentriesattr_args *u, int *r) { return generic_syscall_log(p, u, "SYS_getdirentriesattr", kernel_functions[SYS_getdirentriesattr], r); }
int hook_exchangedata(struct proc *p, struct exchangedata_args *u, int *r) { return generic_syscall_log(p, u, "SYS_exchangedata", kernel_functions[SYS_exchangedata], r); }
int hook_searchfs(struct proc *p, struct searchfs_args *u, int *r) { return generic_syscall_log(p, u, "SYS_searchfs", kernel_functions[SYS_searchfs], r); }
int hook_delete(struct proc *p, struct delete_args *u, int *r) { return generic_syscall_log(p, u, "SYS_delete", kernel_functions[SYS_delete], r); }
int hook_copyfile(struct proc *p, struct copyfile_args *u, int *r) { return generic_syscall_log(p, u, "SYS_copyfile", kernel_functions[SYS_copyfile], r); }
int hook_fgetattrlist(struct proc *p, struct fgetattrlist_args *u, int *r) { return generic_syscall_log(p, u, "SYS_fgetattrlist", kernel_functions[SYS_fgetattrlist], r); }
int hook_fsetattrlist(struct proc *p, struct fsetattrlist_args *u, int *r) { return generic_syscall_log(p, u, "SYS_fsetattrlist", kernel_functions[SYS_fsetattrlist], r); }
int hook_poll(struct proc *p, struct poll_args *u, int *r) { return generic_syscall_log(p, u, "SYS_poll", kernel_functions[SYS_poll], r); }
int hook_watchevent(struct proc *p, struct watchevent_args *u, int *r) { return generic_syscall_log(p, u, "SYS_watchevent", kernel_functions[SYS_watchevent], r); }
int hook_waitevent(struct proc *p, struct waitevent_args *u, int *r) { return generic_syscall_log(p, u, "SYS_waitevent", kernel_functions[SYS_waitevent], r); }
int hook_modwatch(struct proc *p, struct modwatch_args *u, int *r) { return generic_syscall_log(p, u, "SYS_modwatch", kernel_functions[SYS_modwatch], r); }
int hook_fgetxattr(struct proc *p, struct fgetxattr_args *u, user_ssize_t *r) { return generic_syscall_log(p, u, "SYS_fgetxattr", kernel_functions[SYS_fgetxattr], r); }
int hook_setxattr(struct proc *p, struct setxattr_args *u, int *r) { return generic_syscall_log(p, u, "SYS_setxattr", kernel_functions[SYS_setxattr], r); }
int hook_fsetxattr(struct proc *p, struct fsetxattr_args *u, int *r) { return generic_syscall_log(p, u, "SYS_fsetxattr", kernel_functions[SYS_fsetxattr], r); }
int hook_removexattr(struct proc *p, struct removexattr_args *u, int *r) { return generic_syscall_log(p, u, "SYS_removexattr", kernel_functions[SYS_removexattr], r); }
int hook_fremovexattr(struct proc *p, struct fremovexattr_args *u, int *r) { return generic_syscall_log(p, u, "SYS_fremovexattr", kernel_functions[SYS_fremovexattr], r); }
int hook_listxattr(struct proc *p, struct listxattr_args *u, user_ssize_t *r) { return generic_syscall_log(p, u, "SYS_listxattr", kernel_functions[SYS_listxattr], r); }
int hook_flistxattr(struct proc *p, struct flistxattr_args *u, user_ssize_t *r) { return generic_syscall_log(p, u, "SYS_flistxattr", kernel_functions[SYS_flistxattr], r); }
int hook_fsctl(struct proc *p, struct fsctl_args *u, int *r) { return generic_syscall_log(p, u, "SYS_fsctl", kernel_functions[SYS_fsctl], r); }
int hook_initgroups(struct proc *p, struct initgroups_args *u, int *r) { return generic_syscall_log(p, u, "SYS_initgroups", kernel_functions[SYS_initgroups], r); }
int hook_posix_spawn(struct proc *p, struct posix_spawn_args *u, int *r) { return generic_syscall_log(p, u, "SYS_posix_spawn", kernel_functions[SYS_posix_spawn], r); }
int hook_ffsctl(struct proc *p, struct ffsctl_args *u, int *r) { return generic_syscall_log(p, u, "SYS_ffsctl", kernel_functions[SYS_ffsctl], r); }
int hook_nfsclnt(struct proc *p, struct nfsclnt_args *u, int *r) { return generic_syscall_log(p, u, "SYS_nfsclnt", kernel_functions[SYS_nfsclnt], r); }
int hook_minherit(struct proc *p, struct minherit_args *u, int *r) { return generic_syscall_log(p, u, "SYS_minherit", kernel_functions[SYS_minherit], r); }
int hook_semsys(struct proc *p, struct semsys_args *u, int *r) { return generic_syscall_log(p, u, "SYS_semsys", kernel_functions[SYS_semsys], r); }
int hook_msgsys(struct proc *p, struct msgsys_args *u, int *r) { return generic_syscall_log(p, u, "SYS_msgsys", kernel_functions[SYS_msgsys], r); }
int hook_shmsys(struct proc *p, struct shmsys_args *u, int *r) { return generic_syscall_log(p, u, "SYS_shmsys", kernel_functions[SYS_shmsys], r); }
int hook_semctl(struct proc *p, struct semctl_args *u, int *r) { return generic_syscall_log(p, u, "SYS_semctl", kernel_functions[SYS_semctl], r); }
int hook_semget(struct proc *p, struct semget_args *u, int *r) { return generic_syscall_log(p, u, "SYS_semget", kernel_functions[SYS_semget], r); }
int hook_semop(struct proc *p, struct semop_args *u, int *r) { return generic_syscall_log(p, u, "SYS_semop", kernel_functions[SYS_semop], r); }
int hook_msgctl(struct proc *p, struct msgctl_args *u, int *r) { return generic_syscall_log(p, u, "SYS_msgctl", kernel_functions[SYS_msgctl], r); }
int hook_msgget(struct proc *p, struct msgget_args *u, int *r) { return generic_syscall_log(p, u, "SYS_msgget", kernel_functions[SYS_msgget], r); }
int hook_msgsnd(struct proc *p, struct msgsnd_args *u, int *r) { return generic_syscall_log(p, u, "SYS_msgsnd", kernel_functions[SYS_msgsnd], r); }
int hook_msgrcv(struct proc *p, struct msgrcv_args *u, user_ssize_t *r) { return generic_syscall_log(p, u, "SYS_msgrcv", kernel_functions[SYS_msgrcv], r); }
int hook_shmat(struct proc *p, struct shmat_args *u, user_addr_t *r) { return generic_syscall_log(p, u, "SYS_shmat", kernel_functions[SYS_shmat], r); }
int hook_shmctl(struct proc *p, struct shmctl_args *u, int *r) { return generic_syscall_log(p, u, "SYS_shmctl", kernel_functions[SYS_shmctl], r); }
int hook_shmdt(struct proc *p, struct shmdt_args *u, int *r) { return generic_syscall_log(p, u, "SYS_shmdt", kernel_functions[SYS_shmdt], r); }
int hook_shmget(struct proc *p, struct shmget_args *u, int *r) { return generic_syscall_log(p, u, "SYS_shmget", kernel_functions[SYS_shmget], r); }
int hook_shm_open(struct proc *p, struct shm_open_args *u, int *r) { return generic_syscall_log(p, u, "SYS_shm_open", kernel_functions[SYS_shm_open], r); }
int hook_shm_unlink(struct proc *p, struct shm_unlink_args *u, int *r) { return generic_syscall_log(p, u, "SYS_shm_unlink", kernel_functions[SYS_shm_unlink], r); }
int hook_sem_close(struct proc *p, struct sem_close_args *u, int *r) { return generic_syscall_log(p, u, "SYS_sem_close", kernel_functions[SYS_sem_close], r); }
int hook_sem_unlink(struct proc *p, struct sem_unlink_args *u, int *r) { return generic_syscall_log(p, u, "SYS_sem_unlink", kernel_functions[SYS_sem_unlink], r); }
int hook_sem_wait(struct proc *p, struct sem_wait_args *u, int *r) { return generic_syscall_log(p, u, "SYS_sem_wait", kernel_functions[SYS_sem_wait], r); }
int hook_sem_trywait(struct proc *p, struct sem_trywait_args *u, int *r) { return generic_syscall_log(p, u, "SYS_sem_trywait", kernel_functions[SYS_sem_trywait], r); }
int hook_sem_post(struct proc *p, struct sem_post_args *u, int *r) { return generic_syscall_log(p, u, "SYS_sem_post", kernel_functions[SYS_sem_post], r); }
int hook_sem_init(struct proc *p, struct sem_init_args *u, int *r) { return generic_syscall_log(p, u, "SYS_sem_init", kernel_functions[SYS_sem_init], r); }
int hook_sem_destroy(struct proc *p, struct sem_destroy_args *u, int *r) { return generic_syscall_log(p, u, "SYS_sem_destroy", kernel_functions[SYS_sem_destroy], r); }
int hook_open_extended(struct proc *p, struct open_extended_args *u, int *r) { return generic_syscall_log(p, u, "SYS_open_extended", kernel_functions[SYS_open_extended], r); }
int hook_umask_extended(struct proc *p, struct umask_extended_args *u, int *r) { return generic_syscall_log(p, u, "SYS_umask_extended", kernel_functions[SYS_umask_extended], r); }
int hook_stat_extended(struct proc *p, struct stat_extended_args *u, int *r) { return generic_syscall_log(p, u, "SYS_stat_extended", kernel_functions[SYS_stat_extended], r); }
int hook_lstat_extended(struct proc *p, struct lstat_extended_args *u, int *r) { return generic_syscall_log(p, u, "SYS_lstat_extended", kernel_functions[SYS_lstat_extended], r); }
int hook_fstat_extended(struct proc *p, struct fstat_extended_args *u, int *r) { return generic_syscall_log(p, u, "SYS_fstat_extended", kernel_functions[SYS_fstat_extended], r); }
int hook_chmod_extended(struct proc *p, struct chmod_extended_args *u, int *r) { return generic_syscall_log(p, u, "SYS_chmod_extended", kernel_functions[SYS_chmod_extended], r); }
int hook_fchmod_extended(struct proc *p, struct fchmod_extended_args *u, int *r) { return generic_syscall_log(p, u, "SYS_fchmod_extended", kernel_functions[SYS_fchmod_extended], r); }
int hook_access_extended(struct proc *p, struct access_extended_args *u, int *r) { return generic_syscall_log(p, u, "SYS_access_extended", kernel_functions[SYS_access_extended], r); }
int hook_settid(struct proc *p, struct settid_args *u, int *r) { return generic_syscall_log(p, u, "SYS_settid", kernel_functions[SYS_settid], r); }
int hook_setsgroups(struct proc *p, struct setsgroups_args *u, int *r) { return generic_syscall_log(p, u, "SYS_setsgroups", kernel_functions[SYS_setsgroups], r); }
int hook_getsgroups(struct proc *p, struct getsgroups_args *u, int *r) { return generic_syscall_log(p, u, "SYS_getsgroups", kernel_functions[SYS_getsgroups], r); }
int hook_setwgroups(struct proc *p, struct setwgroups_args *u, int *r) { return generic_syscall_log(p, u, "SYS_setwgroups", kernel_functions[SYS_setwgroups], r); }
int hook_getwgroups(struct proc *p, struct getwgroups_args *u, int *r) { return generic_syscall_log(p, u, "SYS_getwgroups", kernel_functions[SYS_getwgroups], r); }
int hook_mkfifo_extended(struct proc *p, struct mkfifo_extended_args *u, int *r) { return generic_syscall_log(p, u, "SYS_mkfifo_extended", kernel_functions[SYS_mkfifo_extended], r); }
int hook_identitysvc(struct proc *p, struct identitysvc_args *u, int *r) { return generic_syscall_log(p, u, "SYS_identitysvc", kernel_functions[SYS_identitysvc], r); }
int hook_shared_region_check_np(struct proc *p, struct shared_region_check_np_args *u, int *r) { return generic_syscall_log(p, u, "SYS_shared_region_check_np", kernel_functions[SYS_shared_region_check_np], r); }
int hook_vm_pressure_monitor(struct proc *p, struct vm_pressure_monitor_args *u, int *r) { return generic_syscall_log(p, u, "SYS_vm_pressure_monitor", kernel_functions[SYS_vm_pressure_monitor], r); }
int hook_psynch_rw_longrdlock(struct proc *p, struct psynch_rw_longrdlock_args *u, uint32_t *r) { return generic_syscall_log(p, u, "SYS_psynch_rw_longrdlock", kernel_functions[SYS_psynch_rw_longrdlock], r); }
int hook_psynch_rw_yieldwrlock(struct proc *p, struct psynch_rw_yieldwrlock_args *u, uint32_t *r) { return generic_syscall_log(p, u, "SYS_psynch_rw_yieldwrlock", kernel_functions[SYS_psynch_rw_yieldwrlock], r); }
int hook_psynch_rw_downgrade(struct proc *p, struct psynch_rw_downgrade_args *u, int *r) { return generic_syscall_log(p, u, "SYS_psynch_rw_downgrade", kernel_functions[SYS_psynch_rw_downgrade], r); }
int hook_psynch_rw_upgrade(struct proc *p, struct psynch_rw_upgrade_args *u, uint32_t *r) { return generic_syscall_log(p, u, "SYS_psynch_rw_upgrade", kernel_functions[SYS_psynch_rw_upgrade], r); }
int hook_psynch_rw_unlock2(struct proc *p, struct psynch_rw_unlock2_args *u, uint32_t *r) { return generic_syscall_log(p, u, "SYS_psynch_rw_unlock2", kernel_functions[SYS_psynch_rw_unlock2], r); }
int hook_getsid(struct proc *p, struct getsid_args *u, int *r) { return generic_syscall_log(p, u, "SYS_getsid", kernel_functions[SYS_getsid], r); }
int hook_settid_with_pid(struct proc *p, struct settid_with_pid_args *u, int *r) { return generic_syscall_log(p, u, "SYS_settid_with_pid", kernel_functions[SYS_settid_with_pid], r); }
int hook_psynch_cvclrprepost(struct proc *p, struct psynch_cvclrprepost_args *u, int *r) { return generic_syscall_log(p, u, "SYS_psynch_cvclrprepost", kernel_functions[SYS_psynch_cvclrprepost], r); }
int hook_aio_fsync(struct proc *p, struct aio_fsync_args *u, int *r) { return generic_syscall_log(p, u, "SYS_aio_fsync", kernel_functions[SYS_aio_fsync], r); }
int hook_aio_return(struct proc *p, struct aio_return_args *u, user_ssize_t *r) { return generic_syscall_log(p, u, "SYS_aio_return", kernel_functions[SYS_aio_return], r); }
int hook_aio_suspend(struct proc *p, struct aio_suspend_args *u, int *r) { return generic_syscall_log(p, u, "SYS_aio_suspend", kernel_functions[SYS_aio_suspend], r); }
int hook_aio_cancel(struct proc *p, struct aio_cancel_args *u, int *r) { return generic_syscall_log(p, u, "SYS_aio_cancel", kernel_functions[SYS_aio_cancel], r); }
int hook_aio_error(struct proc *p, struct aio_error_args *u, int *r) { return generic_syscall_log(p, u, "SYS_aio_error", kernel_functions[SYS_aio_error], r); }
int hook_aio_read(struct proc *p, struct aio_read_args *u, int *r) { return generic_syscall_log(p, u, "SYS_aio_read", kernel_functions[SYS_aio_read], r); }
int hook_aio_write(struct proc *p, struct aio_write_args *u, int *r) { return generic_syscall_log(p, u, "SYS_aio_write", kernel_functions[SYS_aio_write], r); }
int hook_lio_listio(struct proc *p, struct lio_listio_args *u, int *r) { return generic_syscall_log(p, u, "SYS_lio_listio", kernel_functions[SYS_lio_listio], r); }
int hook_process_policy(struct proc *p, struct process_policy_args *u, int *r) { return generic_syscall_log(p, u, "SYS_process_policy", kernel_functions[SYS_process_policy], r); }
int hook_mlockall(struct proc *p, struct mlockall_args *u, int *r) { return generic_syscall_log(p, u, "SYS_mlockall", kernel_functions[SYS_mlockall], r); }
int hook_munlockall(struct proc *p, struct munlockall_args *u, int *r) { return generic_syscall_log(p, u, "SYS_munlockall", kernel_functions[SYS_munlockall], r); }
int hook___pthread_kill(struct proc *p, struct __pthread_kill_args *u, int *r) { return generic_syscall_log(p, u, "SYS___pthread_kill", kernel_functions[SYS___pthread_kill], r); }
int hook___sigwait(struct proc *p, struct __sigwait_args *u, int *r) { return generic_syscall_log(p, u, "SYS___sigwait", kernel_functions[SYS___sigwait], r); }
int hook___pthread_markcancel(struct proc *p, struct __pthread_markcancel_args *u, int *r) { return generic_syscall_log(p, u, "SYS___pthread_markcancel", kernel_functions[SYS___pthread_markcancel], r); }
int hook_sendfile(struct proc *p, struct sendfile_args *u, int *r) { return generic_syscall_log(p, u, "SYS_sendfile", kernel_functions[SYS_sendfile], r); }
int hook_stat64_extended(struct proc *p, struct stat64_extended_args *u, int *r) { return generic_syscall_log(p, u, "SYS_stat64_extended", kernel_functions[SYS_stat64_extended], r); }
int hook_lstat64_extended(struct proc *p, struct lstat64_extended_args *u, int *r) { return generic_syscall_log(p, u, "SYS_lstat64_extended", kernel_functions[SYS_lstat64_extended], r); }
int hook_fstat64_extended(struct proc *p, struct fstat64_extended_args *u, int *r) { return generic_syscall_log(p, u, "SYS_fstat64_extended", kernel_functions[SYS_fstat64_extended], r); }
int hook_audit(struct proc *p, struct audit_args *u, int *r) { return generic_syscall_log(p, u, "SYS_audit", kernel_functions[SYS_audit], r); }
int hook_auditon(struct proc *p, struct auditon_args *u, int *r) { return generic_syscall_log(p, u, "SYS_auditon", kernel_functions[SYS_auditon], r); }
int hook_getauid(struct proc *p, struct getauid_args *u, int *r) { return generic_syscall_log(p, u, "SYS_getauid", kernel_functions[SYS_getauid], r); }
int hook_setauid(struct proc *p, struct setauid_args *u, int *r) { return generic_syscall_log(p, u, "SYS_setauid", kernel_functions[SYS_setauid], r); }
int hook_setaudit_addr(struct proc *p, struct setaudit_addr_args *u, int *r) { return generic_syscall_log(p, u, "SYS_setaudit_addr", kernel_functions[SYS_setaudit_addr], r); }
int hook_auditctl(struct proc *p, struct auditctl_args *u, int *r) { return generic_syscall_log(p, u, "SYS_auditctl", kernel_functions[SYS_auditctl], r); }
int hook_lchown(struct proc *p, struct lchown_args *u, int *r) { return generic_syscall_log(p, u, "SYS_lchown", kernel_functions[SYS_lchown], r); }
int hook_stack_snapshot(struct proc *p, struct stack_snapshot_args *u, int *r) { return generic_syscall_log(p, u, "SYS_stack_snapshot", kernel_functions[SYS_stack_snapshot], r); }
int hook___mac_execve(struct proc *p, struct __mac_execve_args *u, int *r) { return generic_syscall_log(p, u, "SYS___mac_execve", kernel_functions[SYS___mac_execve], r); }
int hook___mac_get_file(struct proc *p, struct __mac_get_file_args *u, int *r) { return generic_syscall_log(p, u, "SYS___mac_get_file", kernel_functions[SYS___mac_get_file], r); }
int hook___mac_set_file(struct proc *p, struct __mac_set_file_args *u, int *r) { return generic_syscall_log(p, u, "SYS___mac_set_file", kernel_functions[SYS___mac_set_file], r); }
int hook___mac_get_link(struct proc *p, struct __mac_get_link_args *u, int *r) { return generic_syscall_log(p, u, "SYS___mac_get_link", kernel_functions[SYS___mac_get_link], r); }
int hook___mac_set_link(struct proc *p, struct __mac_set_link_args *u, int *r) { return generic_syscall_log(p, u, "SYS___mac_set_link", kernel_functions[SYS___mac_set_link], r); }
int hook___mac_get_proc(struct proc *p, struct __mac_get_proc_args *u, int *r) { return generic_syscall_log(p, u, "SYS___mac_get_proc", kernel_functions[SYS___mac_get_proc], r); }
int hook___mac_set_proc(struct proc *p, struct __mac_set_proc_args *u, int *r) { return generic_syscall_log(p, u, "SYS___mac_set_proc", kernel_functions[SYS___mac_set_proc], r); }
int hook___mac_get_fd(struct proc *p, struct __mac_get_fd_args *u, int *r) { return generic_syscall_log(p, u, "SYS___mac_get_fd", kernel_functions[SYS___mac_get_fd], r); }
int hook___mac_set_fd(struct proc *p, struct __mac_set_fd_args *u, int *r) { return generic_syscall_log(p, u, "SYS___mac_set_fd", kernel_functions[SYS___mac_set_fd], r); }
int hook___mac_get_pid(struct proc *p, struct __mac_get_pid_args *u, int *r) { return generic_syscall_log(p, u, "SYS___mac_get_pid", kernel_functions[SYS___mac_get_pid], r); }
int hook___mac_get_lcid(struct proc *p, struct __mac_get_lcid_args *u, int *r) { return generic_syscall_log(p, u, "SYS___mac_get_lcid", kernel_functions[SYS___mac_get_lcid], r); }
int hook___mac_get_lctx(struct proc *p, struct __mac_get_lctx_args *u, int *r) { return generic_syscall_log(p, u, "SYS___mac_get_lctx", kernel_functions[SYS___mac_get_lctx], r); }
int hook___mac_set_lctx(struct proc *p, struct __mac_set_lctx_args *u, int *r) { return generic_syscall_log(p, u, "SYS___mac_set_lctx", kernel_functions[SYS___mac_set_lctx], r); }
int hook_setlcid(struct proc *p, struct setlcid_args *u, int *r) { return generic_syscall_log(p, u, "SYS_setlcid", kernel_functions[SYS_setlcid], r); }
int hook_getlcid(struct proc *p, struct getlcid_args *u, int *r) { return generic_syscall_log(p, u, "SYS_getlcid", kernel_functions[SYS_getlcid], r); }
int hook_wait4_nocancel(struct proc *p, struct wait4_nocancel_args *u, int *r) { return generic_syscall_log(p, u, "SYS_wait4_nocancel", kernel_functions[SYS_wait4_nocancel], r); }
int hook_recvmsg_nocancel(struct proc *p, struct recvmsg_nocancel_args *u, int *r) { return generic_syscall_log(p, u, "SYS_recvmsg_nocancel", kernel_functions[SYS_recvmsg_nocancel], r); }
int hook_sendmsg_nocancel(struct proc *p, struct sendmsg_nocancel_args *u, int *r) { return generic_syscall_log(p, u, "SYS_sendmsg_nocancel", kernel_functions[SYS_sendmsg_nocancel], r); }
int hook_recvfrom_nocancel(struct proc *p, struct recvfrom_nocancel_args *u, int *r) { return generic_syscall_log(p, u, "SYS_recvfrom_nocancel", kernel_functions[SYS_recvfrom_nocancel], r); }
int hook_accept_nocancel(struct proc *p, struct accept_nocancel_args *u, int *r) { return generic_syscall_log(p, u, "SYS_accept_nocancel", kernel_functions[SYS_accept_nocancel], r); }
int hook_msync_nocancel(struct proc *p, struct msync_nocancel_args *u, int *r) { return generic_syscall_log(p, u, "SYS_msync_nocancel", kernel_functions[SYS_msync_nocancel], r); }
int hook_select_nocancel(struct proc *p, struct select_nocancel_args *u, int *r) { return generic_syscall_log(p, u, "SYS_select_nocancel", kernel_functions[SYS_select_nocancel], r); }
int hook_fsync_nocancel(struct proc *p, struct fsync_nocancel_args *u, int *r) { return generic_syscall_log(p, u, "SYS_fsync_nocancel", kernel_functions[SYS_fsync_nocancel], r); }
int hook_connect_nocancel(struct proc *p, struct connect_nocancel_args *u, int *r) { return generic_syscall_log(p, u, "SYS_connect_nocancel", kernel_functions[SYS_connect_nocancel], r); }
int hook_sigsuspend_nocancel(struct proc *p, struct sigsuspend_nocancel_args *u, int *r) { return generic_syscall_log(p, u, "SYS_sigsuspend_nocancel", kernel_functions[SYS_sigsuspend_nocancel], r); }
int hook_readv_nocancel(struct proc *p, struct readv_nocancel_args *u, user_ssize_t *r) { return generic_syscall_log(p, u, "SYS_readv_nocancel", kernel_functions[SYS_readv_nocancel], r); }
int hook_writev_nocancel(struct proc *p, struct writev_nocancel_args *u, user_ssize_t *r) { return generic_syscall_log(p, u, "SYS_writev_nocancel", kernel_functions[SYS_writev_nocancel], r); }
int hook_sendto_nocancel(struct proc *p, struct sendto_nocancel_args *u, int *r) { return generic_syscall_log(p, u, "SYS_sendto_nocancel", kernel_functions[SYS_sendto_nocancel], r); }
int hook_pread_nocancel(struct proc *p, struct pread_nocancel_args *u, user_ssize_t *r) { return generic_syscall_log(p, u, "SYS_pread_nocancel", kernel_functions[SYS_pread_nocancel], r); }
int hook_pwrite_nocancel(struct proc *p, struct pwrite_nocancel_args *u, user_ssize_t *r) { return generic_syscall_log(p, u, "SYS_pwrite_nocancel", kernel_functions[SYS_pwrite_nocancel], r); }
int hook_waitid_nocancel(struct proc *p, struct waitid_nocancel_args *u, int *r) { return generic_syscall_log(p, u, "SYS_waitid_nocancel", kernel_functions[SYS_waitid_nocancel], r); }
int hook_poll_nocancel(struct proc *p, struct poll_nocancel_args *u, int *r) { return generic_syscall_log(p, u, "SYS_poll_nocancel", kernel_functions[SYS_poll_nocancel], r); }
int hook_msgsnd_nocancel(struct proc *p, struct msgsnd_nocancel_args *u, int *r) { return generic_syscall_log(p, u, "SYS_msgsnd_nocancel", kernel_functions[SYS_msgsnd_nocancel], r); }
int hook_msgrcv_nocancel(struct proc *p, struct msgrcv_nocancel_args *u, user_ssize_t *r) { return generic_syscall_log(p, u, "SYS_msgrcv_nocancel", kernel_functions[SYS_msgrcv_nocancel], r); }
int hook_sem_wait_nocancel(struct proc *p, struct sem_wait_nocancel_args *u, int *r) { return generic_syscall_log(p, u, "SYS_sem_wait_nocancel", kernel_functions[SYS_sem_wait_nocancel], r); }
int hook_aio_suspend_nocancel(struct proc *p, struct aio_suspend_nocancel_args *u, int *r) { return generic_syscall_log(p, u, "SYS_aio_suspend_nocancel", kernel_functions[SYS_aio_suspend_nocancel], r); }
int hook___sigwait_nocancel(struct proc *p, struct __sigwait_nocancel_args *u, int *r) { return generic_syscall_log(p, u, "SYS___sigwait_nocancel", kernel_functions[SYS___sigwait_nocancel], r); }
int hook___semwait_signal_nocancel(struct proc *p, struct __semwait_signal_nocancel_args *u, int *r) { return generic_syscall_log(p, u, "SYS___semwait_signal_nocancel", kernel_functions[SYS___semwait_signal_nocancel], r); }
int hook___mac_mount(struct proc *p, struct __mac_mount_args *u, int *r) { return generic_syscall_log(p, u, "SYS___mac_mount", kernel_functions[SYS___mac_mount], r); }
int hook___mac_get_mount(struct proc *p, struct __mac_get_mount_args *u, int *r) { return generic_syscall_log(p, u, "SYS___mac_get_mount", kernel_functions[SYS___mac_get_mount], r); }
int hook___mac_getfsstat(struct proc *p, struct __mac_getfsstat_args *u, int *r) { return generic_syscall_log(p, u, "SYS___mac_getfsstat", kernel_functions[SYS___mac_getfsstat], r); }
int hook_audit_session_self(struct proc *p, struct audit_session_self_args *u, mach_port_name_t *r) { return generic_syscall_log(p, u, "SYS_audit_session_self", kernel_functions[SYS_audit_session_self], r); }
int hook_audit_session_join(struct proc *p, struct audit_session_join_args *u, int *r) { return generic_syscall_log(p, u, "SYS_audit_session_join", kernel_functions[SYS_audit_session_join], r); }
int hook_fileport_makeport(struct proc *p, struct fileport_makeport_args *u, int *r) { return generic_syscall_log(p, u, "SYS_fileport_makeport", kernel_functions[SYS_fileport_makeport], r); }
int hook_fileport_makefd(struct proc *p, struct fileport_makefd_args *u, int *r) { return generic_syscall_log(p, u, "SYS_fileport_makefd", kernel_functions[SYS_fileport_makefd], r); }
int hook_audit_session_port(struct proc *p, struct audit_session_port_args *u, int *r) { return generic_syscall_log(p, u, "SYS_audit_session_port", kernel_functions[SYS_audit_session_port], r); }
int hook_pid_suspend(struct proc *p, struct pid_suspend_args *u, int *r) { return generic_syscall_log(p, u, "SYS_pid_suspend", kernel_functions[SYS_pid_suspend], r); }
int hook_pid_resume(struct proc *p, struct pid_resume_args *u, int *r) { return generic_syscall_log(p, u, "SYS_pid_resume", kernel_functions[SYS_pid_resume], r); }
int hook_shared_region_map_and_slide_np(struct proc *p, struct shared_region_map_and_slide_np_args *u, int *r) { return generic_syscall_log(p, u, "SYS_shared_region_map_and_slide_np", kernel_functions[SYS_shared_region_map_and_slide_np], r); }
int hook_kas_info(struct proc *p, struct kas_info_args *u, int *r) { return generic_syscall_log(p, u, "SYS_kas_info", kernel_functions[SYS_kas_info], r); }
int hook_ioctl(struct proc *p, struct ioctl_args *u, int *r) { return generic_syscall_log(p, u, "SYS_ioctl", kernel_functions[SYS_ioctl], r); }







