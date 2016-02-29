//
//  hooker.c
//  grey_fox
//
//  Hooks all the relevant system calls and logs them to system.log for later analysis.
//
//  Created by vivami on 04/11/15.
//  Copyright © 2015 vivami. All rights reserved.
//

#include "cpu_protections.h"
#include "hooker.h"
#include <sys/syslimits.h>
#include <sys/proc.h>
#include <kern/clock.h>
#include <libkern/libkern.h>

void hook_syscall(void *sysent_addr, int32_t syscall);
void unhook_syscall(void *sysent_addr, int32_t syscall);

typedef int (*kern_f)(struct proc *, struct args *, int *);

/* Array of pointers to original syscall functions. Saved to restore before leaving the kernel. */
static kern_f kernel_functions[SYS_MAXSYSCALL+1] = {0};

/* Array of pointers to our own hook functions. The NULL pointers are syscalls we don't hook (to reduce
 * verbosity of the dataset), or syscalls that are depricated.
 */
//static int (*hook_functions[SYS_MAXSYSCALL+1]) = {NULL, NULL, hook_fork, hook_read, hook_write, hook_open};

static int (*hook_functions[SYS_MAXSYSCALL+1]) = {NULL, NULL, hook_fork, NULL, hook_write, NULL, NULL, NULL, NULL, hook_link, hook_unlink, NULL, NULL, NULL, hook_mknod, hook_chmod, hook_chown, NULL, hook_getfsstat, NULL, NULL, NULL, NULL, hook_setuid, NULL, NULL, hook_ptrace, NULL, NULL, NULL, NULL, NULL, NULL, hook_access, hook_chflags, hook_fchflags, NULL, NULL, NULL, hook_getppid, NULL, NULL, hook_pipe, hook_getegid, NULL, NULL, hook_sigaction, NULL, NULL, hook_getlogin, hook_setlogin, hook_acct, hook_sigpending, NULL, hook_ioctl, hook_reboot, hook_revoke, hook_symlink, NULL, hook_execve, hook_umask, hook_chroot, NULL, NULL, NULL, hook_msync, hook_vfork, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, hook_mincore, hook_getgroups, hook_setgroups, hook_getpgrp, hook_setpgid, NULL, NULL, hook_swapon, hook_getitimer, NULL, NULL, hook_getdtablesize, hook_dup2, NULL, NULL, NULL, NULL, NULL, hook_setpriority, hook_socket, hook_connect, NULL, hook_getpriority, NULL, NULL, NULL, hook_bind, hook_setsockopt, hook_listen, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, hook_getsockopt, NULL, hook_readv, hook_writev, hook_settimeofday, hook_fchown, hook_fchmod, NULL, hook_setreuid, hook_setregid, hook_rename, NULL, NULL, hook_flock, hook_mkfifo, hook_sendto, hook_shutdown, hook_socketpair, NULL, hook_rmdir, hook_utimes, hook_futimes, NULL, NULL, hook_gethostuuid, NULL, NULL, NULL, NULL, hook_setsid, NULL, NULL, NULL, hook_getpgid, hook_setprivexec, NULL, hook_pwrite, hook_nfssvc, NULL, hook_statfs, hook_fstatfs, hook_unmount, NULL, hook_getfh, NULL, NULL, NULL, hook_quotactl, NULL, hook_mount, NULL, NULL, NULL, NULL, NULL, hook_waitid, NULL, NULL, NULL, NULL, NULL, NULL, hook_kdebug_trace, hook_setgid, hook_setegid, hook_seteuid, NULL, hook_chud, NULL, hook_fdatasync, hook_stat, hook_fstat, hook_lstat, hook_pathconf, hook_fpathconf, NULL, hook_getrlimit, hook_setrlimit, hook_getdirentries, NULL, NULL, NULL, hook_truncate, hook_ftruncate, hook___sysctl, hook_mlock, hook_munlock, hook_undelete, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, hook_setattrlist, hook_getdirentriesattr, hook_exchangedata, NULL, hook_searchfs, hook_delete, hook_copyfile, hook_fgetattrlist, hook_fsetattrlist, hook_poll, hook_watchevent, hook_waitevent, hook_modwatch, NULL, hook_fgetxattr, hook_setxattr, hook_fsetxattr, hook_removexattr, hook_fremovexattr, hook_listxattr, hook_flistxattr, hook_fsctl, hook_initgroups, hook_posix_spawn, hook_ffsctl, NULL, hook_nfsclnt, NULL, NULL, hook_minherit, hook_semsys, hook_msgsys, hook_shmsys, hook_semctl, hook_semget, hook_semop, NULL, hook_msgctl, hook_msgget, hook_msgsnd, hook_msgrcv, hook_shmat, hook_shmctl, hook_shmdt, hook_shmget, hook_shm_open, hook_shm_unlink, NULL, hook_sem_close, hook_sem_unlink, hook_sem_wait, hook_sem_trywait, hook_sem_post, NULL, hook_sem_init, hook_sem_destroy, hook_open_extended, hook_umask_extended, hook_stat_extended, hook_lstat_extended, hook_fstat_extended, hook_chmod_extended, hook_fchmod_extended, hook_access_extended, hook_settid, NULL, hook_setsgroups, hook_getsgroups, hook_setwgroups, hook_getwgroups, hook_mkfifo_extended, NULL, hook_identitysvc, hook_shared_region_check_np, NULL, hook_vm_pressure_monitor, hook_psynch_rw_longrdlock, hook_psynch_rw_yieldwrlock, hook_psynch_rw_downgrade, hook_psynch_rw_upgrade, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, hook_psynch_rw_unlock2, hook_getsid, hook_settid_with_pid, hook_psynch_cvclrprepost, hook_aio_fsync, hook_aio_return, hook_aio_suspend, hook_aio_cancel, hook_aio_error, hook_aio_read, hook_aio_write, hook_lio_listio, NULL, NULL, NULL, hook_mlockall, hook_munlockall, NULL, NULL, hook___pthread_kill, NULL, hook___sigwait, NULL, hook___pthread_markcancel, NULL, NULL, NULL, NULL, hook_sendfile, NULL, NULL, NULL, hook_stat64_extended, hook_lstat64_extended, hook_fstat64_extended, NULL, NULL, NULL, NULL, NULL, NULL, hook_audit, hook_auditon, NULL, hook_getauid, hook_setauid, NULL, NULL, NULL, hook_setaudit_addr, hook_auditctl, NULL, NULL, NULL, NULL, hook_lchown, hook_stack_snapshot, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, hook___mac_execve, NULL, hook___mac_get_file, hook___mac_set_file, hook___mac_get_link, hook___mac_set_link, hook___mac_get_proc, hook___mac_set_proc, hook___mac_get_fd, hook___mac_set_fd, hook___mac_get_pid, hook___mac_get_lcid, hook___mac_get_lctx, hook___mac_set_lctx, hook_setlcid, hook_getlcid, NULL, NULL, NULL, NULL, hook_wait4_nocancel, hook_recvmsg_nocancel, hook_sendmsg_nocancel, hook_recvfrom_nocancel, hook_accept_nocancel, hook_msync_nocancel, NULL, hook_select_nocancel, hook_fsync_nocancel, hook_connect_nocancel, hook_sigsuspend_nocancel, hook_readv_nocancel, hook_writev_nocancel, hook_sendto_nocancel, hook_pread_nocancel, hook_pwrite_nocancel, hook_waitid_nocancel, hook_poll_nocancel, hook_msgsnd_nocancel, hook_msgrcv_nocancel, hook_sem_wait_nocancel, hook_aio_suspend_nocancel, hook___sigwait_nocancel, hook___semwait_signal_nocancel, hook___mac_mount, hook___mac_get_mount, hook___mac_getfsstat, NULL, hook_audit_session_self, hook_audit_session_join, hook_fileport_makeport, hook_fileport_makefd, hook_audit_session_port, hook_pid_suspend, hook_pid_resume, NULL, NULL, NULL, hook_shared_region_map_and_slide_np, hook_kas_info, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL};

extern const int version_major;


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
void hook_syscall(void *sysent_addr, int32_t syscall) {
    switch (version_major) {
        case EL_CAPITAN: {
            struct sysent_yosemite *sysent = (struct sysent_yosemite*)sysent_addr;
            if (hook_functions[syscall]) {
                kernel_functions[syscall] = (void*)sysent[syscall].sy_call;
                sysent[syscall].sy_call = (sy_call_t*)hook_functions[syscall];
                LOG_INFO("Hooked syscall no.: %d\n", syscall);
            }
            break;
        }
        case YOSEMITE: {
            struct sysent_yosemite *sysent = (struct sysent_yosemite*)sysent_addr;
            if (hook_functions[syscall] != NULL) {
                kernel_functions[syscall] = (void*)sysent[syscall].sy_call;
                sysent[syscall].sy_call = (sy_call_t*)hook_functions[syscall];
                LOG_INFO("Hooked syscall no.: %d\n", syscall);
            }
            break;
        }
        case MAVERICKS: {
            struct sysent_mavericks *sysent = (struct sysent_mavericks*)sysent_addr;
            if (hook_functions[syscall]) {
                kernel_functions[syscall] = (void*)sysent[syscall].sy_call;
                sysent[syscall].sy_call = (sy_call_t*)hook_functions[syscall];
                LOG_INFO("Hooked syscall no.: %d\n", syscall);
            }
            break;
        }
        default: {
            struct sysent *sysent = (struct sysent*)sysent_addr;
            if (hook_functions[syscall]) {
                kernel_functions[syscall] = (void*)sysent[syscall].sy_call;
                sysent[syscall].sy_call = (sy_call_t*)hook_functions[syscall];
                LOG_INFO("Hooked syscall no.: %d\n", syscall);
            }
            break;
        }
    }
}

/* Restores the original syscall function. */
void unhook_syscall(void *sysent_addr, int32_t syscall) {
    switch (version_major) {
        case EL_CAPITAN: {
            if (kernel_functions[syscall] != NULL) {
                struct sysent_yosemite *sysent = (struct sysent_yosemite*)sysent_addr;
                sysent[syscall].sy_call = (sy_call_t*)kernel_functions[syscall];
                LOG_INFO("Unhooked syscall %d\n", syscall);
            } else {
                LOG_INFO("Syscall %d was not hooked...\n", syscall);
            }
            break;
        }
        case YOSEMITE: {
            if (kernel_functions[syscall] != NULL) {
                struct sysent_yosemite *sysent = (struct sysent_yosemite*)sysent_addr;
                sysent[syscall].sy_call = (sy_call_t*)kernel_functions[syscall];
                LOG_INFO("Unhooked syscall %d\n", syscall);
            } else {
                LOG_INFO("Syscall %d was not hooked...\n", syscall);
            }
            break;
        }
        case MAVERICKS: {
            struct sysent_mavericks *sysent = (struct sysent_mavericks*)sysent_addr;
            if (kernel_functions[syscall] != NULL) {
                sysent[syscall].sy_call = (sy_call_t*)kernel_functions[syscall];
                LOG_INFO("Unhooked syscall %d\n", syscall);
            } else {
                LOG_INFO("Syscall %d was not hooked...\n", syscall);
            }
            break;
        }
        default: {
            struct sysent *sysent = (struct sysent*)sysent_addr;
            if (kernel_functions[syscall] != NULL) {
                sysent[syscall].sy_call = (sy_call_t*)kernel_functions[syscall];
                LOG_INFO("Unhooked syscall %d\n", syscall);
            } else {
                LOG_INFO("Syscall %d was not hooked...\n", syscall);
            }
            break;
        }
    }
}

/* Prevents deadlocks by checking if the process is not a call from syslogd or kernel. */
int32_t should_i_log_this(struct proc *p) {
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

/* Returns 1 iff process p has root privs. */
uint32_t is_root(struct proc *p) {
    return proc_suser(p) == 0;
}



/* Logs the imporant features of calling process to output. */
int32_t generic_syscall_log(struct proc *p, struct args *a, char* syscall, kern_f k, int *r) {
    if (!should_i_log_this(p)) {
        return k(p, a, r);
    }
    pid_t pid = proc_pid(p);
    pid_t ppid = proc_ppid(p);
    uint32_t superusr = is_root(p);
    char processname[MAXCOMLEN+1];
    proc_name(pid, processname, sizeof(processname));
    clock_sec_t secs = 0;
    uint32_t microsecs = 0;
    clock_get_system_microtime(&secs, &microsecs);
    unsigned long mins = secs/60;
    secs = secs%60;
    unsigned long hours = mins/60;
    if (strcmp("SYS_open", syscall) == 0) {
        struct open_args* oa = (struct open_args*) a;
        char path[MAXPATHLEN];
        size_t dummy = 0;
        int error = copyinstr((void*)oa->path, (void *)path, MAXPATHLEN, &dummy);
        if (!error) {
            if (strstr(path, "/.") != NULL) {
                //LOG_INFO("open hidden file path: %s\n",path);
                printf("[GREY FOX] %lu:%lu:%lu,%u; %s; %d; %d; %s; %d; %s;\n",
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
        printf("[GREY FOX] %lu:%lu:%lu,%u; %s; %d; %d; %s; %d;\n",
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
    return k(p, a, r);
}

/* This crap is generated automatically ofc.. */
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







