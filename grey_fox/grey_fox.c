//
//  GREY FOX.c
//  GREY FOX
//
//  Created by vivami on 04/11/15.
//  Copyright © 2015 vivami. All rights reserved.
//

#include "my_data_definitions.h"
#include "sysent.h"
#include "hooker.h"
#include "proc_exec_mon.h"
#include <sys/param.h>
#include <IOKit/IOLib.h>

kern_return_t grey_fox_start(kmod_info_t * ki, void *d);
kern_return_t grey_fox_stop(kmod_info_t *ki, void *d);

/* Globals for syscall hooking */
struct sysent_yosemite *_sysent;


kern_return_t grey_fox_start(kmod_info_t * ki, void *d)
{
    printf("[GREY FOX] Rawr, hi kernel!\n");
    mach_vm_address_t kernel_base = 0;
    if ((_sysent = find_sysent(&kernel_base)) == NULL) {
        return KERN_FAILURE;
    }
    hook_all_syscalls(_sysent);
    
    plug_kauth_listener();
    
    return KERN_SUCCESS;
}

kern_return_t grey_fox_stop(kmod_info_t *ki, void *d)
{
    unhook_all_syscalls(_sysent);

    unplug_kauth_listener();
    
    /* This is super ugly, but waiting for all processes
       to finish using my hooked functions... Should be fixed
       semaphores.
     */
    IOSleep(20000);
    printf("[GREY FOX] Byebye..\n");
    return KERN_SUCCESS;
}
