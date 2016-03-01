#! /usr/bin/python

'''
kern_sigaction = sysent[SYS_sigaction].sy_call;
sysent[SYS_sigaction].sy_call = mon_sigaction;
printf("[GREY FOX] Hooked SYS_sigaction.\n");
break;
'''

'''
case SYS_open:
            kernel_functions[SYS_open] = (void*)sysent[SYS_open].sy_call;
            //kern_open = (void*)sysent[SYS_open].sy_call;
            sysent[SYS_open].sy_call = (sy_call_t*)mon_open;
            kprintf("[GREY FOX] Hooked SYS_open.\n");
            break;
'''
def strip_SYS(sys):
    return sys.replace('SYS_','').rstrip('\n')
    
    
    

hook1 = "] = (void*)sysent[" 
hook2 = "].sy_call;\n\tsysent[" 
hook3 = "].sy_call = " 
hook4 = ";\n\tprintf('[GREY FOX] Hooked " 
hook5 = "\ n');\n\tbreak;\n"


fin = open("SYS_calls_filtered.txt", "r")
fout = open("output_hook_code.txt", "w")

syscalls = fin.readlines()

for sys_call in syscalls:
    call = strip_SYS(sys_call)
    constructed = "case " + sys_call.rstrip() + ":\n\tkernel_functions[" + sys_call.rstrip() + hook1 + sys_call.rstrip() + hook2 + sys_call.rstrip() + hook3 + "mon_" + call + hook4 + sys_call.rstrip() + hook5
    fout.write(constructed)
    #fout.write(call)
    
    
