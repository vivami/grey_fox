#! /usr/bin/python

'''
        case	SYS_sigaction:
            sysent[SYS_sigaction].sy_call = kern_sigaction;
            printf("[GREY FOX] Unhooked SYS_sigaction.\n");
            break;
'''

def strip_SYS(sys):
    return sys.replace('SYS_','').rstrip('\n')
    
    
    

hook1 = "sysent[" 
hook2 = "].sy_call = kern_" 
hook3 = ";\n\tprintf('[GREY FOX] Unhooked " 
hook4 = ".\ n');\n\tbreak;\n" 
#hook5 = "');\n\tbreak;\n"


fin = open("SYS_calls.txt", "r")
fout = open("output_unhook_switchcase.c", "w")

syscalls = fin.readlines()

for sys_call in syscalls:
    call = strip_SYS(sys_call)
    constructed = "case " + sys_call.rstrip() + ":\n\t" + hook1 + sys_call.rstrip() + hook2 + call + hook3 + sys_call.rstrip() + hook4
    fout.write(constructed)
    #fout.write(call)
    
    