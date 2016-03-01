#! /usr/bin/python

'''
int mon_write(struct proc *p, struct write_args *u, user_ssize_t *r) {
    return generic_syscall_log(p, u, "SYS_write", kern_write, r);
}
'''

def strip_SYS(sys):
    return sys.replace('SYS_','').rstrip('\n')
    
    
    

hook1 = "int mon_" 
hook2 = "(struct proc *p, struct " 
hook3 = " *u, int *r) { return generic_syscall_log(p, u, '" 
hook4 = "', kernel_functions["
hook5 = "], r); }\n"


fin = open("SYS_calls_filtered.txt", "r")
fout = open("func_code_output.c", "w")

syscalls = fin.readlines()

for sys_call in syscalls:
    call = strip_SYS(sys_call)
    constructed = hook1 + call + hook2 + call + "_args" + hook3 + sys_call.rstrip() + hook4 + sys_call.rstrip() +hook5
    #fout.write(constructed)
    fout.write(constructed)
    
    
