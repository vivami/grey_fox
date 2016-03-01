#! /usr/bin/python


def strip_SYS(sys):
    return sys.replace('SYS_','').rstrip('\n')
    

fin = open("sys_calls_processed.txt", "r")
fout = open("SYS_calls_filtered.txt", "w")

syscalls = fin.readlines()

for line in syscalls:
    if "SYS_" in line and "case" in line:
        line = line.replace("case", "")
        line = line.replace(":", "")
        fout.write(line.strip(" "))

    # call = strip_SYS(sys_call)
    # constructed = "case " + sys_call.rstrip() + ":\n\t" + hook1 + sys_call.rstrip() + hook2 + call + hook3 + sys_call.rstrip() + hook4
    # fout.write(constructed)
    # #fout.write(call)
    
    