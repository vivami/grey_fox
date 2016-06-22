# the grey fox :wolf:
The grey fox is a kernel extension for Mac OS X that logs performed system calls by any process running on the system. Research for my master thesis required a dataset of all system calls performed by benign as well as malicious processes (malware). After analysis of the gathered datasets, several system call patterns that identified malware were extracted. 
grey fox replaces (hooks) all the syscall function pointers in the `_sysent` table with pointers to own implementations that log the syscall using `kprintf()` and return the result of the original syscall. It also implementes two KAuth listeners on the vnode and file operations scope used to gather additional metadata regarding `SYS_write` and `SYS_execve`.

OSX versions supported: 10.6, 10.7, 10.8, 10.9, 10.10, 10.11.

__NOTE__: kext is now signed! :smile: Questions/requests? Let me know in the [issues](https://github.com/vivami/grey_fox/issues)!

####Environment
grey fox is best ran in a VM (prefereably VMware), since VMware logs flawlessly via a serial port. `printf()`'s buffer is not flushed in time causing malformed output. `kprintf()` is thread-save, since a log operation over the serial port is [fully synchronous](https://stackoverflow.com/questions/36327605/printf-in-system-call-returns-malformed-output/). 

#### III. Manual run
Manually running grey fox is recommended. This temporarily loads grey fox in the kernel and ensures that it is not automatically started after a reboot. In case of a kernel panic (crash), your system will reboot in an untouched state.

- Unzip `grey_fox-0.x.x.zip` to the Desktop
- Open Terminal.app
- Type: `cd` and drag the `grey_fox-0.x.x` folder into the Terminal window and hit `Enter`
- Then type `sudo sh run_greyfox.sh` and hit `Enter`


#### VI. Export logs
- Define an output file for VMware serial port ([VMware docs](https://pubs.vmware.com/fusion-5/index.jsp?topic=%2Fcom.vmware.fusion.help.doc%2FGUID-F1E20E9E-7588-4F3B-A0FC-A5FA7A68CFB4.html))
- Boot the VM
- Load greyfox
- Find the logs in your defined file in step 1.



**Note**: this is a very **_hacky_** and **_experimental_** project that uses undocumented KPI's that are due to change in next major XNU releases. Also, note that many warnings in `hooker.c` are suppressed by the `-w` compile flag. Much of the heavy lifting is done by functions taken from [@osxreverser](https://github.com/gdbinit/onyx-the-black-cat) (thank you). 

