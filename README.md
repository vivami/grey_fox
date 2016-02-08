# the grey fox :wolf:
The grey fox is a kernel extension for Mac OS X (10.6 to 10.10) that logs all performed system calls by any process running on the system. Research for my master thesis required a dataset of all system calls performed by benign as well as malicious processes (malware). It also implementes two KAuth listeners on the vnode and file operations scope used to gather extra metadata. After analysis of the gathered datasets, several system call patterns that identified malware were extracted. grey fox replaces all the syscall function pointers in the `_sysent` table with pointers to own implementations that log the syscall and return the result of the original syscall. 

**Note**: this is a very _hacky_ and _experimental_ project that contain many parts of fugly code and uses undocumented KPI's. Many warnings in `hooker.c` are suppressed. Much of the heavy lifting is done by functions taken from [@osxreverser](https://github.com/gdbinit/onyx-the-black-cat) (thank you). 

### License
This project holds the [GPLv3](http://choosealicense.com/licenses/gpl-3.0/).