# the grey fox :wolf:
The grey fox is a kernel extension for Mac OS X that logs all performed system calls to the kernel by any process running on the system. Research for my master thesis required a dataset of all system calls performed by benign as well as malicious processes (malware). After analysis of the gathered datasets, several system call patterns that identified malware were extracted. 
grey fox replaces all the syscall function pointers in the `_sysent` table with pointers to own implementations that log the syscall to `/var/log/system.log` and return the result of the original syscall. It also implementes two KAuth listeners on the vnode and file operations scope used to gather additional metadata regarding `SYS_write` and `SYS_execve`.

OSX versions supported: 10.6, 10.7, 10.8, 10.9, 10.10, 10.11.

__NOTE__: since this kext is not signed with a valid kext certificate from Apple, you will have to enable kext developer mode; see I. This disabled kext signing and is a security risk. Don't forget to disable (see. II) this mode after you have used grey fox. 

#### I. Enabling KEXT-DEV mode

- Go to Terminal.app
- Type: `sudo nvram boot-args="debug=0x146 kext-dev-mode=1 keepsyms=1`

This enables `kext-dev-mode` and also enables symbolic links to ensure that crash logs are somewhat useful.

Iff you are running OSX 10.11, you will have to disable System Integerty Protection as well:
- Restart your Mac.
- Press CMD+R right after your Mac starts to boot up and shows the Apple logo.
- You Mac will reboot into Recovery mode. 
- Go to Utilities on the top menu bar and go to Terminal.
- Type: `csrutil disable`.
- Type: `reboot`.

You're good to go to III.

#### II. Disable KEXT-DEV mode

- Go to Terminal.app
- Type: `sudo nvram boot-args=""`

#### III. Install

- Unzip `grey_fox-x.x.zip` to the Desktop.
- Open Terminal.app.
- type: `sudo` and drag `install.sh` inside the `grey_fox-x.x` folder into the Terminal window.
- Terminal should resolve the path to `install.sh` and hit `Enter`.
- grey fox will now install, after a reboot it become active.

#### IV. Uninstall

- Open Terminal.app.
- type: `sudo` and drag `uninstall.sh` inside the `grey_fox-x.x` folder into the Terminal window.
- Terminal should resolve the path to `uninstall.sh` and hit `Enter`.
- grey fox will now uninstall. After a reboot, it is removed from your system.


#### V. Export logs

- Open Finder.app
- Press: CMD+Shift+G
- Type: `/var/log/`
- Copy and paste `system.log` and all `system.log.X.gz` to the Desktop. 
- Send the files to me :smile:



**Note**: this is a very **_hacky_** and **_experimental_** project that uses undocumented KPI's that are due to change in next major XNU releases. Also, note that many warnings in `hooker.c` are suppressed by the `-w` compile flag. Much of the heavy lifting is done by functions taken from [@osxreverser](https://github.com/gdbinit/onyx-the-black-cat) (thank you). 
