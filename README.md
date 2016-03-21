# the grey fox :wolf:
The grey fox is a kernel extension for Mac OS X that logs performed system calls by any process running on the system. Research for my master thesis required a dataset of all system calls performed by benign as well as malicious processes (malware). After analysis of the gathered datasets, several system call patterns that identified malware were extracted. 
grey fox replaces (hooks) all the syscall function pointers in the `_sysent` table with pointers to own implementations that log the syscall to `/var/log/system.log` and return the result of the original syscall. It also implementes two KAuth listeners on the vnode and file operations scope used to gather additional metadata regarding `SYS_write` and `SYS_execve`.

OSX versions supported: 10.6, 10.7, 10.8, 10.9, 10.10, 10.11.

__NOTE__: since this kext is not signed with a valid kext certificate from Apple, you will have to enable kext developer mode; see I. This disables kext signing and is a security risk. Do not forget to disable this mode after you have used grey fox (see. II). 

#### I. Enabling KEXT-DEV mode
- Go to Terminal.app
- Type: `sudo nvram boot-args="debug=0x146 kext-dev-mode=1 keepsyms=1"`

This enables `kext-dev-mode` and also enables symbolic links to ensure that crash logs are somewhat useful.

Iff you are running OSX 10.11 (El Capitan), you will have to disable System Integerty Protection (SIP) as well:
- Restart your Mac
- Press CMD+R right after your Mac starts to boot up and shows the Apple logo
- Your Mac will reboot into Recovery mode
- Go to Utilities in the top menu bar and go to Terminal
- Type: `csrutil disable`
- Type: `reboot`

You're good to go to III or IV.

#### II. Disable KEXT-DEV mode

- Go to Terminal.app
- Type: `sudo nvram boot-args=""`

Iff you are running OSX 10.11 (El Capitan), you have to enable System Integerty Protection (SIP) again:
- Restart your Mac
- Press CMD+R right after your Mac starts to boot up and shows the Apple logo
- Your Mac will reboot into Recovery mode
- Go to Utilities in the top menu bar and go to Terminal
- Type: `csrutil enable`
- Type: `reboot`

All security protections are put in place again.

#### III. Manual run
Manually running grey fox is recommended. This temporarily loads grey fox in the kernel and ensures that it is not automatically started after a reboot. In case of a kernel panic (crash), your system will reboot in an untouched state.

- Unzip `grey_fox-0.1.x.zip` to the Desktop
- Open Terminal.app
- Type: `cd` and drag the `grey_fox-0.1.x` folder into the Terminal window and hit `Enter`
- Then type `sudo sh run_greyfox.sh` and hit `Enter`


#### IV. Install
`install.sh` will install `grey_fox.kext` in the kext proprietary directory `/Library/Extensions` and install a LaunchDaemon to ensure that it is launched upon system boot (this type of installation in itself could be identified as malicious behaviour). 

- Unzip `grey_fox-0.1.x.zip` to the Desktop
- Open Terminal.app
- Type: `cd` and drag the `grey_fox-0.1.x` folder into the Terminal window and hit `Enter`
- Then type `sudo sh install.sh` and hit `Enter`
- grey fox will now install, after a reboot it becomes active
- You can check this by opening Console.app in `Applications/Utilities/Console.app`. 

#### V. Uninstall
- Open Terminal.app
- Type: `cd` and drag the `grey_fox-0.1.x` folder into the Terminal window and hit `Enter`
- Then type `sudo sh uninstall.sh` and hit `Enter`
- Terminal should resolve the path to `uninstall.sh` and hit `Enter`

grey fox will now uninstall. After a reboot, it is removed from your system.


#### VI. Export logs
- Open Finder.app
- Press: CMD+Shift+G
- Type: `/var/log/`
- Copy and paste `system.log` and all `system.log.X.gz` to the Desktop

Please send the log files to me! :smile:



**Note**: this is a very **_hacky_** and **_experimental_** project that uses undocumented KPI's that are due to change in next major XNU releases. Also, note that many warnings in `hooker.c` are suppressed by the `-w` compile flag. Much of the heavy lifting is done by functions taken from [@osxreverser](https://github.com/gdbinit/onyx-the-black-cat) (thank you). 
