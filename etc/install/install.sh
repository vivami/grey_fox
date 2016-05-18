#! /bin/bash

declare -i steps=4


echo "\n\t======grey fox installer======\n"
if [ "$EUID" -ne 0 ]
  then echo "[-] Please run me as root (sudo sh install.sh)\n"
  exit
fi
echo "(1/$steps) [+] Installing grey fox to /System/Library/Extensions..."
cp -R grey_fox.kext /Library/Extensions/grey_fox.kext
chmod -R 755 /Library/Extensions/grey_fox.kext
chown -R root:wheel /Library/Extensions/grey_fox.kext

echo "(2/$steps) [+] Creating LaunchDaemon..."
cp -R com.fox.grey_fox.plist /Library/LaunchDaemons/com.fox.grey_fox.plist
chown -R root:wheel /Library/LaunchDaemons/com.fox.grey_fox.plist

echo "(3/$steps) [+] Launching grey fox!\n"
launchctl load -w /Library/LaunchDaemons/com.fox.grey_fox.plist

echo "(4/$steps) [+] Cleaning kernel cache, may be necessary"
rm -R Extensions.kextcache
rm -R Extensions.mkext

echo "[+] Done. Maybe reboot? Check Console.app for GREY FOX messages."