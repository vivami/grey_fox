#! /bin/bash

declare -i steps=3


echo "\n======grey fox uninstaller======\n"
if [ "$EUID" -ne 0 ]
  then echo "[-] Please run me as root (sudo sh uninstall.sh)\n"
  exit
fi
echo "(1/$steps) [+] Unloading grey fox from kernel..." 
kextunload /System/Library/Extensions/grey_fox.kext

echo "(2/$steps) [+] Removing grey fox from /System/Library/Extensions..."
rm -rf /System/Library/Extensions/grey_fox.kext

echo "(3/$steps) [+] Removing LaunchDaemon..."
rm -rf /Library/LaunchDaemons/com.fox.grey_fox.plist

echo "[+] Done.\n"