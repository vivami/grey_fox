#! /bin/bash

echo "[!] Ensure that grey_fox.kext is in the same directory as run_greyfox.sh!"

if [ "$EUID" -ne 0 ]
  then echo "[-] Please run me as root (sudo sh install.sh)\n"
  exit
fi

chgrp -R wheel grey_fox.kext
chown -R root grey_fox.kext
kextload grey_fox.kext
echo "[+] grey fox is loaded. Check Console.app for [GREY FOX] messages."
echo "[+] To unload: sudo kextunload grey_fox.kext"