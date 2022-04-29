#!/bin/bash

mv muadDib.ko /lib/modules/$(uname -r)/kernel/drivers/
echo "muadDib.ko" >> /etc/modules
depmod
insmod /lib/modules/$(uname -r)/kernel/drivers/muadDib.ko

