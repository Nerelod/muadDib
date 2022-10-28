#!/bin/bash


make
mv muadDib.ko /lib/modules/$(uname -r)/kernel/drivers/
echo "muadDib" >> /etc/modules
depmod
insmod /lib/modules/$(uname -r)/kernel/drivers/muadDib.ko
