#!/bin/sh
make clean
make
lsmod | grep attachjp
sudo rmmod attachjprobe
sudo insmod ./attachjprobe.ko
lsmod | grep attachjprobe 
cc -g tun.c -o pritun; sudo  ./pritun mul 
dmesg -T | tail

