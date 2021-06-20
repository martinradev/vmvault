#!/bin/sh

KERNEL_DIR_NESTED=/home/sisu/code/linux-kernels/linux-5.11.15/
KERNEL_DIR_HOST=/usr/lib/modules/5.13.0-rc4+/build

if [ "$1" = "build_nested" ]; then
	KERNEL_DIR=$KERNEL_DIR_NESTED make
elif [ "$1" = "run_nested" ]; then
	cd ./testing
	./run.sh
elif [ "$1" = "build" ]; then
	KERNEL_DIR=$KERNEL_DIR_HOST make
elif [ "$1" = "run" ]; then
	taskset 0x2 sudo insmod ./mini-svm.ko
	taskset 0x2 sudo ./hv-user-space/hv-user-space-program ./vm-code/vm-program
	taskset 0x2 sudo rmmod mini-svm.ko
else
	echo "Unrecognized command " "$1"
fi
