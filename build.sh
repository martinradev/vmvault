#!/bin/sh

KERNEL_DIR_NESTED=/home/sisu/code/linux-kernels/linux/
KERNEL_DIR_HOST=/usr/lib/modules/5.13.0-rc4+/build

if [ "$1" = "build_nested" ]; then
	KERNEL_DIR=$KERNEL_DIR_NESTED make all
elif [ "$1" = "run_nested" ]; then
	cd ./testing
	./run.sh
elif [ "$1" = "build" ]; then
	KERNEL_DIR=$KERNEL_DIR_HOST make all
elif [ "$1" = "run" ]; then
	sudo insmod ./vmvault-mini.ko vmvault_debug_enable_logging=0
else
	echo "Unrecognized command " "$1"
fi
