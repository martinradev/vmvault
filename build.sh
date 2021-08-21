#!/bin/sh

if [ "$1" = "build_nested" ]; then
	KERNEL_DIR=/home/sisu/code/linux-kernels/linux/ make all
elif [ "$1" = "build" ]; then
	KERNEL_DIR=/home/sisu/code/linux-kernels/linux/ make all
elif [ "$1" = "run_nested" ]; then
	cd ./testing
	./run.sh
elif [ "$1" = "run" ]; then
	sudo insmod ./vmvault.ko vmvault_debug_enable_logging=0
else
	echo "Unrecognized command " "$1"
fi
