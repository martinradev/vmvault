obj-m = src/mini-svm.o

kernel_dir = /home/sisu/code/linux-kernels/linux-5.11.15/
#kernel_dir = /usr/lib/modules/5.8.0-50-generic/build

all:
	make -C $(kernel_dir) M=$(PWD) modules

clean:
	make -C $(kernel_dir) M=$(PWD) clean
