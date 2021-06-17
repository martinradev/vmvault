# Mini SVM

Mini SVM is a simple hypervisor based on SVM, currently targetting Linux.
Part of the hypervisor, which performs privileged operations, is implemented as a kernel module.
The rest is implemented as a user program which modifies the VMCB, guest physical memory, guest page tables, etc.

## Components

* Privileged HV code: it implements the hypervisor part which performs privileged operations (vmrun, physical memory allocations).

* User space HV code: setups VMCB, guest physical memory, guest page tables, registers.

* VM program: it's copied from the user space HV to guest physical memory.

## Running

1. Modify the kernel module makefile, and build it
2. Build the user space HV code.
3. Build the vm program
4. Load the kernel module: `taskset 0x1 sudo insmod mini-svm.ko`
5. Run the HV user space program: `taskset 0x1 sudo ./hv-user-space-program`

