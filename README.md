# SE-Vault Mini (HV + Tiny VM)

`SE-Vault Mini` is a PoC implementation for storing cryptographic keys and performing encryption/decryption requests inside a small VM operated by a small HV.
Users of the Linux Kernel Crypto API can transparently utilize `SE-Vault Mini` if the corresponding cipher is supported.
Each logical core on the Host can make use of `SE-Vault Mini` in parallel.

This specific idea and implementation is a spin-off of my Master thesis: *Leveraging Hardware-Assisted TEEs to Protect Host Secrets in an OS-Level Virtualization Environment*.
This implementation (`SE-Vault Mini`) improves upon the idea by reducing the memory footprint and resource utilization.
Because the original depended on QEMU, KVM and a Linux VM, lots of memory and computation was wasted.

One drawback of my current HV implementation is that it lacks support for SEV/SEV-ES to have the memory of the VM be encrypted.
The whole point of this academic endeavour is that the VM's memory would be encrypted, so the keys would never be accessible.
The work is tracked under https://github.com/martinradev/sevault-mini-svm/issues/3 and https://github.com/martinradev/sevault-mini-svm/issues/4.
This shouldn't be too difficult but requires one of AMD EPYC CPUs.
Note that one can already implement something like this, with SEV-ES and SEV-SNP support, purely based on KVM but this would remove the fun from implementing a small hypervisor.

## Components

### SE-Vault Mini Tiny VM
The VM is a small program written in C++17 and built without a C++ runtime.
The VM contains a small implementation of AES-128 utilizing `aesni` and supports both ECB and CBC mode.
The VM image itself fits within 4096 bytes but uses more memory for page tables, stack, communication blocks, VMCB pages, etc.
The VM has full access to the physical memory of the system which avoids extra memory copies when serving encryption and encryption requests.
The code is located in `vm-code/`.

### SE-Vault Mini Hypervisor
The hypervisor is implemented as a Linux kernel module and uses AMD SVM, but only few of its features.
The code is located in `sevault-mini-hv`.

## Life of an encryption request

1. Some user of the Kernel Crypto API has registered a key already and sends an encryption request.
   This request would likely be dispatched to `SE-Vault Mini` module because it has a low `cra_priority` value.
2. The `SE-Vault Mini` cipher implementation would take the request and walk the scatter list.
   Each entry would be translated to the scatter-list format in the HV-VM communication block.
   Once the limit is reached, the HV would update the request information and resume the VM.
3. The VM would validate the request and walk the scatter-list to perform the requested operation.
4. Once finished, the VM would update the return value in the communication block and execute the `VMGEXIT` instruction.
   This instruction was selected because it results in an "Automatic Exit (#AE)" which avoids having to setup the IDT under SEV-ES+.
5. The HV handles the exit and propagates the return value in the communication block to the caller.

## Build & Run

The build scripts support building and testing with running the HV as a Host kernel module and also running the HV under ***nested virtualization***.
With nested virtualization, `SE-Vault Mini` is run within a VM as a Level 2 hypervisor.
This protects the Host from memory corruptions, resource leaks, misconfigured system state, etc.

To build and run, check `build.sh`:
1. On host: Modify `build.sh` to have the correct Linux tree path
2. On host: `./build.sh build_nested`
3. On host: `./build.sh run_nested`
4. Inside the VM: `./run_kcapi.sh`

*TODO: I need to provide you with a download link for the VM (bzImage, initramfs, launch script)*

## Warning

This is a Work-in-Progress project and it likely has bugs. Please run it inside a VM to avoid corrupting your memory.

## Contributing

If you like the project and want to hack on it, write a pull request and I would happily review it.

## Authors

Martin Radev

## Attribution

I would like to thank Christian Epple, Felix Wruck, Michael Weiss for giving feedback during meetings, and to Christian Epple for supervising my Master thesis.
