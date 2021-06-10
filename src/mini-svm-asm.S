#include <linux/linkage.h>
#include <asm/asm.h>

/*
	RDI contains the VMCB
	RSI contains the MINI_SVM_VM_REGS
*/
SYM_FUNC_START(__mini_svm_run)

// save host registers on the stack
push %rbx
push %rcx
push %rdx
push %rdi
push %rsi
push %rbp
push %r8
push %r9
push %r10
push %r11
push %r12
push %r13
push %r14
push %r15

// Save vm regs base
push %rsi

// Save vmcb
push %rdi

// use rax as base for vm context
mov %rsi, %rax

// load other registers
mov 1 * 8(%rax), %rbx
mov 2 * 8(%rax), %rcx
mov 3 * 8(%rax), %rdx
mov 4 * 8(%rax), %rdi
mov 5 * 8(%rax), %rsi
mov 6 * 8(%rax), %rbp

// pop vmcb into rax
pop %rax

// run vm
clgi
vmrun
stgi

pop %rax

mov %rbx, 1 * 8(%rax)
mov %rcx, 2 * 8(%rax)
mov %rdx, 3 * 8(%rax)
mov %rdi, 4 * 8(%rax)
mov %rsi, 5 * 8(%rax)
mov %rbp, 6 * 8(%rax)

// restore host registers
pop %r15
pop %r14
pop %r13
pop %r12
pop %r11
pop %r10
pop %r9
pop %r8
pop %rbp
pop %rsi
pop %rdi
pop %rdx
pop %rcx
pop %rbx

ret 
SYM_FUNC_END(__mini_svm_run)
