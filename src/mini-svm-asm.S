#include <linux/linkage.h>
#include <asm/asm.h>

SYM_FUNC_START(hello_world)

mov %rdi, %rax
vmrun
ret 
SYM_FUNC_END(hello_world)
