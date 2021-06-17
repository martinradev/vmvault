
global _start

section .text
_start:
	mov rax, 0x979713371337
	vmmcall
	asd:
	jmp asd
