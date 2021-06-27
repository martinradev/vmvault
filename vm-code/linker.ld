ENTRY(_start)

MEMORY
{
	VM_IMAGE (rwx) : ORIGIN = 0x8000, LENGTH = 0x8000
}

SECTIONS
{
	.enter_vm :
	{
		vm-program.o(.text._start)
		vm-program.o(.text*)
	} > VM_IMAGE
}
