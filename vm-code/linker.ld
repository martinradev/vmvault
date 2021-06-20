
SECTIONS
{
	.enter :
	{
		vm-program.o(.text._Z6_startv)
		vm-program.o(.text*)
	}
	.remaining :
	{
		util.o(.text)
	}
}
