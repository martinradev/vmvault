
SECTIONS
{
	.enter :
	{
		vm-program.o(.text)
	}
	.remaining :
	{
		util.o(.text)
	}
}
