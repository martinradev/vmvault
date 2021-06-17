void _start() {
	const char msg[] = "Hello World!";
	for (unsigned i = 0; i < sizeof(msg); ++i) {
		asm volatile(
			"xorl %%eax, %%eax\n\t"
			"movb %0, %%al\n\t"
			"vmmcall\n\t"
			:
			: "r"(msg[i])
			: "%rax", "%rbx", "%rcx", "%rdx"
		);
	}
	asm volatile(
		"hlt\n\t"
	);
}
