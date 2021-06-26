#ifndef MINI_SVM_EXIT_CODES_H
#define MINI_SVM_EXIT_CODES_H

enum MINI_SVM_EXITCODE {
	MINI_SVM_EXITCODE_VMEXIT_INVALID = -1,
	MINI_SVM_EXITCODE_VMEXIT_BUSY = -2,
	MINI_SVM_EXITCODE_VMEXIT_EXCP_0 = 0x40,
	MINI_SVM_EXITCODE_VMEXIT_EXCP_1,
	MINI_SVM_EXITCODE_VMEXIT_EXCP_2,
	MINI_SVM_EXITCODE_VMEXIT_EXCP_3,
	MINI_SVM_EXITCODE_VMEXIT_EXCP_4,
	MINI_SVM_EXITCODE_VMEXIT_EXCP_5,
	MINI_SVM_EXITCODE_VMEXIT_EXCP_6,
	MINI_SVM_EXITCODE_VMEXIT_EXCP_7,
	MINI_SVM_EXITCODE_VMEXIT_EXCP_8,
	MINI_SVM_EXITCODE_VMEXIT_EXCP_9,
	MINI_SVM_EXITCODE_VMEXIT_EXCP_10,
	MINI_SVM_EXITCODE_VMEXIT_EXCP_11,
	MINI_SVM_EXITCODE_VMEXIT_EXCP_12,
	MINI_SVM_EXITCODE_VMEXIT_EXCP_13,
	MINI_SVM_EXITCODE_VMEXIT_EXCP_14,
	MINI_SVM_EXITCODE_VMEXIT_EXCP_15,

	MINI_SVM_EXITCODE_VMEXIT_RDTSC = 0x6E,
	MINI_SVM_EXITCODE_VMEXIT_HLT = 0x78,
	MINI_SVM_EXITCODE_VMEXIT_VMMCALL = 0x81,
	MINI_SVM_EXITCODE_VMEXIT_RDTSCP = 0x87,
	MINI_SVM_EXITCODE_VMEXIT_CPUID = 0x72,

	MINI_SVM_EXITCODE_VMEXIT_SHUTDOWN = 0x7f,

	MINI_SVM_EXITCODE_VMEXIT_NPF = 0x400,
};

static inline const char *translate_mini_svm_exitcode_to_str(const enum MINI_SVM_EXITCODE exitcode) {
#define p(X) \
	case X: \
		return #X

	switch (exitcode) {
	p(MINI_SVM_EXITCODE_VMEXIT_INVALID);
	p(MINI_SVM_EXITCODE_VMEXIT_BUSY);
	p(MINI_SVM_EXITCODE_VMEXIT_SHUTDOWN);
	p(MINI_SVM_EXITCODE_VMEXIT_EXCP_0);
	p(MINI_SVM_EXITCODE_VMEXIT_EXCP_1);
	p(MINI_SVM_EXITCODE_VMEXIT_EXCP_2);
	p(MINI_SVM_EXITCODE_VMEXIT_EXCP_3);
	p(MINI_SVM_EXITCODE_VMEXIT_EXCP_4);
	p(MINI_SVM_EXITCODE_VMEXIT_EXCP_5);
	p(MINI_SVM_EXITCODE_VMEXIT_EXCP_6);
	p(MINI_SVM_EXITCODE_VMEXIT_EXCP_7);
	p(MINI_SVM_EXITCODE_VMEXIT_EXCP_8);
	p(MINI_SVM_EXITCODE_VMEXIT_EXCP_9);
	p(MINI_SVM_EXITCODE_VMEXIT_EXCP_10);
	p(MINI_SVM_EXITCODE_VMEXIT_EXCP_11);
	p(MINI_SVM_EXITCODE_VMEXIT_EXCP_12);
	p(MINI_SVM_EXITCODE_VMEXIT_EXCP_13);
	p(MINI_SVM_EXITCODE_VMEXIT_EXCP_14);
	p(MINI_SVM_EXITCODE_VMEXIT_EXCP_15);
	p(MINI_SVM_EXITCODE_VMEXIT_HLT);
	p(MINI_SVM_EXITCODE_VMEXIT_VMMCALL);
	p(MINI_SVM_EXITCODE_VMEXIT_RDTSC);
	p(MINI_SVM_EXITCODE_VMEXIT_RDTSCP);
	p(MINI_SVM_EXITCODE_VMEXIT_CPUID);
	p(MINI_SVM_EXITCODE_VMEXIT_NPF);
	default:
		return "unkown";
	};

#undef p
}

enum MINI_SVM_EXCEPTION {
#define p(X) MINI_SVM_EXCEPTION_ ## X
	p(DE) = 0U, // Divide by zero
	p(DB),      // Debug
	p(NMI),     // Non-maskable interrupt
	p(BP),      // Breakpoint
	p(OF),      // Overflow
	p(BR),      // Bound Range Exceeded
	p(UD),      // Invalid opcode
	p(NM),      // Device not available
	p(DF),      // Double fault
	p(CSO),     // Coprocessor segment overrun
	p(TS),      // Invalid TSS
	p(NP),      // Segment Not Present
	p(SS),      // Stack Segment Overflow
	p(GP),      // General-protection Fault
	p(PF),      // Page Fault
	p(MF) = 0x10U, // x86 floating-point exception
	p(AC), // Alignment check
	p(MC), // Machine check
	p(XF), // SIMD floating-point exception
	p(VE), // Virtualization exception
	p(SX) = 0x1FU, // Security exception
#undef p
};

static inline const char *translate_mini_svm_exception_number_to_str(const enum MINI_SVM_EXCEPTION excp) {
#define p(X) \
	case MINI_SVM_EXCEPTION_ ## X: \
		return #X " exception"
	switch(excp) {
	p(DE);
	p(DB);
	p(NMI);
	p(BP);
	p(OF);
	p(BR);
	p(UD);
	p(NM);
	p(DF);
	p(CSO);
	p(TS);
	p(NP);
	p(SS);
	p(GP);
	p(PF);
	p(MF);
	p(AC);
	p(MC);
	p(XF);
	p(VE);
	p(SX);
	default:
		return "unknown";
	}
#undef p
}

#endif // MINI_SVM_EXIT_CODES_H
