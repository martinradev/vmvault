// Copyright (C) 2021 Martin Radev
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

#ifndef VMVAULT_EXIT_CODES_H
#define VMVAULT_EXIT_CODES_H

enum VMVAULT_EXITCODE {
	VMVAULT_EXITCODE_VMEXIT_INVALID = -1,
	VMVAULT_EXITCODE_VMEXIT_BUSY = -2,
	VMVAULT_EXITCODE_VMEXIT_EXCP_0 = 0x40,
	VMVAULT_EXITCODE_VMEXIT_EXCP_1,
	VMVAULT_EXITCODE_VMEXIT_EXCP_2,
	VMVAULT_EXITCODE_VMEXIT_EXCP_3,
	VMVAULT_EXITCODE_VMEXIT_EXCP_4,
	VMVAULT_EXITCODE_VMEXIT_EXCP_5,
	VMVAULT_EXITCODE_VMEXIT_EXCP_6,
	VMVAULT_EXITCODE_VMEXIT_EXCP_7,
	VMVAULT_EXITCODE_VMEXIT_EXCP_8,
	VMVAULT_EXITCODE_VMEXIT_EXCP_9,
	VMVAULT_EXITCODE_VMEXIT_EXCP_10,
	VMVAULT_EXITCODE_VMEXIT_EXCP_11,
	VMVAULT_EXITCODE_VMEXIT_EXCP_12,
	VMVAULT_EXITCODE_VMEXIT_EXCP_13,
	VMVAULT_EXITCODE_VMEXIT_EXCP_14,
	VMVAULT_EXITCODE_VMEXIT_EXCP_15,

	VMVAULT_EXITCODE_VMEXIT_RDTSC = 0x6E,
	VMVAULT_EXITCODE_VMEXIT_HLT = 0x78,
	VMVAULT_EXITCODE_VMEXIT_VMMCALL = 0x81,
	VMVAULT_EXITCODE_VMEXIT_RDTSCP = 0x87,
	VMVAULT_EXITCODE_VMEXIT_CPUID = 0x72,

	VMVAULT_EXITCODE_VMEXIT_SHUTDOWN = 0x7f,

	VMVAULT_EXITCODE_VMEXIT_NPF = 0x400,
};

static inline const char *translate_vmvault_exitcode_to_str(const enum VMVAULT_EXITCODE exitcode) {
#define p(X) \
	case X: \
		return #X

	switch (exitcode) {
	p(VMVAULT_EXITCODE_VMEXIT_INVALID);
	p(VMVAULT_EXITCODE_VMEXIT_BUSY);
	p(VMVAULT_EXITCODE_VMEXIT_SHUTDOWN);
	p(VMVAULT_EXITCODE_VMEXIT_EXCP_0);
	p(VMVAULT_EXITCODE_VMEXIT_EXCP_1);
	p(VMVAULT_EXITCODE_VMEXIT_EXCP_2);
	p(VMVAULT_EXITCODE_VMEXIT_EXCP_3);
	p(VMVAULT_EXITCODE_VMEXIT_EXCP_4);
	p(VMVAULT_EXITCODE_VMEXIT_EXCP_5);
	p(VMVAULT_EXITCODE_VMEXIT_EXCP_6);
	p(VMVAULT_EXITCODE_VMEXIT_EXCP_7);
	p(VMVAULT_EXITCODE_VMEXIT_EXCP_8);
	p(VMVAULT_EXITCODE_VMEXIT_EXCP_9);
	p(VMVAULT_EXITCODE_VMEXIT_EXCP_10);
	p(VMVAULT_EXITCODE_VMEXIT_EXCP_11);
	p(VMVAULT_EXITCODE_VMEXIT_EXCP_12);
	p(VMVAULT_EXITCODE_VMEXIT_EXCP_13);
	p(VMVAULT_EXITCODE_VMEXIT_EXCP_14);
	p(VMVAULT_EXITCODE_VMEXIT_EXCP_15);
	p(VMVAULT_EXITCODE_VMEXIT_HLT);
	p(VMVAULT_EXITCODE_VMEXIT_VMMCALL);
	p(VMVAULT_EXITCODE_VMEXIT_RDTSC);
	p(VMVAULT_EXITCODE_VMEXIT_RDTSCP);
	p(VMVAULT_EXITCODE_VMEXIT_CPUID);
	p(VMVAULT_EXITCODE_VMEXIT_NPF);
	default:
		return "unkown";
	};

#undef p
}

enum VMVAULT_EXCEPTION {
#define p(X) VMVAULT_EXCEPTION_ ## X
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

// TODO fix me
static inline const char *translate_vmvault_exception_number_to_str(const enum VMVAULT_EXCEPTION excp) {
#define p(X) \
	case VMVAULT_EXCEPTION_ ## X: \
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

#endif // VMVAULT_EXIT_CODES_H
