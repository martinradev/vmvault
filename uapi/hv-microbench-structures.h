#ifndef MICROBENCH_STRUCTURES_H
#define MICROBENCH_STRUCTURES_H

enum class VmmCall : unsigned {
	StartRandomAccess,
	StartRandomJmp,
	StartRandomPageAccess,
	StartRandomPageJmp,
	DoneTest,

/*
 * rdi = result (cycles)
 * rsi = num cache lines
 */
	ReportResult,

/*
 * rdi = random sequence start address
 * rsi = num elements
 */
	RequestRandomDataAccessSeq,
	RequestRandomPageAccessSeq,
	RequestRandomJmpAccessSeq,
	RequestRandomJmpPageSeq,

};

#endif
