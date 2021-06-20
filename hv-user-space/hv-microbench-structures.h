#ifndef MICROBENCH_STRUCTURES_H
#define MICROBENCH_STRUCTURES_H

/*
 * rdi = random sequence start address
 * rsi = num elements
 */
#define VMMCALL_REQUEST_RANDOM_DATA_ACCESS_SEQUENCE 0x1

/*
 * rdi = result (cycles)
 * rsi = num cache lines
 */
#define VMMCALL_REPORT_RESULT 0x2

#define VMMCALL_MICROBENCHING_DONE 0x3

/*
 * rdi = random sequence start address
 * rsi = num elements
 */
#define VMMCALL_REQUEST_RANDOM_JMP_SEQUENCE 0x4

#endif
