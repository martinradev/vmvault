#ifndef MINI_SVM_MM_H
#define MINI_SVM_MM_H

#include <linux/types.h>

enum MINI_GUEST_TABLE_TYPE {
	MINI_GUEST_TABLE_TYPE_PML4 = 0,
	MINI_GUEST_TABLE_TYPE_PDP,
	MINI_GUEST_TABLE_TYPE_PD,
	MINI_GUEST_TABLE_TYPE_PT,
};

struct mini_svm_guest_table {
	__u64 *entries;
	__u32 num_entries;
	enum MINI_GUEST_TABLE_TYPE type;
};

struct mini_svm_mm {
	struct mini_svm_guest_table *guest_table;
};

struct mini_svm_guest_table *mini_svm_construct_debug_mm_one_page(void *vm_page);
void destroy_mini_svm_guest_table(struct mini_svm_guest_table *root);

#endif // MINI_SVM_MM_H
