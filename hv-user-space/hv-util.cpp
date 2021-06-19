#include "hv-util.h"

#include <algorithm>
#include <random>

void generate_random_unique_sequence(size_t n, std::vector<unsigned long> &indices) {
	indices.resize(n - 1);
	for (size_t i = 1; i < n; ++i) {
		indices[i - 1] = i;
	}

	std::random_device rd;
	std::mt19937 g(rd());
	std::shuffle(indices.begin(), indices.end(), g);

	indices.push_back(0);
}

