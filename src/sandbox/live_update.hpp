#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

struct LiveUpdateParams {
	std::vector<uint8_t> binary;
	const bool     is_debug;
	const uint16_t debug_port;
};

struct LiveUpdateResult {
	std::string conclusion;
	int success;
};

typedef struct {
	int idx;
	int arg1;
	int arg2;
} vcall_info;
