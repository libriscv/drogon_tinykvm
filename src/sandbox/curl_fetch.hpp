#pragma once
#include <cstddef>
#include <functional>
#include <string>

namespace kvm
{
struct MemoryStruct {
    char*  memory;
    size_t size;
};

using kvm_curl_callback = std::function<void(long status, MemoryStruct *chunk)>;

int curl_fetch(
	const std::string& url, kvm_curl_callback callback, const char* condhdr = nullptr);

} // kvm
