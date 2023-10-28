#include "kvm_api.h"
#include <cstring>
#include <memory>
#include <memory_resource>
#include <latch>
#include <string>
#include <thread>

void remote_storage_callback(size_t n, struct virtbuffer[], size_t res)
{
	// Do nothing
	storage_return_nothing();
}

extern "C" void remote_function()
{
	// Do nothing
}

void remote_writeback(void* addr, size_t len)
{
	//printf("Remote writeback called with addr=%p len=%zu\n", addr, len);
	//fflush(stdout);
	std::memset(addr, 0, len);
	strcpy((char*)addr, "Hello Writeback World");
}

void remote_backend_function(
	std::pmr::polymorphic_allocator<std::byte>& alloc,
	std::vector<int>& vec)
{
	if constexpr (true) {
		auto ctype = std::pmr::string("text/plain", alloc);
		auto result = std::pmr::string("Hello Storage World", alloc);
		for (auto i : vec) {
			result.append(" ", 1);
			const std::string s = std::to_string(i);
			result.append(s.data(), s.size());
		}

		backend_response(200, ctype.data(), ctype.size(),
			result.data(), result.size());
	} else if constexpr (false) {
		const char ctype[] = "text/plain";
		const char result[] = "Hello Storage World";

		backend_response(200, ctype, sizeof(ctype)-1,
			result, sizeof(result)-1);
	} else {
		const char ctype[] = "text/plain";
		thread_local int counter = 0;
		std::string content(128, '\0');
		const int len = snprintf(content.data(), content.size(),
			"Hello Storage World %d\n", ++counter);

		backend_response(200, ctype, sizeof(ctype)-1, content.data(), len);
	}
}

int main()
{
	printf("-== Hello World Storage program ready ==-\n");
	fflush(stdout);
	while (true) {
		void* ptr = NULL;
		size_t len = wait_for_storage_resume_paused(&ptr);
		//printf("Storage resumed with ptr=%p len=%zu\n", ptr, len);
		static const char msg[] = "Hello Remote World";
		memcpy(ptr, msg, sizeof(msg));
		//printf("Storage buffer: %s, returning\n", (char*)ptr);
	}
	// Create enough threads to handle backend requests
	if constexpr (false) {
		static std::vector<std::thread> g_threads;
		static const int num_threads = 32;
		g_threads.reserve(num_threads);
		std::latch start_latch(1+num_threads);
		for (int i = 0; i < num_threads; i++) {
			g_threads.emplace_back([&start_latch, i]() {
				printf("Backend thread %d started\n", i);
				start_latch.arrive_and_wait();
				wait_for_requests();
			});
		}
		start_latch.wait();
	}
	wait_for_requests();
}
