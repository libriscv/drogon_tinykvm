#include "kvm_api.h"
#include <cstring>
#include <memory>
#include <memory_resource>
#include <latch>
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
	std::memset(addr, 0, len);
}

void remote_backend_function(std::pmr::polymorphic_allocator<std::byte>& alloc)
{
	if constexpr (false) {
		const char ctype[] = "text/plain";
		const char result[] = "Hello Storage World";

		backend_response(200, ctype, sizeof(ctype)-1,
			result, sizeof(result)-1);
	} else if constexpr (false) {
		auto ctype = std::pmr::string("text/plain", alloc);
		auto result = std::pmr::string("Hello Storage World", alloc);

		backend_response(200, ctype.data(), ctype.size(),
			result.data(), result.size());
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
	printf("-== Hello World Storage program ready ==-\n");
	fflush(stdout);
	wait_for_requests();
}
