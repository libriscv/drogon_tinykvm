#pragma once
#include <thread>

namespace kvm
{
	class ProgramInstance;

	struct EpollServer
	{
		EpollServer(const TenantInstance* tenant, ProgramInstance* program);
		~EpollServer();

		bool manage(int fd, const char *argument);

		const auto& program() const { return *m_program; }
		auto& program() { return *m_program; }

		const auto& tenant() const { return *m_tenant; }
		auto& tenant() { return *m_tenant; }

	private:
		void epoll_main_loop();
		long fd_readable(int fd);
		void fd_writable(int fd);
		void hangup(int fd, const char *);
		bool epoll_add(int fd);

		int m_epoll_fd = -1;
		int m_listen_fd = -1;
		int m_event_fd = -1;
		bool m_running = true;
		/* We pre-allocate a reading area. */
		uint64_t m_read_vaddr = 0x0;

		std::thread m_epoll_thread;
		const TenantInstance* m_tenant;
		ProgramInstance* m_program;
	};
}
