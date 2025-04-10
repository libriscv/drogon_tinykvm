#include "tenant_instance.hpp"
#include "program_instance.hpp"
#include "utils/crc32.hpp"
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>
using namespace tinykvm;
//#define VERBOSE_SYSCALLS

#ifdef VERBOSE_SYSCALLS
#define SYSPRINT(fmt, ...) printf(fmt, __VA_ARGS__);
#else
#define SYSPRINT(fmt, ...) /* */
#endif

//#include "system_calls_http.cpp"
//#include "system_calls_regex.cpp"
#include "system_calls_fetch.cpp"
#include "system_calls_api.cpp"

namespace kvm {
uint32_t crc32_kvm(vCPU& cpu, uint64_t vaddr, size_t rsize)
{
    uint32_t hash = 0xFFFFFFFF;
    cpu.machine().foreach_memory(vaddr, rsize,
        [&] (const std::string_view data) {
            hash = crc32c_hw(hash, data.begin(), data.size());
        });
	return hash ^ 0xFFFFFFFF;
}

void MachineInstance::sanitize_path(char* buffer, size_t buflen)
{
	buffer[buflen-1] = 0;
	const size_t len = strnlen(buffer, buflen);
	for (const auto& gucci_path : tenant().config.group.allowed_paths)
	{
		if (gucci_path.size() <= len &&
			memcmp(buffer, gucci_path.c_str(), gucci_path.size()) == 0) {
			//printf("Path OK: %.*s against %s\n",
			//	(int)len, buffer, gucci_path.c_str());
			return;
		}
	}
	if (len > 0) {
		if (tenant().config.group.verbose) {
			printf("Path failed: %.*s\n", (int)len, buffer);
		}
		throw std::runtime_error("Disallowed path used");
	}
}

void MachineInstance::sanitize_file(char* buffer, size_t buflen)
{
	const auto& state_file = TenantConfig::guest_state_file;
	// Test against state file including the terminating zero:
	if (memcmp(buffer, state_file.c_str(), state_file.size()+1) == 0) {
		return;
	}
	throw std::runtime_error("Writable file must be the provided state file");
}

static void syscall_unknown(vCPU& cpu, MachineInstance& inst, unsigned scall)
{
	printf("%s: Unhandled system call %u\n",
		inst.name().c_str(), scall);
	auto& regs = cpu.registers();
	regs.rax = -ENOSYS;
	cpu.set_registers(regs);
}

static void syscall_log(vCPU& cpu, MachineInstance&)
{
	auto& regs = cpu.registers();
	const uint64_t g_buf = regs.rdi;
	const uint16_t g_len = regs.rsi;
	cpu.machine().foreach_memory(g_buf, g_len,
		[&cpu] (std::string_view buffer)
		{
			cpu.machine().print(buffer.begin(), buffer.size());
		});
}

void MachineInstance::setup_syscall_interface()
{
	Machine::install_unhandled_syscall_handler(
	[] (vCPU& cpu, unsigned scall) {
		auto& inst = *cpu.machine().get_userdata<MachineInstance>();
		switch (scall) {
			case 0x10000: // REGISTER_FUNC
				syscall_register_func(cpu, inst);
				return;
			case 0x10001: // WAIT_FOR_REQUESTS
				syscall_wait_for_requests(cpu, inst);
				return;
			case 0x10002: // PAUSE_FOR_REQUESTS
				syscall_pause_for_requests(cpu, inst);
				return;
			case 0x10005: // SET_CACHEABLE
				syscall_set_cacheable(cpu, inst);
				return;
			case 0x10010: // BACKEND_RESPONSE
				syscall_backend_response(cpu, inst);
				return;
			case 0x10012: // BACKEND_STREAMING_RESPONSE
				syscall_backend_streaming_response(cpu, inst);
				return;
			case 0x10011: // STORAGE_RETURN
				syscall_storage_return(cpu, inst);
				return;
			case 0x10013: // STORAGE_NORETURN
				syscall_storage_noreturn(cpu, inst);
				return;
			case 0x10020: // HTTP_APPEND
				//syscall_http_append(cpu, inst);
				return;
			case 0x10021: // HTTP_SET
				//syscall_http_set(cpu, inst);
				return;
			case 0x10022: // HTTP_FIND
				//syscall_http_find(cpu, inst);
				return;
			case 0x10023: // HTTP_METHOD
				//syscall_http_method(cpu, inst);
				return;
			case 0x10030: // REGEX_COMPILE
				//syscall_regex_compile(cpu, inst);
				return;
			case 0x10031: // REGEX_FREE
				//syscall_regex_free(cpu, inst);
				return;
			case 0x10032: // REGEX_MATCH
				//syscall_regex_match(cpu, inst);
				return;
			case 0x10033: // REGEX_SUBST
				//syscall_regex_subst(cpu, inst);
				return;
			case 0x10035: // REGEX_COPYTO
				//syscall_regex_copyto(cpu, inst);
				return;
			case 0x10100:
				//syscall_set_backend(cpu, inst);
				return;
			case 0x10700: // SHARED_MEMORY_AREA
				syscall_shared_memory(cpu, inst);
				return;
			case 0x10703: // MAKE_EPHEMERAL
				syscall_make_ephemeral(cpu, inst);
				return;
			case 0x10706: // IS_STORAGE
				syscall_is_storage(cpu, inst);
				return;
			case 0x10707: // STORAGE_ALLOW
				syscall_storage_allow(cpu, inst);
				return;
			case 0x10708: // STORAGE CALL VECTOR
				syscall_storage_callv(cpu, inst);
				return;
			case 0x10709: // ASYNC_STORAGE TASK
				syscall_storage_task(cpu, inst);
				return;
			case 0x1070A: // STOP_STORAGE TASK
				syscall_stop_storage_task(cpu, inst);
				return;
			case 0x10710: // MULTIPROCESS
				syscall_multiprocess(cpu, inst);
				return;
			case 0x10711: // MULTIPROCESS_ARRAY
				syscall_multiprocess_array(cpu, inst);
				return;
			case 0x10712: // MULTIPROCESS_CLONE
				syscall_multiprocess_clone(cpu, inst);
				return;
			case 0x10713: // MULTIPROCESS_WAIT
				syscall_multiprocess_wait(cpu, inst);
				return;
			case 0x10A00: // GET_MEMINFO
				syscall_memory_info(cpu, inst);
				return;
			case 0x20000: // CURL_FETCH
				syscall_fetch(cpu, inst);
				return;
			case 0x7F000: // LOG
				syscall_log(cpu, inst);
				return;
			case 0x7FDEB: // IS_DEBUG
				syscall_is_debug(cpu, inst);
				return;
			case 0x7F7F7: // BREAKPOINT
				syscall_breakpoint(cpu, inst);
				return;
			default:
				syscall_unknown(cpu, inst, scall);
		}
	});
	Machine::install_syscall_handler(
		0, [] (vCPU& cpu) { // READ
			auto& inst = *cpu.machine().get_userdata<MachineInstance>();
			auto& regs = cpu.registers();
			SYSPRINT("READ to fd=%lld, data=0x%llX, size=%llu\n",
				regs.rdi, regs.rsi, regs.rdx);
			int fd = inst.m_fd.translate(regs.rdi);

			// TODO: Make proper tenant setting for file sizes
			// However, this should be large enough for most reads.
			static constexpr size_t MAX_READ_BUFFERS = 128;
			tinykvm::Machine::WrBuffer buffers[MAX_READ_BUFFERS];

			/* Writable readv buffers */
			auto bufcount = cpu.machine().writable_buffers_from_range(
				MAX_READ_BUFFERS, buffers,
				regs.rsi, regs.rdx);

			regs.rax = readv(fd, (struct iovec *)&buffers[0], bufcount);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		1, [] (vCPU& cpu) { // WRITE
			auto& inst = *cpu.machine().get_userdata<MachineInstance>();
			auto& regs = cpu.registers();
			const int    fd = regs.rdi;
			const size_t bytes = regs.rdx;
			SYSPRINT("WRITE to fd=%lld, data=0x%llX, size=%llu\n",
				regs.rdi, regs.rsi, regs.rdx);
			// TODO: Make proper tenant setting for file sizes
			if (fd == 1 || fd == 2) {
				if (bytes > 1024*64) {
					regs.rax = -1;
					cpu.set_registers(regs);
					return;
				}
			}
			else if (bytes > 1024*1024*4) {
				regs.rax = -1;
				cpu.set_registers(regs);
				return;
			}
			if (fd != 1 && fd != 2) {
				/* Use gather-buffers and writev */
				static constexpr size_t WRITEV_BUFFERS = 64;
				tinykvm::Machine::Buffer buffers[WRITEV_BUFFERS];
				const auto bufcount =
					cpu.machine().gather_buffers_from_range(WRITEV_BUFFERS, buffers, regs.rsi, bytes);

				/* Complain about writes outside of existing FDs */
				const int fd = inst.m_fd.translate(regs.rdi);
				regs.rax = writev(fd, (const struct iovec *)buffers, bufcount);
			}
			else {
				const auto g_buf = regs.rsi;
				cpu.machine().foreach_memory(g_buf, bytes,
					[&cpu] (std::string_view buffer)
					{
						cpu.machine().print(buffer.begin(), buffer.size());
					});
				regs.rax = bytes;
			}
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		3, [] (vCPU& cpu) { // CLOSE
			auto& inst = *cpu.machine().get_userdata<MachineInstance>();
			auto& regs = cpu.registers();

			int idx = inst.m_fd.find(regs.rdi);
			if (idx >= 0) {
				auto& entry = inst.m_fd.get(idx);
				const int res = close(entry.item);
				entry.free();
				if (res < 0)
					regs.rax = -errno;
				else
					regs.rax = 0;
			} else {
				regs.rax = -EBADF;
			}
			SYSPRINT("CLOSE(fd=%lld) = %lld\n", regs.rdi, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		4, [] (vCPU& cpu) { // STAT
			auto& inst = *cpu.machine().get_userdata<MachineInstance>();
			auto& regs = cpu.registers();
			const auto vpath = regs.rdi;

			char path[256];
			cpu.machine().copy_from_guest(path, vpath, sizeof(path));
			inst.sanitize_path(path, sizeof(path));

			struct stat vstat;
			regs.rax = stat(path, &vstat);
			SYSPRINT("STAT to path=%s, data=0x%llX = %lld\n",
				path, regs.rsi, regs.rax);
			if (regs.rax == 0) {
				cpu.machine().copy_to_guest(regs.rsi, &vstat, sizeof(vstat));
			}
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		5, [] (vCPU& cpu) { // FSTAT
			auto& inst = *cpu.machine().get_userdata<MachineInstance>();
			auto& regs = cpu.registers();

			int fd = inst.m_fd.translate(regs.rdi);
			struct stat vstat;
			regs.rax = fstat(fd, &vstat);
			if (regs.rax == 0) {
				cpu.machine().copy_to_guest(regs.rsi, &vstat, sizeof(vstat));
			}
			SYSPRINT("FSTAT to vfd=%lld, fd=%d, data=0x%llX = %lld\n",
				regs.rdi, fd, regs.rsi, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		8, [] (vCPU& cpu) { // LSEEK
			auto& inst = *cpu.machine().get_userdata<MachineInstance>();
			auto& regs = cpu.registers();
			const int fd = inst.m_fd.translate(regs.rdi);
			regs.rax = lseek(fd, regs.rsi, regs.rdx);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		48, [] (vCPU& cpu) { // SHUTDOWN
			auto& inst = *cpu.machine().get_userdata<MachineInstance>();
			auto& regs = cpu.registers();

			const int fd = inst.m_fd.translate(regs.rdi);
			regs.rax = shutdown(fd, regs.rsi);
			SYSPRINT("SHUTDOWN(fd=%lld) = %lld\n",
				regs.rdi, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		79, [](vCPU& cpu) { // GETCWD
			auto& regs = cpu.registers();

			const char fakepath[] = "/";
			if (sizeof(fakepath) <= regs.rsi) {
				cpu.machine().copy_to_guest(regs.rdi, fakepath, sizeof(fakepath));
				regs.rax = regs.rdi;
			} else {
				regs.rax = 0;
			}
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		217, [](vCPU& cpu) { // GETDENTS64
			auto& inst = *cpu.machine().get_userdata<MachineInstance>();
			auto& regs = cpu.registers();

			int fd = inst.m_fd.translate(regs.rdi);

			char buffer[2048];
			regs.rax = syscall(SYS_getdents64, fd, buffer, sizeof(buffer));
			if (regs.rax > 0)
			{
				cpu.machine().copy_to_guest(regs.rsi, buffer, regs.rax);
			}
			SYSPRINT("GETDENTS64 to vfd=%lld, fd=%d, data=0x%llX = %lld\n",
				regs.rdi, fd, regs.rsi, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		257, [] (vCPU& cpu) { // OPENAT
			auto& inst = *cpu.machine().get_userdata<MachineInstance>();
			auto& regs = cpu.registers();

			const auto vpath = regs.rsi;
			const int  flags = regs.rdx;

			char path[PATH_MAX];
			cpu.machine().copy_from_guest(path, vpath, sizeof(path));
			bool write_flags = (flags & (O_WRONLY | O_RDWR)) != 0x0;
			if (!write_flags)
			{
				try {
					inst.sanitize_path(path, sizeof(path));

					int fd = openat(AT_FDCWD, path, flags);
					SYSPRINT("OPENAT fd=%lld path=%s = %d\n",
						regs.rdi, path, fd);

					if (fd > 0) {
						inst.m_fd.manage(fd, 0x1000 + fd);
						regs.rax = 0x1000 + fd;
						cpu.set_registers(regs);
						return;
					} else {
						regs.rax = -1;
					}
				} catch (...) {
					regs.rax = -1;
				}
			}
			if (write_flags || regs.rax == (__u64)-1)
			{
				try {
					inst.sanitize_file(path, sizeof(path));

					const auto& state_file = inst.tenant().config.allowed_file;
					int fd = openat(AT_FDCWD, state_file.c_str(), flags, S_IWUSR | S_IRUSR);
					SYSPRINT("OPENAT where=%lld path=%s flags=%X = fd %d\n",
						regs.rdi, path, flags, fd);

					if (fd > 0) {
						inst.m_fd.manage(fd, 0x1000 + fd);
						regs.rax = 0x1000 + fd;
					} else {
						regs.rax = -1;
					}
				} catch (...) {
					regs.rax = -1;
				}
			}
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		262, [] (vCPU& cpu) { // NEWFSTATAT
			auto& inst = *cpu.machine().get_userdata<MachineInstance>();
			auto& regs = cpu.registers();
			const auto vpath  = regs.rsi;
			const auto buffer = regs.rdx;
			const int  flags  = regs.r8;
			long fd = AT_FDCWD;

			char path[PATH_MAX];
			cpu.machine().copy_from_guest(path, vpath, sizeof(path));

			try {
				inst.sanitize_path(path, sizeof(path));

				// Translate from vfd when fd != CWD
				if ((long)regs.rdi != fd) fd = inst.m_fd.translate(regs.rdi);

				struct stat64 vstat;
				regs.rax = fstatat64(fd, path, &vstat, flags);
				if (regs.rax == 0) {
					cpu.machine().copy_to_guest(buffer, &vstat, sizeof(vstat));
				}
			} catch (...) {
				printf("ERROR\n");
				regs.rax = -1;
			}

			SYSPRINT("NEWFSTATAT to vfd=%lld, fd=%ld, path=%s, data=0x%llX, flags=0x%X = %lld\n",
				regs.rdi, fd, path, buffer, flags, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		332, [] (vCPU& cpu) { // STATX
			auto& inst = *cpu.machine().get_userdata<MachineInstance>();
			auto& regs = cpu.registers();
			long fd = AT_FDCWD; // rdi
			const auto vpath  = regs.rsi;
			const auto flags  = regs.rdx;
			const auto mask   = regs.r10;
			const auto buffer = regs.r8;

			char path[PATH_MAX];
			cpu.machine().copy_from_guest(path, vpath, sizeof(path));

			try {
				inst.sanitize_path(path, sizeof(path));

				// Translate from vfd when fd != AT_FDCWD
				if ((long)regs.rdi != AT_FDCWD)
					fd = inst.m_fd.translate(regs.rdi);

				struct statx vstat;
				regs.rax = statx(fd, path, flags, mask, &vstat);
				if (regs.rax == 0) {
					cpu.machine().copy_to_guest(buffer, &vstat, sizeof(vstat));
				}
			} catch (...) {
				regs.rax = -1;
			}

			SYSPRINT("STATX to vfd=%lld, fd=%ld, path=%s, data=0x%llX, flags=0x%llX, mask=0x%llX = %lld\n",
				regs.rdi, fd, path, buffer, flags, mask, regs.rax);
			cpu.set_registers(regs);
		});
}

} // kvm
