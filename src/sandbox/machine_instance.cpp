#include "machine_instance.hpp"
#include "program_instance.hpp"
#include "scoped_duration.hpp"
#include "settings.hpp"
#include "tenant_instance.hpp"
#include "timing.hpp"
#include <cstdarg>
#include <tinykvm/util/elf.h>
extern "C" int close(int);
extern void kvm_handle_warmup(kvm::MachineInstance& inst, const kvm::TenantGroup::Warmup&);

namespace kvm {
static std::vector<uint8_t> ld_linux_x86_64_so;
extern std::vector<uint8_t> file_loader(const std::string &);

void MachineInstance::kvm_initialize()
{
	tinykvm::Machine::init();
	setup_syscall_interface();

	// Load the dynamic linker
	ld_linux_x86_64_so = file_loader("/lib64/ld-linux-x86-64.so.2");
}

static uint64_t detect_gigapage_from(const std::vector<uint8_t>& binary)
{
	if (binary.size() < 128U)
		throw std::runtime_error("Invalid ELF program (binary too small)");
	auto* elf = (Elf64_Ehdr *)binary.data();

	auto start_address_gigapage = elf->e_entry >> 30U;
	if (start_address_gigapage >= 64)
		throw std::runtime_error("Invalid ELF start address (adress was > 64GB)");

	return start_address_gigapage << 30U;
}

static const std::vector<uint8_t>& select_main_binary(const std::vector<uint8_t>& program_binary)
{
	const tinykvm::DynamicElf dyn_elf = tinykvm::is_dynamic_elf(
		std::string_view{(const char *)program_binary.data(), program_binary.size()});
	if (dyn_elf.has_interpreter()) {
		// Add the dynamic linker as first argument
		return ld_linux_x86_64_so;
	}
	return program_binary;
}

MachineInstance::MachineInstance(
	const std::vector<uint8_t>& binary,
	const TenantInstance* ten, ProgramInstance* inst,
	bool storage, bool debug)
	: m_machine(select_main_binary(binary), tinykvm::MachineOptions{
		.max_mem = ten->config.max_address(),
		.max_cow_mem = 0UL,
		.dylink_address_hint = ten->config.group.dylink_address_hint,
		.heap_address_hint = ten->config.group.heap_address_hint,
		.vmem_base_address = detect_gigapage_from(binary),
		.remappings {ten->config.group.vmem_remappings},
		.verbose_loader = ten->config.group.verbose,
		.hugepages = ten->config.hugepages(),
		.transparent_hugepages = ten->config.group.transparent_hugepages,
		.master_direct_memory_writes = true,
		.split_hugepages = false,
		.relocate_fixed_mmap = ten->config.group.relocate_fixed_mmap,
		.executable_heap = ten->config.group.vmem_heap_executable,
		.hugepages_arena_size = ten->config.group.hugepage_arena_size,
	  }),
	  m_tenant(ten), m_inst(inst),
	  m_original_binary(binary),
	  m_request_id(0),
	  m_is_debug(debug),
	  m_is_storage(storage),
	  m_regex     {ten->config.max_regex(), "Regex handles"}
{
	// By default programs start out ephemeral, but it can be overridden
	this->m_is_ephemeral = ten->config.group.ephemeral;
	machine().set_userdata<MachineInstance> (this);
	machine().set_printer(get_printer());
	machine().set_verbose_system_calls(
		ten->config.group.verbose_syscalls);
	machine().set_verbose_mmap_syscalls(
		ten->config.group.verbose_syscalls);
	machine().set_verbose_thread_syscalls(
		ten->config.group.verbose_syscalls);
	// Set the current working directory
	machine().fds().set_current_working_directory(
		ten->config.group.current_working_directory);
	// Add all the allowed paths to the VMs file descriptor sub-system
	for (auto& path : ten->config.group.allowed_paths) {
		if (path.prefix && path.writable) {
			// Add as a prefix path
			machine().fds().add_writable_prefix(path.virtual_path);
			continue;
		}
		machine().fds().add_readonly_file(path.virtual_path);
	}
	// Add a single writable file simply called 'state'
	machine().fds().set_open_writable_callback(
	[&] (std::string& path) -> bool {
		if (path == "state") {
			// Rewrite the path to the allowed file
			path = tenant().config.allowed_file;
			return true;
		}
		for (auto& tpath : tenant().config.group.allowed_paths) {
			if (tpath.virtual_path == path && tpath.writable) {
				// Rewrite the path to the allowed file
				path = tpath.real_path;
				return true;
			}
		}
		return false;
	});
	machine().fds().set_open_readable_callback(
	[&] (std::string& path) -> bool {
		if (path == "state") {
			// Rewrite the path to the allowed file
			path = tenant().config.allowed_file;
			return true;
		}
		// Rewrite the path if it's in the rewrite paths
		// It's also allowed to be opened (read-only)
		auto it = tenant().config.group.rewrite_path_indices.find(path);
		if (it != tenant().config.group.rewrite_path_indices.end()) {
			const size_t index = it->second;
			// Rewrite the path to the allowed file
			path = tenant().config.group.allowed_paths.at(index).real_path;
			return true;
		}
		return false;
	});
	machine().fds().set_connect_socket_callback(
	[&] (int fd, struct sockaddr_storage& addr) -> bool {
		(void)fd;
		(void)addr;
		return true;
	});
	machine().fds().set_resolve_symlink_callback(
	[&] (std::string& path) -> bool {
		for (auto& tpath : tenant().config.group.allowed_paths) {
			if (tpath.virtual_path == path && tpath.symlink) {
				// Rewrite the path to where the symlink points
				path = tpath.real_path;
				return true;
			}
		}
		return false;
	});
	machine().set_mmap_callback(
	[&] (tinykvm::vCPU& cpu, uint64_t addr, size_t size,
			int flags, int prot, int fd, uint64_t offset) {
		(void)cpu;
		if (false && (prot & 4) != 0) {
			printf("Executable range: 0x%lX -> 0x%lX (size: %zu) fd: %d offset: %lu\n",
				addr, addr + size, size, fd, offset);
			// Discover 2MB alignment that also covers at least a 2MB range
			const uint64_t HUGE_ALIGN = 0x200000;
			const uint64_t HUGE_MASK = HUGE_ALIGN - 1;
			// Well-aligned start and end addresses for 2MB hugepages
			const uint64_t huge_addr_begin = (addr + HUGE_MASK) & ~HUGE_MASK;
			const uint64_t huge_addr_end   = (addr + size) & ~HUGE_MASK;
			if (huge_addr_begin >= huge_addr_end) {
				// The range is too small or unaligned to contain an aligned 2MB page
				return;
			}
			if (huge_addr_end - huge_addr_begin >= HUGE_ALIGN) {
				// We have a 2MB aligned range
				printf("2MB aligned range: 0x%lX -> 0x%lX\n", huge_addr_begin, huge_addr_end);
				printf("There are %zu 2MB pages\n",
					(huge_addr_end - huge_addr_begin) / HUGE_ALIGN);
			}
		}
	});
}
void MachineInstance::initialize()
{
	try {
		/* Some run-times are quite buggy. Zig makes a calculation on
		   RSP and the loadable segments in order to find img_base.
		   This calculation results in a panic when the stack is
		   below the program and heap. Workaround: Move above.
		   TOOD: Make sure we have room for it, using memory limits. */
		const auto stack = machine().mmap_allocate(MAIN_STACK_SIZE);
		const auto stack_end = stack + MAIN_STACK_SIZE;
		machine().set_stack_address(stack_end);
		//printf("Heap BRK: 0x%lX -> 0x%lX\n", machine().heap_address(), machine().heap_address() + tinykvm::Machine::BRK_MAX);
		//printf("Stack: 0x%lX -> 0x%lX\n", stack, stack + MAIN_STACK_SIZE);

		// This can probably be solved later, but for now they are incompatible
		if (shared_memory_size() > 0 && !tenant().config.group.vmem_remappings.empty())
		{
			throw std::runtime_error("Shared memory is currently incompatible with vmem remappings");
		}
		// Global shared memory boundary
		const uint64_t shm_boundary = shared_memory_boundary();
		//printf("Shared memory boundary: 0x%lX Max addr: 0x%lX\n",
		//	shm_boundary, machine().max_address());

		// Use constrained working memory
		machine().prepare_copy_on_write(tenant().config.max_main_memory(), shm_boundary);

		const tinykvm::DynamicElf dyn_elf =
			tinykvm::is_dynamic_elf(std::string_view{
				(const char *)m_original_binary.data(),
				m_original_binary.size()});
		this->m_binary_type = dyn_elf.has_interpreter() ?
			BinaryType::Dynamic :
			(dyn_elf.is_dynamic ? BinaryType::StaticPie :
			 BinaryType::Static);

		// Main arguments: 3x mandatory + N configurable
		std::vector<std::string> args;
		args.reserve(5);
		if (dyn_elf.has_interpreter()) {
			// The real program path (which must be guest-readable)
			/// XXX: TODO: Use /proc/self/exe instead of this?
			m_machine.fds().add_readonly_file(tenant().config.filename);
			args.push_back("/lib64/ld-linux-x86-64.so.2");
			args.push_back(tenant().config.filename);
		} else {
			// Fake filename for the program using the name of the tenant
			args.push_back(name());
		}
		std::shared_ptr<std::vector<std::string>> main_arguments =
			std::atomic_load(&tenant().config.group.main_arguments);
		if (main_arguments != nullptr) {
			args.insert(args.end(), main_arguments->begin(), main_arguments->end());
		}

		std::vector<std::string> envp = tenant().config.environ();
		envp.push_back("KVM_NAME=" + name());
		envp.push_back("KVM_GROUP=" + group());
		envp.push_back("KVM_TYPE=" + std::string(is_storage() ? "storage" : "request"));
		envp.push_back("KVM_STATE=" + TenantConfig::guest_state_file);
		envp.push_back("KVM_DEBUG=" + std::to_string(is_debug()));

		// Build stack, auxvec, envp and program arguments
		machine().setup_linux(args, envp);

		// If verbose pagetables, print them just before running
		if (tenant().config.group.verbose_pagetable) {
			machine().print_pagetables();
		}

		if (this->is_debug()) {
			this->open_debugger(2159, 120.0f);
		}

		// Continue/resume or run through main()
		machine().run( tenant().config.max_boot_time() );

		// Make sure the program is waiting for requests
		if (!is_waiting_for_requests()) {
			throw std::runtime_error("Program did not wait for requests");
		}

		// We don't know if this is a resumable VM, but if it is we must skip
		// over the OUT instruction that was executed in the backend call.
		// We can do this regardless of whether it is a resumable VM or not.
		// This will also help make faulting VMs return back to the correct
		// state when they are being reset.
		auto& regs = machine().registers();
		regs.rip += 2;
		machine().set_registers(regs);

		// Only request VMs need the copy-on-write mechanism enabled
		if (!is_storage())
		{
			// Perform warmup, if requested
			if (m_tenant->config.group.warmup) {
				this->warmup();
			}

			// Make forkable (with *NO* working memory)
			machine().prepare_copy_on_write(0UL, shm_boundary);
		}

		// Set new vmcall stack base lower than current RSP, in
		// order to avoid trampling stack-allocated things in main.
		auto rsp = machine().registers().rsp;
		if (rsp >= stack && rsp < stack_end) {
			rsp = (rsp - 128UL) & ~0xFLL; // Avoid red-zone if main is leaf
			machine().set_stack_address(rsp);
		}
	}
	catch (const tinykvm::MachineException& me)
	{
		fprintf(stderr,
			"Machine not initialized properly: %s\n", name().c_str());
		fprintf(stderr,
			"Error: %s Data: 0x%#lX\n", me.what(), me.data());
		this->print_backtrace();
		if (this->tenant().config.group.remote_debug_on_exception) {
			this->open_debugger(2159, 120.0f);
		}
		throw; /* IMPORTANT: Re-throw */
	}
	catch (const std::exception& e)
	{
		fprintf(stderr,
			"Machine not initialized properly: %s\n", name().c_str());
		fprintf(stderr,
			"Error: %s\n", e.what());
		this->print_backtrace();
		if (this->tenant().config.group.remote_debug_on_exception) {
			this->open_debugger(2159, 120.0f);
		}
		throw; /* IMPORTANT: Re-throw */
	}
}

void MachineInstance::warmup()
{
	if (!tenant().config.group.warmup)
		throw std::runtime_error("Warmup has not been enabled");
	auto& w = *tenant().config.group.warmup;
	if (w.url.empty())
		throw std::runtime_error("Warmup URL is empty");
	if (w.method.empty())
		throw std::runtime_error("Warmup method is empty");

	this->m_is_warming_up = true;
	try {
		kvm_handle_warmup(*this, w);
	} catch (const std::exception& e) {
		fprintf(stderr, "Warmup failed: %s\n", e.what());
	}
	this->m_is_warming_up = false;
}

MachineInstance::MachineInstance(
	unsigned reqid,
	const MachineInstance& source, const TenantInstance* ten, ProgramInstance* inst)
	: m_machine(source.machine(), tinykvm::MachineOptions{
		.max_mem = ten->config.max_main_memory(),
		.max_cow_mem = ten->config.max_req_memory(),
		.reset_free_work_mem = ten->config.limit_req_memory(),
		.split_hugepages = ten->config.group.split_hugepages,
		.relocate_fixed_mmap = ten->config.group.relocate_fixed_mmap,
		.hugepages_arena_size = ten->config.group.hugepage_requests_arena,
	  }),
	  m_tenant(ten), m_inst(inst),
	  m_original_binary(source.m_original_binary),
	  m_request_id(reqid),
	  m_is_debug(source.is_debug()),
	  m_is_storage(false),
	  m_is_ephemeral(source.is_ephemeral()),
	  m_waiting_for_requests(true), // If we got this far, we are waiting...
	  m_binary_type(source.binary_type()),
	  m_sighandler{source.m_sighandler},
	  m_regex     {ten->config.max_regex(), "Regex handles"}
{
#ifdef ENABLE_TIMING
	TIMING_LOCATION(t0);
#endif
	machine().set_userdata<MachineInstance> (this);
	machine().set_printer(get_printer());
	/* vCPU request id */
	machine().cpu().set_vcpu_table_at(1, reqid);
	/* Allow open read-only files */
	for (auto& path : ten->config.group.allowed_paths) {
		if (path.writable) {
			continue;
		}
		machine().fds().add_readonly_file(path.virtual_path);
	}
	/* Allow duplicating read-only FDs from the source */
	machine().fds().set_find_readonly_master_vm_fd_callback(
		[&] (int vfd) -> std::optional<const tinykvm::FileDescriptors::Entry*> {
			return source.machine().fds().entry_for_vfd(vfd);
		});
	machine().fds().set_connect_socket_callback(
	[&] (int fd, struct sockaddr_storage& addr) -> bool {
		(void)fd;
		(void)addr;
		return true;
	});
	machine().fds().set_verbose(ten->config.group.verbose);
	machine().set_verbose_mmap_syscalls(ten->config.group.verbose_syscalls);
	machine().set_verbose_system_calls(ten->config.group.verbose_syscalls);
	machine().set_verbose_thread_syscalls(ten->config.group.verbose_syscalls);
	/* Load the compiled regexes of the source */
	m_regex.reset_and_loan(source.m_regex);
#ifdef ENABLE_TIMING
	TIMING_LOCATION(t1);
	printf("Total time in MachineInstance constr body: %ldns\n", nanodiff(t0, t1));
#endif
}

void MachineInstance::tail_reset()
{
	/* Free any owned regex pointers */
	m_regex.foreach_owned(
		[] (auto& entry) {
			//..._free(&entry.item);
		});
	if (this->is_debug()) {
		//this->stop_debugger();
	}
}
void MachineInstance::reset_to(MachineInstance& source)
{
	/* If it crashed, or reset is always needed, then reset now. */
	const bool reset_needed = this->m_reset_needed || this->m_is_ephemeral;

	/* We only reset ephemeral VMs. */
	if (reset_needed) {
		stats().resets ++;
		ScopedDuration cputime(this->stats().vm_reset_time);

		machine().reset_to(source.machine(), {
			.max_mem = tenant().config.max_main_memory(),
			.max_cow_mem = tenant().config.max_req_memory(),
			.reset_free_work_mem = tenant().config.limit_req_memory(),
			.reset_copy_all_registers = true,
			// When m_reset_needed is true, we want to do a full reset
			.reset_keep_all_work_memory = !this->m_reset_needed && tenant().config.group.ephemeral_keep_working_memory,
		});
		this->m_waiting_for_requests = source.m_waiting_for_requests;
		/* The POST memory area is gone. */
		this->m_post_size = 0;
		/* The ephemeral backend_inputs "stack" area is gone. */
		this->m_inputs_allocation = 0;

		m_sighandler = source.m_sighandler;

		/* Load the compiled regexes of the source */
		m_regex.reset_and_loan(source.m_regex);
		/* XXX: Todo: reset more stuff */
		this->m_reset_needed = false;
	}
}

MachineInstance::~MachineInstance()
{
	this->tail_reset();
}

void MachineInstance::wait_for_requests_paused()
{
	this->m_waiting_for_requests = true;
	//printf("*** Waiting for requests in paused state\n");
}

void MachineInstance::copy_to(uint64_t addr, const void* src, size_t len, bool zeroes)
{
	machine().copy_to_guest(addr, src, len, zeroes);
}

bool MachineInstance::allows_debugging() const noexcept
{
	return tenant().config.group.allow_debug;
}
float MachineInstance::max_req_time() const noexcept {
	return tenant().config.max_req_time(is_debug());
}
const std::string& MachineInstance::name() const noexcept {
	return tenant().config.name;
}
const std::string& MachineInstance::group() const noexcept {
	return tenant().config.group.name;
}

std::string MachineInstance::binary_type_string() const noexcept {
	switch (m_binary_type) {
	case BinaryType::Static:     return "static";
	case BinaryType::StaticPie:  return "static-pie";
	case BinaryType::Dynamic:    return "dynamic";
	default:                     return "unknown";
	}
}

uint64_t MachineInstance::shared_memory_boundary() const noexcept
{
	if (shared_memory_size() > 0)
		/* For VMs < 4GB this works well enough. */
		return tenant().config.group.max_address_space - shared_memory_size();
	else
		return ~uint64_t(0);
}
uint64_t MachineInstance::shared_memory_size() const noexcept
{
	return tenant().config.group.shared_memory;
}

void MachineInstance::print_backtrace()
{
	const auto regs = machine().registers();
	machine().print_registers();

	uint64_t rip = regs.rip;
	if (rip >= 0x2000 && rip < 0x3000) {
		/* Exception handler */
		try {
			machine().unsafe_copy_from_guest(&rip, regs.rsp, 8);
			// Unwinding the stack is too hard :(
			// But this is the real RSP:
			//machine().unsafe_copy_from_guest(&rsp, regs.rsp + 24, 8);
		} catch (...) {}
	}

	char buffer[4096];
	int len = snprintf(buffer, sizeof(buffer),
		"[0] 0x%8lX   %s\n",
		rip, machine().resolve(rip).c_str());
	if (len > 0) {
		machine().print(buffer, len);
	}
}

uint64_t MachineInstance::allocate_post_data(size_t bytes)
{
	/* Simple mremap scheme. */
	if (this->m_post_size < bytes)
	{
		if (this->m_post_size > 0)
			machine().mmap_unmap(m_post_data, m_post_size);

		this->m_post_data = machine().mmap_allocate(bytes);
		this->m_post_size = bytes;
	}
	return this->m_post_data;
}

void MachineInstance::logf(const char *fmt, ...) const
{
	char buffer[2048];
	va_list va;
	va_start(va, fmt);
	/* NOTE: vsnprintf has an insane return value. */
	const int len = vsnprintf(buffer, sizeof(buffer), fmt, va);
	va_end(va);
	if (len >= 0 && (size_t)len < sizeof(buffer)) {
		this->logprint(std::string_view{buffer, (size_t)len}, false);
	} else {
		throw std::runtime_error("Printf buffer exceeded");
	}
}
void MachineInstance::print(std::string_view text) const
{
	if (text.empty())
		return;

	if (this->m_last_newline) {
		printf(">>> [%s] %.*s", name().c_str(), (int)text.size(), text.begin());
	} else {
		printf("%.*s", (int)text.size(), text.begin());
	}
	this->m_last_newline = (text.back() == '\n');
}
void MachineInstance::logprint(std::string_view text, bool says) const
{
	/* Simultaneous logging is not possible with SMP. */
	const bool smp = machine().smp_active();
	if (!smp) {
		if (says) {
			tenant().logf(
				"%s says: %.*s", name().c_str(), (int)text.size(), text.begin());
		} else {
			tenant().logf(
				"%.*s", (int)text.size(), text.begin());
		}
		/* Print to stdout as well */
		if (tenant().config.print_stdout()) {
			this->print(text);
		}
	}
}
tinykvm::Machine::printer_func MachineInstance::get_printer() const
{
	/* NOTE: Guests will "always" end with newlines */
	return [this] (const char* buffer, size_t len) {
		/* Avoid wrap-around and empty log */
		if (len == 0 || len > 1UL << 20) {
			if (len > 0)
				this->print("Invalid log buffer length");
			return;
		}
		/* Logging with $PROGRAM says: ... */
		this->logprint(std::string_view(buffer, len), true);
	};
}

} // kvm
