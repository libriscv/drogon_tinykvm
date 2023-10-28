#include "machine_instance.hpp"
#include "program_instance.hpp"
#include "scoped_duration.hpp"
#include "settings.hpp"
#include "../settings.hpp"
#include "tenant_instance.hpp"
#include "timing.hpp"
#include <cstdarg>
#include <tinykvm/util/elf.h>
extern "C" int close(int);
extern void kvm_handle_warmup(kvm::MachineInstance& inst, const kvm::TenantGroup::Warmup&);

namespace kvm {
static BinaryStorage ld_linux_x86_64_so;
extern std::vector<uint8_t> file_loader(const std::string &);

void MachineInstance::kvm_initialize()
{
	tinykvm::Machine::init();
	setup_syscall_interface();

	// Load the dynamic linker
	ld_linux_x86_64_so = file_loader("/lib64/ld-linux-x86-64.so.2");
}

static bool is_interpreted_binary(const BinaryStorage& binary)
{
	if (binary.size() < 128U)
		throw std::runtime_error("Invalid ELF program (binary too small)");

	const tinykvm::DynamicElf dyn_elf = tinykvm::is_dynamic_elf(
		std::string_view{(const char *)binary.data(), binary.size()});
	return dyn_elf.has_interpreter();
}
static uint64_t detect_gigapage_from(const BinaryStorage& binary, uint64_t dylink_address_hint)
{
	if (dylink_address_hint >= (1ULL << 30U)) {
		const tinykvm::DynamicElf dyn_elf = tinykvm::is_dynamic_elf(
			std::string_view{(const char *)binary.data(), binary.size()});
		// We can only use a dylink address hint if the binary is dynamic
		if (dyn_elf.is_dynamic)
			return (dylink_address_hint >> 30U) << 30U; // Aligned to gigapage
	}

	if (binary.size() < 128U)
		throw std::runtime_error("Invalid ELF program (binary too small)");
	auto* elf = (Elf64_Ehdr *)binary.data();

	auto start_address_gigapage = elf->e_entry >> 30U;
	if (start_address_gigapage >= 64)
		throw std::runtime_error("Invalid ELF start address (address was > 64GB)");

	return start_address_gigapage << 30U;
}

static std::span<const uint8_t> select_main_binary(const BinaryStorage& program_binary)
{
	if (is_interpreted_binary(program_binary)) {
		// If the program is interpreted, we need to use the dynamic linker
		// as the main binary.
		if (ld_linux_x86_64_so.empty()) {
			throw std::runtime_error("Dynamic linker not loaded");
		}
		return ld_linux_x86_64_so.binary();
	}
	return program_binary.binary();
}

static std::pair<uint64_t, uint64_t> get_urandom_state()
{
	FILE* urandom = fopen("/dev/urandom", "rb");
	if (!urandom) {
		throw std::runtime_error("Failed to open /dev/urandom");
	}

	std::pair<uint64_t, uint64_t> state;
	if (fread(&state, sizeof(state), 1, urandom) != 1) {
		fclose(urandom);
		throw std::runtime_error("Failed to read /dev/urandom");
	}
	fclose(urandom);
	return state;
}

static uint64_t dylink_address(const TenantInstance* ten, bool storage)
{
	if (storage) {
		return ten->config.group.storage_dylink_address_hint;
	}
	return ten->config.group.dylink_address_hint;
}

MachineInstance::MachineInstance(
	const BinaryStorage& binary,
	const TenantInstance* ten, ProgramInstance* inst,
	bool storage, bool debug)
	: m_machine(select_main_binary(binary), tinykvm::MachineOptions{
		.max_mem = storage ? ten->config.max_storage_memory() : ten->config.max_address(),
		.max_cow_mem = 0UL,
		.dylink_address_hint = dylink_address(ten, storage),
		.heap_address_hint = storage ? 0 : ten->config.group.heap_address_hint,
		.vmem_base_address = detect_gigapage_from(binary, dylink_address(ten, storage)),
		.remappings {storage ? ten->config.group.storage_remappings : ten->config.group.vmem_remappings},
		.verbose_loader = ten->config.group.verbose,
		.hugepages = ten->config.hugepages(),
		.transparent_hugepages = ten->config.group.transparent_hugepages,
		.master_direct_memory_writes = true,
		.split_hugepages = false,
		.split_all_hugepages_during_loading = false,
		.executable_heap = ten->config.group.vmem_heap_executable || is_interpreted_binary(binary),
		.mmap_backed_files = storage || ten->config.group.cold_start_file.empty(),
		.snapshot_file = storage ? "" : ten->config.group.cold_start_file,
		.hugepages_arena_size = ten->config.group.hugepage_arena_size,
	  }),
	  m_tenant(ten), m_inst(inst),
	  m_original_binary(binary),
	  m_request_id(0),
	  m_is_debug(debug),
	  m_is_storage(storage),
	  m_prng(get_urandom_state())
{
	if (ten->config.group.profiling_interval > 0) {
		machine().set_profiling(true);
	}
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
	machine().fds().set_preempt_epoll_wait(true);
	// Set the current working directory
	machine().fds().set_current_working_directory(
		ten->config.group.current_working_directory);
	// Add all the allowed paths to the VMs file descriptor sub-system
	machine().fds().set_open_readable_callback(
	[this] (std::string& path) -> bool {
		// Check if the path is allowed
		for (auto& tpath : tenant().config.group.allowed_paths) {
			if (!tpath.prefix && tpath.virtual_path == path) {
				// Rewrite the path to the allowed file
				path = tpath.real_path;
				return true;
			} else if (tpath.prefix && path.find(tpath.virtual_path) == 0) {
				// If the path starts with the prefix, rewrite it
				path = tpath.real_path + path.substr(tpath.virtual_path.size());
				return true;
			}
		}
		if (path == "./libdrogon.so") {
			// Special case for drogon library
			path = g_settings.drogon_library_path;
			return true;
		}
		else if (path == "state") {
			// Rewrite the path to the allowed file
			path = tenant().config.allowed_file;
			return true;
		}
		return false;
	});
	machine().fds().set_open_writable_callback(
	[&] (std::string& path) -> bool {
		for (auto& tpath : tenant().config.group.allowed_paths) {
			if (!tpath.prefix && tpath.writable && tpath.virtual_path == path) {
				// Rewrite the path to the allowed file
				path = tpath.real_path;
				return true;
			} else if (tpath.prefix && tpath.writable && path.find(tpath.virtual_path) == 0) {
				// If the path starts with the prefix, rewrite it
				path = tpath.real_path + path.substr(tpath.virtual_path.size());
				return true;
			}
		}
		if (path == "state") {
			// Rewrite the path to the allowed file
			path = tenant().config.allowed_file;
			return true;
		}
		return false;
	});
	machine().fds().set_connect_socket_callback(
	[] (int fd, struct sockaddr_storage& addr) -> bool {
		(void)fd;
		(void)addr;
		return true;
	});
	machine().fds().bind_socket_callback =
	[] (int, struct sockaddr_storage&) -> bool {
		return false;
	};
	machine().fds().listening_socket_callback =
	[] (int vfd, int fd) -> bool {
		(void)vfd;
		(void)fd;
		return false;
	};
	machine().fds().set_resolve_symlink_callback(
	[&] (std::string& path) -> bool {
		for (auto& tpath : tenant().config.group.allowed_paths) {
			if (tpath.virtual_path == path && tpath.symlink) {
				// Rewrite the path to where the symlink points
				path = tpath.real_path;
				return true;
			}
		}
		// Allow reading symlink to the program binary (when filename is present)
		if (path == "/proc/self/exe" && !tenant().config.request_program_filename().empty()) {
			path = tenant().config.request_program_filename();
			return true;
		}
		return false;
	});
}
double MachineInstance::initialize()
{
	double warmup_time = 0.0;
	try {
		// This can probably be solved later, but for now they are incompatible
		if (shared_memory_size() > 0 && !tenant().config.group.vmem_remappings.empty())
		{
			throw std::runtime_error("Shared memory is currently incompatible with vmem remappings");
		}
		// Check if fast cold start file is used, and if so load the state
		if (!is_storage() && machine().has_snapshot_state()) {
			printf("Loaded cold start state from: %s\n",
				tenant().config.group.cold_start_file.c_str());
			// Load the programs state as well
			program().load_state(machine().get_snapshot_state_user_area());
			if (tenant().config.group.verbose_pagetable) {
				machine().print_pagetables();
			}
			// Set as waiting for requests
			this->wait_for_requests();
			return 0.0f;
		}

		// Global shared memory boundary
		const uint64_t shm_boundary = shared_memory_boundary();
		//printf("Shared memory boundary: 0x%lX Max addr: 0x%lX\n",
		//	shm_boundary, machine().max_address());

		// Use constrained working memory
		uint64_t max_main_mem = tenant().config.max_main_memory();
		if (is_storage()) {
			max_main_mem = tenant().config.max_storage_memory();
		}
		machine().prepare_copy_on_write(max_main_mem, shm_boundary);

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
			args.push_back("/lib64/ld-linux-x86-64.so.2");
			args.push_back(tenant().config.filename);
		} else {
			// Fake filename for the program using the name of the tenant
			args.push_back(name());
		}
		std::shared_ptr<std::vector<std::string>> main_arguments = nullptr;
		if (is_storage()) {
			main_arguments = std::atomic_load(&tenant().config.group.storage_arguments);
			if (main_arguments == nullptr) {
				main_arguments = std::atomic_load(&tenant().config.group.main_arguments);
			}
		} else {
			main_arguments = std::atomic_load(&tenant().config.group.main_arguments);
		}
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

		if (g_settings.debug_boot) {
			tinykvm::Machine::RemoteGDBOptions opts;
			machine().print_remote_gdb_backtrace(
				tenant().config.request_program_filename(),
				opts);
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

		if (g_settings.debug_prefork) {
			machine().cpu().enter_usermode();
			tinykvm::Machine::RemoteGDBOptions opts;
			machine().print_remote_gdb_backtrace(
				tenant().config.request_program_filename(),
				opts);
		}

		// Only request VMs need the copy-on-write mechanism enabled
		if (!is_storage())
		{
			// Perform warmup, if requested
			if (m_tenant->config.group.warmup) {
				ScopedDuration d(warmup_time);
				this->warmup();
			}

			if (machine().has_remote()) {
				// If we have a remote connection, wait for it to be ready
				if (machine().is_remote_connected())
					throw std::runtime_error("Remote connection was open after warmup");
			}

			// Make forkable (with *NO* working memory)
			machine().prepare_copy_on_write(0UL, shm_boundary, true);
		}

		// Set new vmcall stack base lower than current RSP, in
		// order to avoid trampling stack-allocated things in main.
		auto rsp = machine().registers().rsp;
		rsp = (rsp - 128UL) & ~0xFLL; // Avoid red-zone if main is leaf
		machine().set_stack_address(rsp);


		// If fast cold start file is used, we should store the VM state as well
		if (!is_storage() && !tenant().config.group.cold_start_file.empty()) {
			machine().save_snapshot_state_now();
			// Save program state as well
			program().save_state(machine().get_snapshot_state_user_area());
			printf("Saved cold start state to '%s'\n",
				tenant().config.group.cold_start_file.c_str());
			this->m_store_state_on_reset = true;
		}

		return warmup_time;
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
	throw std::runtime_error("Machine not initialized properly");
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
		this->machine().print_registers();
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
		.hugepages_arena_size = ten->config.group.hugepage_requests_arena,
	  }),
	  m_tenant(ten), m_inst(inst),
	  m_original_binary(source.m_original_binary),
	  m_request_id(reqid),
	  m_is_debug(source.is_debug()),
	  m_is_storage(source.is_storage()),
	  m_is_ephemeral(source.is_ephemeral()),
	  m_waiting_for_requests(true), // If we got this far, we are waiting...
	  m_binary_type(source.binary_type()),
	  m_sighandler{source.m_sighandler},
	  m_prng(source.m_prng)
{
#ifdef ENABLE_TIMING
	TIMING_LOCATION(t0);
#endif
	if (ten->config.group.profiling_interval > 0) {
		machine().set_profiling(true);
	}
	machine().set_userdata<MachineInstance> (this);
	machine().set_printer(get_printer());
	if (!is_storage() && tenant().config.has_storage() && tenant().config.group.storage_1_to_1) {
		// Connect to the storage VM matching this request VM id
		auto& storage = m_inst->storage();
		if (ten->config.group.storage_perm_remote) {
			machine().permanent_remote_connect(storage.storage_vm.at(m_request_id)->machine());
		} else {
			machine().remote_connect(storage.storage_vm.at(m_request_id)->machine());
		}
	}
	machine().set_remote_allow_page_faults(true);
	/* vCPU request id */
	machine().cpu().set_vcpu_table_at(1, reqid);
	machine().set_verbose_system_calls(
		ten->config.group.verbose_syscalls);
	machine().set_verbose_mmap_syscalls(
		ten->config.group.verbose_syscalls);
	machine().set_verbose_thread_syscalls(
		ten->config.group.verbose_syscalls);
	/* Allow duplicating read-only FDs from the source */
	machine().fds().set_find_readonly_master_vm_fd_callback(
		[&] (int vfd) -> std::optional<const tinykvm::FileDescriptors::Entry*> {
			return source.machine().fds().entry_for_vfd(vfd);
		});
	/* Allow network connections in forked VMs */
	machine().fds().set_connect_socket_callback(
	[this] (int fd, struct sockaddr_storage& addr) -> bool {
		(void)fd;
		(void)addr;
		return true;
	});
	// Allow forks to read files from the allowed paths
	machine().fds().set_open_readable_callback(
	[this] (std::string& path) -> bool {
		// Check if the path is allowed
		for (auto& tpath : tenant().config.group.allowed_paths) {
			if (!tpath.prefix && tpath.virtual_path == path) {
				// Rewrite the path to the allowed file
				path = tpath.real_path;
				return true;
			} else if (tpath.prefix && path.find(tpath.virtual_path) == 0) {
				// If the path starts with the prefix, rewrite it
				path = tpath.real_path + path.substr(tpath.virtual_path.size());
				return true;
			}
		}
		if (path == "state") {
			// Rewrite the path to the allowed file
			path = tenant().config.allowed_file;
			return true;
		}
		return false;
	});
#ifdef ENABLE_TIMING
	TIMING_LOCATION(t1);
	printf("Total time in MachineInstance constr body: %ldns\n", nanodiff(t0, t1));
#endif
}

void MachineInstance::tail_reset()
{
	if (this->is_debug()) {
		//this->stop_debugger();
	}
}
bool MachineInstance::is_reset_needed() const
{
	return this->m_reset_needed || this->m_is_ephemeral;
}
void MachineInstance::reset_to(MachineInstance& source)
{
	/* If it crashed, or reset is always needed, then reset now. */
	const bool reset_needed = this->is_reset_needed();

	/* We only reset ephemeral VMs. */
	if (reset_needed) {
		ScopedDuration cputime(this->stats().vm_reset_time);
		auto& main_vm = *program().main_vm;
		if (main_vm.m_store_state_on_reset) {
			main_vm.m_store_state_on_reset = false;
			// Save the state before resetting
			auto populate_pages = machine().get_accessed_pages();
			main_vm.machine().save_snapshot_state_now(populate_pages);
			// Save program state as well
			program().save_state(main_vm.machine().get_snapshot_state_user_area());
			printf("Saved state on reset for program '%s' (%zu accessed pages)\n",
				tenant().config.name.c_str(), populate_pages.size());
			// Merge leaf pages into hugepages to reduce future page table walking
			const size_t merged = main_vm.machine().main_memory().merge_leaf_pages_into_hugepages();
			printf("Merged %zu leaf pages into hugepages for program '%s'\n",
				merged, tenant().config.name.c_str());
			if (tenant().config.group.verbose_pagetable) {
				machine().print_pagetables();
			}
		}

		const bool full_reset = machine().reset_to(source.machine(), {
			.max_mem = tenant().config.max_main_memory(),
			.max_cow_mem = tenant().config.max_req_memory(),
			.reset_free_work_mem = tenant().config.limit_req_memory(),
			.reset_copy_all_registers = true,
			// When m_reset_needed is true, we want to do a full reset
			.reset_keep_all_work_memory = !this->m_reset_needed && tenant().config.group.ephemeral_keep_working_memory,
		});
		stats().resets ++;
		if (full_reset) {
			stats().full_resets ++;
		}

		this->m_waiting_for_requests = source.m_waiting_for_requests;
		/* The POST memory area is gone. */
		this->m_post_size = 0;
		/* The ephemeral backend_inputs "stack" area is gone. */
		this->m_inputs_allocation = 0;

		m_sighandler = source.m_sighandler;

		/* XXX: Todo: reset more stuff? */
		this->m_reset_needed = false;
	}
	if (machine().is_profiling()) {
		const int samples = machine().profiling()->times.at(0).size();
		if (samples >= tenant().config.group.profiling_interval) {
			this->print_profiling();
			if (machine().has_remote()) {
				auto& remote_inst = *machine().remote().get_userdata<MachineInstance>();
				remote_inst.print_profiling();
				remote_inst.machine().profiling()->reset();
			}
			machine().profiling()->reset();
		}
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
	tinykvm::Machine::RemoteGDBOptions opts;
	opts.quit = true;
	machine().print_remote_gdb_backtrace(
		tenant().config.request_program_filename(),
		opts);

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

void MachineInstance::print_profiling() const
{
	if (!machine().is_profiling()) {
		return;
	}
	printf("Profiling results for VM %s (%s):\n",
		name().c_str(), is_storage() ? "storage" : "request");
	machine().profiling()->print();
}

} // kvm
