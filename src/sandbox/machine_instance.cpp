#include "machine_instance.hpp"
#include "program_instance.hpp"
#include "scoped_duration.hpp"
#include "settings.hpp"
#include "tenant_instance.hpp"
#include "timing.hpp"
#include <cstdarg>
#include <tinykvm/util/elf.h>
extern "C" int close(int);
extern void setup_kvm_system_calls();


namespace kvm {

void MachineInstance::kvm_initialize()
{
	tinykvm::Machine::init();
	setup_kvm_system_calls();
	setup_syscall_interface();
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

MachineInstance::MachineInstance(
	const std::vector<uint8_t>& binary,
	const TenantInstance* ten, ProgramInstance* inst,
	bool storage, bool debug)
	: m_machine(binary, tinykvm::MachineOptions{
		.max_mem = ten->config.max_address(),
		.max_cow_mem = 0UL,
		.vmem_base_address = detect_gigapage_from(binary),
		.remappings {ten->config.group.vmem_remappings},
		.hugepages = ten->config.hugepages(),
		.transparent_hugepages = ten->config.group.transparent_hugepages,
		.master_direct_memory_writes = true,
		.split_hugepages = false,
		.relocate_fixed_mmap = ten->config.group.relocate_fixed_mmap,
		.executable_heap = ten->config.group.vmem_heap_executable,
		.hugepages_arena_size = ten->config.group.hugepage_arena_size,
	  }),
	  m_tenant(ten), m_inst(inst),
	  m_is_debug(debug),
	  m_is_storage(storage),
	  m_print_stdout(ten->config.print_stdout()),
	  m_fd        {ten->config.max_fd(), "File descriptors"},
	  m_regex     {ten->config.max_regex(), "Regex handles"}
{
	// By default programs start out ephemeral, but it can be overridden
	this->m_is_ephemeral = ten->config.group.ephemeral;
	machine().set_userdata<MachineInstance> (this);
	machine().set_printer(get_vsl_printer());
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

		machine().prepare_copy_on_write(
			tenant().config.max_main_memory(), shm_boundary);

		// Main arguments: 3x mandatory + N configurable
		std::vector<std::string> args {
			name(), TenantConfig::guest_state_file, is_storage() ? "storage" : "request"
		};
		std::shared_ptr<std::vector<std::string>> main_arguments =
			std::atomic_load(&tenant().config.group.main_arguments);
		if (main_arguments != nullptr) {
			args.insert(args.end(), main_arguments->begin(), main_arguments->end());
		}

		// Build stack, auxvec, envp and program arguments
		machine().setup_linux(
			args,
			tenant().config.environ());

		// If verbose pagetables, print them just before running
		if (tenant().config.group.verbose_pagetable) {
			machine().print_pagetables();
		}

		if (this->is_debug()) {
			this->open_debugger(2159, 120.0f);
		}

		// Run through main()
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
	catch (const std::exception& e)
	{
		tenant().logf(
			"Machine not initialized properly: %s\n", name().c_str());
		tenant().logf(
			"Error: %s\n", e.what());
		throw; /* IMPORTANT: Re-throw */
	}
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
	  m_is_debug(source.is_debug()),
	  m_is_storage(false),
	  m_is_ephemeral(source.is_ephemeral()),
	  m_waiting_for_requests(true), // If we got this far, we are waiting...
	  m_sighandler{source.m_sighandler},
	  m_fd        {ten->config.max_fd(), "File descriptors"},
	  m_regex     {ten->config.max_regex(), "Regex handles"}
{
#ifdef ENABLE_TIMING
	TIMING_LOCATION(t0);
#endif
	machine().set_userdata<MachineInstance> (this);
	machine().set_printer(get_vsl_printer());
	/* vCPU request id */
	machine().cpu().set_vcpu_table_at(1, reqid);
	/* Load the fds of the source */
	m_fd.reset_and_loan(source.m_fd);
	/* Load the compiled regexes of the source */
	m_regex.reset_and_loan(source.m_regex);
#ifdef ENABLE_TIMING
	TIMING_LOCATION(t1);
	printf("Total time in MachineInstance constr body: %ldns\n", nanodiff(t0, t1));
#endif
}

void MachineInstance::tail_reset()
{
	/* Close any open files */
	m_fd.foreach_owned(
		[] (const auto& entry) {
			close(entry.item);
		});
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

		/* Load the fds of the source */
		m_fd.reset_and_loan(source.m_fd);
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

float MachineInstance::max_req_time() const noexcept {
	return tenant().config.max_req_time(is_debug());
}
const std::string& MachineInstance::name() const noexcept {
	return tenant().config.name;
}
const std::string& MachineInstance::group() const noexcept {
	return tenant().config.group.name;
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
	if (this->m_last_newline) {
		tenant().logf(
			">>> [%s] %.*s", name().c_str(), (int)text.size(), text.begin());
	} else {
		tenant().log(text);
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
	}
}
tinykvm::Machine::printer_func MachineInstance::get_vsl_printer() const
{
	/* NOTE: Guests will "always" end with newlines */
	return [this] (const char* buffer, size_t len) {
		/* Avoid wrap-around and empty log */
		if (buffer + len < buffer || len == 0)
			return;
		/* Logging with $PROGRAM says: ... */
		this->logprint(std::string_view(buffer, len), true);

		if (this->m_print_stdout) {
			this->print({buffer, len});
		}
	};
}

} // kvm
