#pragma once
#include <cassert>
#include <tinykvm/machine.hpp>
#include "binary_storage.hpp"
#include "instance_cache.hpp"
#include "machine_stats.hpp"
#include "utils/xorshift.hpp"

namespace kvm {
class TenantInstance;
class ProgramInstance;

/**
 * MachineInstance is a collection of state that is per VM,
 * and per request. It will keep things like file descriptors,
 * backends, regex handles and such. And most importanatly,
 * it holds an actual KVM VM that is based on the tenants program.
 *
 * Once the request ends and this instance dies, it will decrease
 * refcounts on a few things, so if the tenant sends a new program,
 * the old program is kept alive until all requests that are using
 * it ends.
**/
class MachineInstance {
public:
	using gaddr_t = uint64_t;
	using machine_t = tinykvm::Machine;
	static constexpr size_t REGEX_MAX = 64;

	void print(std::string_view text) const;
	void logprint(std::string_view text, bool says = false) const;
	void logf(const char*, ...) const;

	auto& machine() { return m_machine; }
	const auto& machine() const { return m_machine; }

	void copy_to(uint64_t addr, const void*, size_t, bool zeroes = false);

	const auto& tenant() const noexcept { return *m_tenant; }
	auto& program() noexcept { return *m_inst; }
	const auto& program() const noexcept { return *m_inst; }

	unsigned request_id() const noexcept { return m_request_id; }
	float max_req_time() const noexcept;
	const std::string& name() const noexcept;
	const std::string& group() const noexcept;

	auto& stats() noexcept { return this->m_stats; }
	const auto& stats() const noexcept { return this->m_stats; }

	bool allows_debugging() const noexcept;
	bool is_debug() const noexcept { return m_is_debug; }
	bool is_storage() const noexcept { return m_is_storage; }
	bool is_ephemeral() const noexcept { return m_is_ephemeral; }
	gaddr_t shared_memory_boundary() const noexcept;
	gaddr_t shared_memory_size() const noexcept;
	void set_ephemeral(bool e) noexcept { m_is_ephemeral = e; }
	enum class BinaryType : uint8_t {
		Static,
		StaticPie,
		Dynamic,
	};
	BinaryType binary_type() const noexcept { return m_binary_type; }
	std::string binary_type_string() const noexcept;

	void reset_wait_for_requests() { m_waiting_for_requests = false; }
	void wait_for_requests() { m_waiting_for_requests = true; }
	/* For now, pausing does nothing. */
	void wait_for_requests_paused();
	bool is_waiting_for_requests() const noexcept { return m_waiting_for_requests; }
	/* With this we can enforce that certain syscalls have been invoked before
	   we even check the validity of responses. This makes sure that crashes does
	   not accidentally produce valid responses, which can cause confusion. */
	void begin_call() { m_response_called = 0; }
	void finish_call(uint8_t n) { m_response_called = n; }
	bool response_called(uint8_t n) const noexcept { return m_response_called == n; }
	void reset_needed_now() { m_reset_needed = true; }
	bool is_reset_needed() const;

	void init_sha256();
	void hash_buffer(const char* buffer, int len);
	bool apply_hash();

	std::string symbol_name(gaddr_t address) const;
	gaddr_t resolve_address(const char* name) const { return machine().address_of(name); }

	void set_sigaction(int sig, gaddr_t handler);
	void print_backtrace();
	void open_debugger(uint16_t, float timeout);
	void storage_debugger(float timeout);

	uint64_t allocate_post_data(size_t size);
	gaddr_t& get_inputs_allocation() { return m_inputs_allocation; }
	uint64_t rand_uint64() { return m_prng.randU64(); }

	static void kvm_initialize();
	MachineInstance(const BinaryStorage&, const TenantInstance*, ProgramInstance*, bool storage, bool dbg);
	MachineInstance(unsigned reqid, const MachineInstance&, const TenantInstance*, ProgramInstance*);
	double initialize();
	void warmup();
	~MachineInstance();
	void tail_reset();
	void reset_to(MachineInstance&);
	void print_profiling() const;

private:
	static void setup_syscall_interface();
	void handle_exception(gaddr_t);
	void handle_timeout(gaddr_t);
	tinykvm::Machine::printer_func get_printer() const;

	machine_t m_machine;
	const TenantInstance* m_tenant = nullptr;
	ProgramInstance* m_inst;
	const BinaryStorage& m_original_binary;
	uint16_t    m_request_id = 0;
	bool        m_is_debug;
	const bool  m_is_storage;
	bool        m_is_ephemeral = true;
	bool        m_waiting_for_requests = false;
	bool        m_is_warming_up = false;
	uint8_t     m_response_called = 0;
	bool        m_reset_needed = false;
	bool        m_store_state_on_reset = false;
	mutable bool m_last_newline = true;
	BinaryType m_binary_type = BinaryType::Static;
	gaddr_t     m_sighandler = 0x0;

	gaddr_t     m_post_data = 0x0;
	size_t      m_post_size = 0;
	gaddr_t     m_inputs_allocation = 0x0;

	MachineStats m_stats;

	XorPRNG m_prng;
};

} // kvm
