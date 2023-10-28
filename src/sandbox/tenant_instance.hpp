#pragma once
#include <functional>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include "live_update.hpp"
#include "tenant.hpp"
namespace tinykvm { struct vCPU; }

namespace kvm {
class ProgramInstance;
class MachineInstance;
struct VMPoolItem;

class TenantInstance {
public:
	/* Obtain ownership of a single VM. */
	VMPoolItem* vmreserve(bool debug);

	/* Append statistics from the current program and all its VMs. */
	void gather_stats(nlohmann::json& j);

	std::shared_ptr<ProgramInstance> ref(bool debug);
	bool no_program_loaded() const noexcept { return this->program == nullptr; }

	uint64_t lookup(const char* name) const;

	/* Perform a live update, replacing the current program. */
	LiveUpdateResult live_update(const LiveUpdateParams& params);

	/* Reloads/unloads the current program. */
	void reload_program_live(bool debug);

	/* If the tenants program employ serialization callbacks, we can
	   serialize the important bits of the current program and then
	   pass these bits to a new incoming live updated program, allowing
	   safe state transfer between storage VM of two programs. */
	static void serialize_storage_state(
		std::shared_ptr<ProgramInstance>& old,
		std::shared_ptr<ProgramInstance>& inst);

	/* Create tenant. */
	TenantInstance(const TenantConfig&, bool start_initialize);

	void begin_initialize();
	void begin_async_initialize();
	std::shared_ptr<ProgramInstance> wait_for_initialization();

	const TenantConfig config;
	/* Hot-swappable machine */
	mutable std::shared_ptr<ProgramInstance> program = nullptr;
	/* Hot-swappable machine for debugging */
	mutable std::shared_ptr<ProgramInstance> debug_program = nullptr;

	/* Logging */
	void do_log(std::string_view data) const;
	void logf(const char* fmt, ...) const;

	using logging_func_t = std::function<void(TenantInstance*, std::string_view)>;
	static void set_logger(logging_func_t new_logger) { m_logger = new_logger; }

private:
	/* Used by live update mechanism to replace the main VM with a new
	   one that was HTTP POSTed by a tenant. */
	void commit_program_live(
		std::shared_ptr<ProgramInstance>& new_prog) const;

	bool wait_guarded_initialize(std::shared_ptr<ProgramInstance>&);
	void handle_exception(const TenantConfig&, const std::exception&);
	bool m_started_init = false;
	std::mutex mtx_running_init;
	static inline logging_func_t m_logger;
};

} // kvm
