#include "common_defs.hpp"
#include "program_instance.hpp"
#include "scoped_duration.hpp"
#include "tenant_instance.hpp"
#include <atomic>
#include <nlohmann/json.hpp>

namespace kvm {
template <typename TT>
static auto gather_stats(const MachineInstance& mi, TT& taskq)
{
	const auto& stats = mi.stats();

	return nlohmann::json::object({
		{"invocations", stats.invocations},
		{"resets",      stats.resets},
		{"exceptions",  stats.exceptions},
		{"timeouts",    stats.timeouts},
		{"reservation_time",   stats.reservation_time},
		{"reset_time",         stats.vm_reset_time},
		{"request_cpu_time",   stats.request_cpu_time},
		{"exception_cpu_time", stats.error_cpu_time},
		{"input_bytes", stats.input_bytes},
		{"output_bytes",stats.output_bytes},
		{"status_2xx",  stats.status_2xx},
		{"status_3xx",  stats.status_3xx},
		{"status_4xx",  stats.status_4xx},
		{"status_5xx",  stats.status_5xx},
		{"vm_address_space", mi.tenant().config.max_address()},
		{"vm_main_memory",   mi.tenant().config.max_main_memory()},
		{"vm_bank_capacity", mi.machine().banked_memory_capacity_bytes()},
		{"vm_bank_highest",  mi.machine().banked_memory_allocated_bytes()},
		{"vm_bank_current",  mi.machine().banked_memory_bytes()},
		{"tasks_queued",   taskq.racy_queue_size()}
	});
}

void TenantInstance::gather_stats(nlohmann::json& j)
{
	using namespace nlohmann;
	static constexpr bool debug = false;

	std::shared_ptr<ProgramInstance> prog;
	if (LIKELY(!debug))
		prog = std::atomic_load(&this->program);
	else
		prog = std::atomic_load(&this->debug_program);

	/* Don't gather stats for missing programs. */
	if (prog == nullptr) {
		fprintf(stderr,
			"compute: Did not gather stats (missing program)");
		return;
	}

	/* JSON object root uses program name. */
	auto& obj = j[this->config.name];

	/* Storage VM */
	if (prog->has_storage())
	{
		auto& storage = prog->storage();
		auto stats = kvm::gather_stats(*storage.storage_vm, prog->m_storage_queue);
		stats.push_back({"tasks_inschedule", prog->m_timer_system.racy_count()});

		obj["storage"] = {stats};
	}

	MachineStats totals {};
	auto& requests = obj["request"];
	auto machines = json::array();

	/* Individual request VMs */
	double total_resv_time = 0.0;
	for (size_t i = 0; i < prog->m_vms.size(); i++)
	{
		auto& mi = *prog->m_vms[i].mi;
		machines.push_back(kvm::gather_stats(mi, prog->m_vms[i].tp));

		totals.invocations += mi.stats().invocations;
		totals.exceptions += mi.stats().exceptions;
		totals.resets += mi.stats().resets;
		totals.timeouts += mi.stats().timeouts;

		total_resv_time += mi.stats().reservation_time;
		totals.reservation_time += mi.stats().reservation_time;
		totals.vm_reset_time += mi.stats().vm_reset_time;
		totals.request_cpu_time += mi.stats().request_cpu_time;
		totals.error_cpu_time += mi.stats().error_cpu_time;

		totals.input_bytes += mi.stats().input_bytes;
		totals.output_bytes += mi.stats().output_bytes;

		totals.status_2xx += mi.stats().status_2xx;
		totals.status_3xx += mi.stats().status_3xx;
		totals.status_4xx += mi.stats().status_4xx;
		totals.status_5xx += mi.stats().status_5xx;
		totals.status_unknown += mi.stats().status_unknown;
	}

	requests["machines"] = std::move(machines);

	/* Cumulative totals */
	requests.push_back({"totals", {
		{"invocations", totals.invocations},
		{"resets",      totals.resets},
		{"exceptions",  totals.exceptions},
		{"timeouts",    totals.timeouts},
		{"reservation_time",   totals.reservation_time},
		{"reset_time",         totals.vm_reset_time},
		{"request_cpu_time",   totals.request_cpu_time},
		{"exception_cpu_time", totals.error_cpu_time},
		{"input_bytes", totals.input_bytes},
		{"output_bytes",totals.output_bytes},
		{"status_2xx",  totals.status_2xx},
		{"status_3xx",  totals.status_3xx},
		{"status_4xx",  totals.status_4xx},
		{"status_5xx",  totals.status_5xx},
	}});

	obj["program"] = {
		{"binary_type",  prog->main_vm->binary_type_string()},
		{"binary_size",  prog->request_binary.size()},
		{"entry_points", {
			{"on_get", prog->entry_address[(size_t)ProgramEntryIndex::ON_GET]},
			{"on_post", prog->entry_address[(size_t)ProgramEntryIndex::ON_POST]},
			{"on_method", prog->entry_address[(size_t)ProgramEntryIndex::ON_METHOD]},
			{"on_stream", prog->entry_address[(size_t)ProgramEntryIndex::ON_STREAM_POST]},
			{"on_error", prog->entry_address[(size_t)ProgramEntryIndex::ON_ERROR]},
			{"live_update_serialize", prog->entry_address[(size_t)ProgramEntryIndex::LIVEUPD_SERIALIZE]},
			{"live_update_deserialize", prog->entry_address[(size_t)ProgramEntryIndex::LIVEUPD_DESERIALIZE]},
			{"socket_pause_resume_api", prog->entry_address[(size_t)ProgramEntryIndex::SOCKET_PAUSE_RESUME_API]}
		}},
		{"live_updates", prog->stats.live_updates},
		{"live_update_transfer_bytes", prog->stats.live_update_transfer_bytes},
		{"reservation_time",     total_resv_time},
		{"reservation_timeouts", prog->stats.reservation_timeouts},
	};

}
} // kvm
