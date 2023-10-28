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
		{"full_resets", stats.full_resets},
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
		{"vm_remote_calls", mi.machine().remote_connection_count()},
		{"tasks_queued",   taskq.racy_queue_size()}
	});
}
static void calculate_totals(MachineStats& total, const MachineStats& add)
{
	total.invocations += add.invocations;
	total.resets      += add.resets;
	total.full_resets += add.full_resets;
	total.exceptions  += add.exceptions;
	total.timeouts    += add.timeouts;

	total.reservation_time += add.reservation_time;
	total.vm_reset_time    += add.vm_reset_time;
	total.request_cpu_time += add.request_cpu_time;
	total.error_cpu_time   += add.error_cpu_time;

	total.status_2xx += add.status_2xx;
	total.status_3xx += add.status_3xx;
	total.status_4xx += add.status_4xx;
	total.status_5xx += add.status_5xx;
	total.status_unknown += add.status_unknown;

	total.input_bytes  += add.input_bytes;
	total.output_bytes += add.output_bytes;
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
		return;
	}

	/* JSON object root uses program name. */
	auto& obj = j[this->config.name];

	/* Storage VM */
	if (prog->has_storage())
	{
		auto& storage = prog->storage();
		MachineStats total_storage {};
		auto storages = json::array();
		for (size_t i = 0; i < storage.storage_vm.size(); i++)
		{
			auto& mi = *storage.storage_vm[i];
			storages.push_back(kvm::gather_stats(mi, prog->m_storage_queue));

			/* Accumulate totals */
			calculate_totals(total_storage, mi.stats());
		}
		if (storage.storage_vm.empty()) {
			// Add the main storage VM
			storages.push_back(kvm::gather_stats(storage.front_storage(), prog->m_storage_queue));
			calculate_totals(total_storage, storage.front_storage().stats());
		}
		auto& storage_stats = obj["storage"];
		storage_stats["machines"] = std::move(storages);
		storage_stats.push_back({"totals", {
			{"invocations", total_storage.invocations},
			{"resets",      total_storage.resets},
			{"full_resets", total_storage.full_resets},
			{"exceptions",  total_storage.exceptions},
			{"timeouts",    total_storage.timeouts},
			{"reservation_time",   total_storage.reservation_time},
			{"reset_time",         total_storage.vm_reset_time},
			{"request_cpu_time",   total_storage.request_cpu_time},
			{"exception_cpu_time", total_storage.error_cpu_time},
			{"input_bytes", total_storage.input_bytes},
			{"output_bytes",total_storage.output_bytes},
			{"status_2xx",  total_storage.status_2xx},
			{"status_3xx",  total_storage.status_3xx},
			{"status_4xx",  total_storage.status_4xx},
			{"status_5xx",  total_storage.status_5xx}
		}});
		storage_stats.push_back({"tasks_inschedule",
			prog->m_timer_system.racy_count()});
	}

	MachineStats totals {};
	auto machines = json::array();
	const size_t num_machines = prog->m_vms.size();
	std::vector<uint64_t> reqid_requests;

	/* Individual request VMs */
	uint64_t total_remote_calls = 0;
	for (size_t i = 0; i < prog->m_vms.size(); i++)
	{
		auto& mi = *prog->m_vms[i].mi;
		machines.push_back(kvm::gather_stats(mi, prog->m_vms[i].tp));

		/* Accumulate totals */
		total_remote_calls += mi.machine().remote_connection_count();
		reqid_requests.push_back(mi.stats().invocations);
		calculate_totals(totals, mi.stats());
	}

	auto& requests = obj["request"];
	requests["machines"] = std::move(machines);

	/* Cumulative totals */
	requests.push_back({"totals", {
		{"invocations", totals.invocations},
		{"resets",      totals.resets},
		{"full_resets", totals.full_resets},
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
		{"distribution_requests", reqid_requests},
		{"vm_remote_calls", total_remote_calls},
		{"num_machines", num_machines}
	}});

	obj["program"] = {
		{"binary_type",  prog->main_vm->binary_type_string()},
		{"binary_size",  prog->request_binary.size()},
		{"entry_points", {
			{"on_get", prog->state.entry_address[(size_t)ProgramEntryIndex::ON_GET]},
			{"on_post", prog->state.entry_address[(size_t)ProgramEntryIndex::ON_POST]},
			{"on_method", prog->state.entry_address[(size_t)ProgramEntryIndex::ON_METHOD]},
			{"on_stream", prog->state.entry_address[(size_t)ProgramEntryIndex::ON_STREAM_POST]},
			{"on_error", prog->state.entry_address[(size_t)ProgramEntryIndex::ON_ERROR]},
			{"live_update_serialize", prog->state.entry_address[(size_t)ProgramEntryIndex::LIVEUPD_SERIALIZE]},
			{"live_update_deserialize", prog->state.entry_address[(size_t)ProgramEntryIndex::LIVEUPD_DESERIALIZE]},
			{"socket_pause_resume_api", prog->state.entry_address[(size_t)ProgramEntryIndex::SOCKET_PAUSE_RESUME_API]}
		}},
		{"live_updates", prog->stats.live_updates},
		{"live_update_transfer_bytes", prog->stats.live_update_transfer_bytes},
		{"reservation_time",     totals.reservation_time},
		{"reservation_timeouts", prog->stats.reservation_timeouts},
	};

}
} // kvm
