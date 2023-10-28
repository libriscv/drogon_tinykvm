#include <drogon/drogon.h>
#include <tinykvm/util/scoped_profiler.hpp>
#include "sandbox/tenants.hpp"
#include "sandbox/program_instance.hpp"
#include "sandbox/scoped_duration.hpp"
#include "settings.hpp"
static constexpr size_t BACKEND_INPUTS_SIZE = 64UL << 10; // 64KB
using namespace drogon;
struct backend_header {
	uint64_t field_ptr;
	uint32_t field_colon;
	uint32_t field_len;
};
struct backend_inputs {
	uint64_t method;
	uint64_t url;
	uint64_t arg;
	uint64_t ctype;
	uint16_t method_len;
	uint16_t url_len;
	uint16_t arg_len;
	uint16_t ctype_len;
	uint64_t data; /* Content: Can be NULL. */
	uint64_t data_len;
	/* HTTP headers */
	uint64_t g_headers;
	uint16_t num_headers;
	uint16_t info_flags; /* 0x1 = request is a warmup request. */
	uint16_t reqid;      /* Request Machine ID. */
	uint16_t reserved0;    /* Reserved for future use. */
	uint64_t prng[2];      /* Pseudo-random number generator state. */
	uint64_t reserved1[2]; /* Reserved for future use. */
};

static void fill_backend_inputs(
	kvm::MachineInstance& machine, __u64& stack,
	const HttpRequestPtr& req,
	backend_inputs& inputs)
{
	auto& vm = machine.machine();
	// Set HTTP method
	switch (req->getMethod()) {
	case HttpMethod::Get:
		inputs.method_len = 3;
		inputs.method     = vm.stack_push_cstr(stack, "GET");
		break;
	case HttpMethod::Post:
		inputs.method_len = 4;
		inputs.method     = vm.stack_push_cstr(stack, "POST");
		break;
	case HttpMethod::Put:
		inputs.method_len = 3;
		inputs.method     = vm.stack_push_cstr(stack, "PUT");
		break;
	case HttpMethod::Delete:
		inputs.method_len = 6;
		inputs.method     = vm.stack_push_cstr(stack, "DELETE");
		break;
	case HttpMethod::Patch:
		inputs.method_len = 5;
		inputs.method     = vm.stack_push_cstr(stack, "PATCH");
		break;
	case HttpMethod::Options:
		inputs.method_len = 7;
		inputs.method     = vm.stack_push_cstr(stack, "OPTIONS");
		break;
	case HttpMethod::Head:
		inputs.method_len = 4;
		inputs.method     = vm.stack_push_cstr(stack, "HEAD");
		break;
	default:
		inputs.method_len = 0;
		inputs.method     = vm.stack_push_cstr(stack, "");
		break;
	}
	// Set URL
	inputs.url_len = req->getPath().length();
	inputs.url     = vm.stack_push(stack, req->getPath().data(), inputs.url_len + 1);
	// Set argument
	inputs.arg_len = req->query().length();
	inputs.arg     = vm.stack_push(stack, req->query().data(), inputs.arg_len + 1);
	// If there's a POST body
	if (req->body().length() > 0) {
		// Set content-type, if available
		const auto& content_type = req->getHeader("Content-Type");
		inputs.ctype = vm.stack_push(stack, content_type.data(), content_type.length() + 1);
		inputs.ctype_len = content_type.length();
		inputs.data  = vm.stack_push(stack, req->body().data(), req->body().length());
		inputs.data_len = req->body().length();
		machine.stats().input_bytes += req->body().length();
	}
	else
	{
		/* Guarantee readable strings. */
		inputs.ctype = inputs.url + inputs.url_len; // Guaranteed zero-terminated.
		inputs.ctype_len = 0;
		/* Buffers with known length can be NULL. */
		inputs.data  = 0;
		inputs.data_len = 0;
	}
	inputs.prng[0] = machine.rand_uint64();
	inputs.prng[1] = machine.rand_uint64();
}
static size_t fill_backend_headers(
	kvm::MachineInstance& machine, __u64& stack,
	const HttpRequestPtr& req,
	backend_inputs& inputs)
{
	auto& vm = machine.machine();
	/* Allocate space for headers on the stack */
	const size_t num_headers = req->getHeaders().size();
	/* If there are no headers, return */
	if (num_headers == 0) {
		inputs.g_headers = 0;
		inputs.num_headers = 0;
		return 0;
	}
	std::array<backend_header, 64> header_array;
	if (num_headers > header_array.size()) {
		throw std::runtime_error("Too many headers in backend inputs");
	}
	/* Push each header field to the stack */
	const auto& req_headers = req->getHeaders();
	size_t n = 0;
	char buffer[16384]; // 16KB buffer for header field
	for (const auto& header : req_headers) {
		auto& guest_header = header_array.at(n++);
		const int len = snprintf(buffer, sizeof(buffer), "%.*s: %.*s",
			(int)header.first.length(), header.first.data(),
			(int)header.second.length(), header.second.data());
		if (len < 0 || len >= sizeof(buffer)) {
			throw std::runtime_error("Header field too long: " + header.first);
		}
		guest_header.field_ptr
			= vm.stack_push_cstr(stack, buffer, len);
		guest_header.field_colon = header.first.length();
		guest_header.field_len = len;
	}
	/* Push the header array to the stack using stack_push_std_array */
	const auto header_array_addr = vm.stack_push_std_array(stack, header_array, num_headers);
	/* Set the header array address and number of headers */
	inputs.g_headers = header_array_addr;
	inputs.num_headers = num_headers;
	inputs.reqid = machine.request_id();
	return num_headers;
}

static void kvm_handle_request(kvm::MachineInstance& inst, const HttpRequestPtr& req, bool ephemeral, bool warmup)
{
	auto& vm = inst.machine();
	{
		/* Scope: Regular CPU-time. */
		kvm::ScopedDuration cputime(inst.stats().request_cpu_time);

		inst.stats().invocations ++;
		inst.begin_call();

		const auto timeout = inst.tenant().config.max_req_time(false);

		/* Make function call into VM, with URL as argument. */
		if (req->getMethod() == HttpMethod::Get && inst.program().entry_at(kvm::ProgramEntryIndex::ON_GET) != 0)
		{
			const auto on_get_addr = inst.program().entry_at(
				kvm::ProgramEntryIndex::ON_GET);

			vm.timed_vmcall(on_get_addr, timeout,
				req->getPath(),
				"");
		}
		else if (req->getMethod() == HttpMethod::Post && inst.program().entry_at(kvm::ProgramEntryIndex::ON_POST) != 0)
		{
			const auto on_post_addr = inst.program().entry_at(
				kvm::ProgramEntryIndex::ON_POST);

			const auto& content_type = req->getHeader("Content-Type");
			const std::string_view body = req->body();

			const auto g_address = inst.allocate_post_data(body.size());
			vm.copy_to_guest(g_address, body.data(), body.size());
			inst.stats().input_bytes += body.size();

			vm.timed_vmcall(on_post_addr,
				timeout,
				req->getPath(),
				"",
				content_type,
				uint64_t(g_address), uint64_t(body.size()));
		}
		else
		{
			/* Ephemeral VMs are reset and don't need to run until halt. */
			if (!ephemeral) {
				if (!inst.is_waiting_for_requests()) {
					/* Run the VM until it halts again, and it should be waiting for requests. */
					vm.run_in_usermode(1.0f);
					if (!inst.is_waiting_for_requests()) {
						throw std::runtime_error("VM did not wait for requests after backend request");
					}
				}
			}
			/* Allocate space for struct backend_inputs */
			struct backend_inputs inputs {};
			if (inst.get_inputs_allocation() == 0) {
				inst.get_inputs_allocation() = vm.mmap_allocate(BACKEND_INPUTS_SIZE) + BACKEND_INPUTS_SIZE;
			}
			__u64 stack = inst.get_inputs_allocation();
			fill_backend_inputs(inst, stack, req, inputs);
			fill_backend_headers(inst, stack, req, inputs);
			inputs.info_flags = warmup ? 1 : 0;

			auto& regs = vm.registers();
			/* RDI is address of struct backend_inputs */
			const uint64_t g_struct_addr = regs.rdi;
			vm.copy_to_guest(g_struct_addr, &inputs, sizeof(inputs));

			/* Resume execution */
			vm.vmresume(timeout);

			/* Ephemeral VMs are reset and don't need to run until halt. */
			if (!ephemeral) {
				// Skip the OUT instruction (again)
				regs.rip += 2;
				vm.set_registers(regs);
				/* We're delivering a response, and clearly not waiting for requests. */
				inst.reset_wait_for_requests();
			}
		}
	}
}

void kvm_compute(kvm::TenantInstance& tenant,
	const HttpRequestPtr& req, HttpResponsePtr& resp)
{
	thread_local kvm::VMPoolItem* slot = nullptr;
	thread_local kvm::VMPoolItem* alternate_slot = nullptr;
	kvm::VMPoolItem* r_slot = nullptr;

	if (g_settings.reservations) {
		if (UNLIKELY((r_slot = tenant.vmreserve(false)) == nullptr)) {
			resp->setStatusCode(k500InternalServerError);
			return;
		}
	} else {
		// Use double-buffering to allow the previous request to be reset
		// while we process the new request
		if (g_settings.double_buffered) {
			std::swap(slot, alternate_slot);
		}
		r_slot = slot;
		if (UNLIKELY(r_slot == nullptr)) {
			if (UNLIKELY((r_slot = tenant.vmreserve(false)) == nullptr)) {
				resp->setStatusCode(k500InternalServerError);
				return;
			}
			if (tenant.config.group.max_concurrency < g_settings.num_threads()) {
				// Limit the number of threads if max_concurrency is set
				throw std::runtime_error("The tenant \"" + tenant.config.name + "\" has a max concurrency of " +
					std::to_string(tenant.config.group.max_concurrency) + ", but the server is configured to use " +
					std::to_string(g_settings.num_threads()) + " threads.");
			}
			slot = r_slot;
		} else if (&tenant != &r_slot->mi->tenant()) {
			if (r_slot->task_future.valid())
				r_slot->task_future.get();
			if (UNLIKELY((r_slot = tenant.vmreserve(false)) == nullptr)) {
				resp->setStatusCode(k500InternalServerError);
				return;
			}
			if (&tenant != &r_slot->mi->tenant()) {
				throw std::runtime_error("Reserved VM from wrong tenant");
			}
			slot = r_slot;
		} else {
			if (r_slot->task_future.valid())
				r_slot->task_future.get();
		}
	}

	kvm::MachineInstance* inst = r_slot->mi.get();
	tinykvm::ScopedProfiler<tinykvm::MachineProfiling::UserDefined> profiler(inst->machine().profiling());
	try {
		if (g_settings.reservations)
		{
			r_slot->tp.enqueue([inst, &req] () -> long {
				kvm_handle_request(*inst, req, inst->tenant().config.group.ephemeral, false);
				return 0;
			}).get();
		} else {
			kvm_handle_request(*inst, req, inst->tenant().config.group.ephemeral, false);
		}

		kvm::MachineInstance* resp_inst = inst;
		/* If the VM is remote, we need to get the response from storage VM instead */
		auto& vm = resp_inst->machine();
		if (vm.is_remote_connected()) {
			resp_inst = &resp_inst->program().storage().front_storage();
		}

		if (UNLIKELY(!resp_inst->response_called(1))) {
			throw std::runtime_error("HTTP response not set. Program crashed? Check logs!");
		}

		/* VM registers with 5 arguments */
		auto& regs = vm.registers();

		/* Get content-type and data */
		const uint16_t status = regs.rdi;
		const uint64_t tvaddr = regs.rsi;
		const uint16_t tlen   = regs.rdx;
		const uint64_t cvaddr = regs.rcx;
		const uint64_t clen   = regs.r8;

		/* Status code statistics */
		if (LIKELY(status >= 200 && status < 300)) {
			resp_inst->stats().status_2xx++;
		} else if (UNLIKELY(status < 200)) {
			resp_inst->stats().status_unknown ++;
		} else if (status < 400) {
			resp_inst->stats().status_3xx++;
		} else if (status < 500) {
			resp_inst->stats().status_4xx++;
		} else if (status < 600) {
			resp_inst->stats().status_5xx++;
		} else {
			resp_inst->stats().status_unknown++;
		}
		/* Set response */
		resp->setStatusCode((drogon::HttpStatusCode)status);
		resp->setContentTypeString(vm.buffer_to_string(tvaddr, tlen));
		resp->setBody(vm.buffer_to_string(cvaddr, clen));

		/* Disconnect from the remote, if it's still connected */
		if (vm.is_remote_connected()) {
			vm.cpu().remote_return_address = vm.exit_address();
			// Complete the function call, which destroys temporary buffers
			vm.run(5.0f);
			if (vm.is_remote_connected()) {
				fprintf(stderr, "%s: Warning: Remote still connected after return\n",
					resp_inst->name().c_str());
				throw std::runtime_error("Remote still connected after return");
			}
		}

		if (g_settings.reservations) {
			kvm::ProgramInstance::vm_free_function(r_slot);
		} else {
			r_slot->deferred_reset();
		}
		return;

	} catch (const tinykvm::MachineTimeoutException& mte) {
		fprintf(stderr, "%s: VM timed out (%f seconds)\n",
			inst->name().c_str(), mte.seconds());
		inst->machine().print_registers();
	} catch (const tinykvm::MachineException& e) {
		fprintf(stderr, "%s: VM exception: %s (data: 0x%lX)\n",
			inst->name().c_str(), e.what(), e.data());
		inst->machine().print_registers();
	} catch (const std::exception& e) {
		fprintf(stderr, "VM exception: %s\n", e.what());
		inst->machine().print_registers();
	}
	resp->setStatusCode(k500InternalServerError);
	inst->stats().exceptions ++;
	// Reset to known good state (which also disconnects remote)
	inst->reset_needed_now();
	if (g_settings.reservations) {
		kvm::ProgramInstance::vm_free_function(r_slot);
	} else {
		r_slot->reset();
		slot = nullptr;
	}
}

void kvm_handle_warmup(kvm::MachineInstance& inst, const kvm::TenantGroup::Warmup& warmup)
{
	if (warmup.num_requests == 0) {
		return;
	}
	auto& vm = inst.machine();
	const bool had_profiling = vm.is_profiling();
	if (!had_profiling) {
		vm.set_profiling(true); // Enable profiling for warmup
	}
	vm.profiling()->clear(); // Clear previous profiling data

	/* Allocate a HttpRequest object */
	auto req = HttpRequest::newHttpRequest();
	req->setPath(warmup.url);
	//req->setMethod(warmup.method);
	req->setMethod(HttpMethod::Get);
	req->addHeader("User-Agent", "TinyKVM/1.0");
	for (const auto& header : warmup.headers) {
		const auto pos = header.find(':');
		if (pos == std::string::npos) {
			throw std::runtime_error("Invalid header format");
		}
		const auto name = header.substr(0, pos);
		const auto value = header.substr(pos + 1);
		if (value.empty()) {
			throw std::runtime_error("Invalid header format");
		}
		req->addHeader(name, value);
	}

	/* Run the warmup requests */
	const int MAX_BAILOUT = warmup.num_requests;
	int improvement_bailout = MAX_BAILOUT; // Stop if no improvement after N tries
	uint64_t best_time = UINT64_MAX;
	for (int i = 0;; i++) {
		{
			tinykvm::ScopedProfiler<tinykvm::MachineProfiling::UserDefined> reqtime(vm.profiling());
			kvm_handle_request(inst, req, false, true);
		}
		/* Check if this was an improvement */
		if (const auto* profiler = vm.profiling(); profiler != nullptr) {
			const auto& samples = profiler->times[tinykvm::MachineProfiling::UserDefined];
			const bool is_improvement = (samples.back() < best_time);
			if (is_improvement) {
				best_time = samples.back();
				improvement_bailout = MAX_BAILOUT; // Reset bailout counter
				if (inst.tenant().config.group.verbose) {
					printf("Warmup: New best time: %lu ns (iteration %d)\n", best_time, i);
				}
			} else {
				// Not an improvement, so we can stop here
				if (--improvement_bailout == 0) {
					if (inst.tenant().config.group.verbose) {
						printf("Warmup: No improvement after %d tries, stopping warmup. Iterations: %d\n", MAX_BAILOUT, i);
					}
					break;
				}
			}
		}
	}

	/* Disable profiling again if it was disabled before */
	if (!had_profiling) {
		vm.set_profiling(false);
	}

	/* Run the VM until it halts again, and it should be waiting for requests. */
	vm.run_in_usermode(1.0f);
	if (!inst.is_waiting_for_requests()) {
		throw std::runtime_error("VM did not wait for requests after backend request");
	}

	// Skip the OUT instruction (again)
	auto& regs = vm.registers();
	regs.rip += 2;
	vm.set_registers(regs);
}
