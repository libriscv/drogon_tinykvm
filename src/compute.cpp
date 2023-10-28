#include <drogon/drogon.h>
#include "sandbox/tenants.hpp"
#include "sandbox/program_instance.hpp"
#include "sandbox/scoped_duration.hpp"
static constexpr bool USE_RESERVATIONS = true;
using namespace drogon;
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
}

static void kvm_handle_request(kvm::MachineInstance& inst, const HttpRequestPtr& req)
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
			if (!inst.tenant().config.group.ephemeral) {
				if (!inst.is_waiting_for_requests()) {
					/* Run the VM until it halts again, and it should be waiting for requests. */
					vm.run_in_usermode(1.0f);
					if (!inst.is_waiting_for_requests()) {
						throw std::runtime_error("VM did not wait for requests after backend request");
					}
				}
			}
			/* Allocate 16KB space for struct backend_inputs */
			struct backend_inputs inputs {};
			if (inst.get_inputs_allocation() == 0) {
				inst.get_inputs_allocation() = vm.mmap_allocate(16384) + 16384;
			}
			__u64 stack = inst.get_inputs_allocation();
			fill_backend_inputs(inst, stack, req, inputs);

			auto& regs = vm.registers();
			/* RDI is address of struct backend_inputs */
			const uint64_t g_struct_addr = regs.rdi;
			vm.copy_to_guest(g_struct_addr, &inputs, sizeof(inputs));

			/* Resume execution */
			vm.vmresume();
			/* Ephemeral VMs are reset and don't need to run until halt. */
			if (!inst.tenant().config.group.ephemeral) {
				// Skip the OUT instruction (again)
				regs.rip += 2;
				vm.set_registers(regs);
				/* We're delivering a response, and clearly not waiting for requests. */
				inst.reset_wait_for_requests();
			}
		}

		/* Make sure no SMP work is in-flight. */
		vm.smp_wait();
	}
}

void kvm_compute(kvm::TenantInstance& tenant,
	const HttpRequestPtr& req, HttpResponsePtr& resp)
{
	thread_local kvm::VMPoolItem* slot = nullptr;
	if constexpr (USE_RESERVATIONS) {
		if (UNLIKELY((slot = tenant.vmreserve(false)) == nullptr)) {
			resp->setStatusCode(k500InternalServerError);
			return;
		}
	} else {
		if (UNLIKELY(slot == nullptr)) {
			if (UNLIKELY((slot = tenant.vmreserve(false)) == nullptr)) {
				resp->setStatusCode(k500InternalServerError);
				return;
			}
		} else if (&tenant != &slot->mi->tenant()) {
			kvm::ProgramInstance::vm_free_function(slot);
			if (UNLIKELY((slot = tenant.vmreserve(false)) == nullptr)) {
				resp->setStatusCode(k500InternalServerError);
				return;
			}
		}
	}

	kvm::MachineInstance& inst = *slot->mi;
	try {
		if constexpr (USE_RESERVATIONS)
		{
			slot->tp.enqueue([&inst, &req] () -> long {
				kvm_handle_request(inst, req);
				return 0;
			}).get();
		} else {
			kvm_handle_request(inst, req);
		}

		if (UNLIKELY(!inst.response_called(1))) {
			throw std::runtime_error("HTTP response not set. Program crashed? Check logs!");
		}

		/* VM registers with 5 arguments */
		auto& vm = inst.machine();
		const auto& regs = vm.registers();

		/* Get content-type and data */
		const uint16_t status = regs.rdi;
		const uint64_t tvaddr = regs.rsi;
		const uint16_t tlen   = regs.rdx;
		const uint64_t cvaddr = regs.rcx;
		const uint64_t clen   = regs.r8;

		/* Status code statistics */
		if (LIKELY(status >= 200 && status < 300)) {
			inst.stats().status_2xx++;
		} else if (UNLIKELY(status < 200)) {
			inst.stats().status_unknown ++;
		} else if (status < 400) {
			inst.stats().status_3xx++;
		} else if (status < 500) {
			inst.stats().status_4xx++;
		} else if (status < 600) {
			inst.stats().status_5xx++;
		} else {
			inst.stats().status_unknown++;
		}

		resp->setStatusCode((drogon::HttpStatusCode)status);
		resp->setContentTypeString(vm.buffer_to_string(tvaddr, tlen));
		resp->setBody(vm.buffer_to_string(cvaddr, clen));

		if constexpr (USE_RESERVATIONS) {
			kvm::ProgramInstance::vm_free_function(slot);
			slot = nullptr;
		} else {
			inst.reset_to(*inst.program().main_vm);
		}
		return;

	} catch (const tinykvm::MachineTimeoutException& mte) {
		fprintf(stderr, "%s: Backend VM timed out (%f seconds)\n",
			inst.name().c_str(), mte.seconds());
	} catch (const tinykvm::MachineException& e) {
		fprintf(stderr, "%s: Backend VM exception: %s (data: 0x%lX)\n",
			inst.name().c_str(), e.what(), e.data());
	} catch (const std::exception& e) {
		fprintf(stderr, "Backend VM exception: %s\n", e.what());
	}
	resp->setStatusCode(k500InternalServerError);
	inst.stats().exceptions ++;
	// Reset to known good state
	inst.reset_needed_now();
	if constexpr (USE_RESERVATIONS) {
		kvm::ProgramInstance::vm_free_function(slot);
		slot = nullptr;
	} else {
		inst.reset_to(*inst.program().main_vm);
	}
}
