/**
 * @file tenant_instance.cpp
 * @author Alf-André Walla (fwsgonzo@hotmail.com)
 * @brief Live tenant configuration and programs.
 * @version 0.1
 * @date 2022-07-23
 * 
 * Contains the current program and debug-program for a tenant.
 * Both programs can be hot-swapped during execution at any time,
 * and atomic ref-counting is used to make sure that every request
 * keeps it alive until completion.
 * 
 * Also contains tenant configuration, which includes things like
 * timeouts, memory limits and other settings.
 * 
**/
#include "tenant_instance.hpp"

#include "common_defs.hpp"
#include "program_instance.hpp"
#include "time_format.hpp"
#include <cstdarg>
#include <sys/stat.h>
#include <unistd.h>

namespace kvm {
	extern std::vector<uint8_t> file_loader(const std::string&);

TenantInstance::TenantInstance(const TenantConfig& conf, bool start_initialize)
	: config{conf}
{
	static bool init = false;
	if (!init) {
		init = true;
		MachineInstance::kvm_initialize();
	}

	if (start_initialize)
		this->begin_initialize();
}

void TenantInstance::begin_initialize()
{
	/* Prevent initializing many times, with a warning. */
	if (this->m_started_init) {
		this->logf(
			"Program '%s' has already been initialized.",
			config.name.c_str());
		return;
	}
	this->m_started_init = true;

	bool filename_accessible = false;
	std::string filename_mtime = "";

	if (!config.filename.empty()) {
		if (access(config.filename.c_str(), R_OK) == 0)
		{
			filename_accessible = true;
			struct stat st;
			if (stat(config.filename.c_str(), &st) == 0) {
				char buf[32];
				time_format(st.st_mtim.tv_sec, buf);
				filename_mtime = "If-Modified-Since: " + std::string(buf);
			}
		}
	}

	/* 1. If program has an URI, use cURL. */
	if (!config.uri.empty())
	{
		/* Load the program from cURL fetch. */
		try {
			auto prog = std::make_shared<ProgramInstance> (
				config.uri, std::move(filename_mtime), this);
			std::atomic_store(&this->program, std::move(prog));
		} catch (const std::exception& e) {
			/* TODO: Retry with file loader here from local filesyste, if
			   the cURL fetch does not succeed. */
			this->handle_exception(config, e);
		}
		return;
	}
	/* 2. If filename is empty, do nothing (with warning in the logs). */
	else if (config.filename.empty()) {
		this->logf(
			"No filename specified for '%s'. Send new program.\n",
			config.name.c_str());
		return;
	}
	/* 3. Check program was in-accessible on local filesystem. */
	else if (!filename_accessible) {
		/* It is *NOT* accessible. */
		this->logf(
			"Missing program or invalid path for '%s'. Send new program.\n",
			config.name.c_str());
		return;
	}

	/* 4. Load the program from filesystem now. */
	try {
		auto elf = file_loader(config.request_program_filename());
		std::shared_ptr<ProgramInstance> prog;
		/* Check for a storage program */
		if (access(config.storage_program_filename().c_str(), R_OK) == 0)
		{
			auto storage_elf = file_loader(config.storage_program_filename());
			prog =
				std::make_shared<ProgramInstance> (std::move(elf), std::move(storage_elf), this);
		}
		else
		{
			prog =
				std::make_shared<ProgramInstance> (elf, elf, this);
		}
		std::atomic_store(&this->program, std::move(prog));

	} catch (const std::exception& e) {
		this->handle_exception(config, e);
	}
}
void TenantInstance::begin_async_initialize()
{
	/* Block other requests from trying to initialize. */
	std::scoped_lock lock(this->mtx_running_init);

	if (!this->m_started_init) {
		this->begin_initialize();
	}
}
bool TenantInstance::wait_guarded_initialize(std::shared_ptr<ProgramInstance>& prog)
{
	begin_async_initialize();

	/* This may take some time, as it is blocking, but this will allow the
		request to proceed.
		XXX: Verify that there are no forever-waiting events here. */
	prog = this->wait_for_initialization();
	return prog != nullptr;
}

void TenantInstance::handle_exception(const TenantConfig& conf, const std::exception& e)
{
	this->logf(
		"Exception when creating machine '%s': %s\n",
		conf.name.c_str(), e.what());
	this->program = nullptr;
}

std::shared_ptr<ProgramInstance> TenantInstance::wait_for_initialization()
{
	std::shared_ptr<ProgramInstance> prog = std::atomic_load(&this->program);
	if (prog != nullptr)
		prog->wait_for_initialization();
	return prog;
}

VMPoolItem* TenantInstance::vmreserve(bool debug)
{
	try
	{
		auto prog = this->ref(debug);
		if (UNLIKELY(prog == nullptr))
			return nullptr;

		// Reserve a machine through blocking queue.
		// May throw if dequeue from the queue times out.
		Reservation resv = prog->reserve_vm(this, std::move(prog));
		// prog is nullptr after this ^
		return (VMPoolItem*) resv.slot;

	} catch (std::exception& e) {
		this->logf(
			"VM '%s' exception: %s", config.name.c_str(), e.what());
		return nullptr;
	}
}

std::shared_ptr<ProgramInstance> TenantInstance::ref(bool debug)
{
	std::shared_ptr<ProgramInstance> prog;
	if (LIKELY(!debug))
		prog = std::atomic_load(&this->program);
	else
		prog = std::atomic_load(&this->debug_program);
	// First-time tenants could have no program loaded
	if (UNLIKELY(prog == nullptr))
	{
		// Attempt to load the program (if it was never attempted)
		// XXX: But not for debug programs (NOT IMPLEMENTED YET).
		if (debug || this->wait_guarded_initialize(prog) == false)
		{
			this->logf(
				"vmreserve: Missing program for %s. Not uploaded?",
				 config.name.c_str());
			return nullptr;
		}
		// On success, prog is now loaded with the new program.
		// XXX: Assert on prog
	}
	// Avoid reservation while still initializing. Wait for lock.
	// Returns false if the main_vm failed to initialize.
	if (UNLIKELY(!prog->wait_for_main_vm()))
	{
		return nullptr;
	}

	return prog;
}

uint64_t TenantInstance::lookup(const char* name) const {
	auto inst = program;
	if (inst != nullptr)
		return inst->lookup(name);
	return 0x0;
}

#include <unistd.h>
std::vector<uint8_t> file_loader(const std::string& filename)
{
    FILE* f = fopen(filename.c_str(), "rb");
    if (f == NULL) throw std::runtime_error("Could not open file: " + filename);

    fseek(f, 0, SEEK_END);
	const size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);

    std::vector<uint8_t> result(size);
    if (size != fread(result.data(), 1, size, f))
    {
        fclose(f);
        throw std::runtime_error("Error when reading from file: " + filename);
    }
    fclose(f);
    return result;
}

void TenantInstance::serialize_storage_state(
	std::shared_ptr<ProgramInstance>& old,
	std::shared_ptr<ProgramInstance>& inst)
{
	auto old_ser_func =
		old->entry_at(ProgramEntryIndex::LIVEUPD_SERIALIZE);
	auto& tenant = inst->main_vm->tenant();
	if (old_ser_func != 0x0)
	{
		auto new_deser_func =
			inst->entry_at(ProgramEntryIndex::LIVEUPD_DESERIALIZE);
		if (new_deser_func != 0x0)
		{
			tenant.logf(
				"Live-update serialization will be performed");
			long res =
				old->live_update_call(old_ser_func, *inst, new_deser_func);
			tenant.logf(
				 "Transferred %ld bytes", res);
			inst->stats.live_update_transfer_bytes = res;
		} else {
			tenant.logf(
				"Live-update deserialization skipped (new program lacks restorer)");
		}
	} else {
		tenant.logf(
			"Live-update skipped (old program lacks serializer)");
	}
}

void TenantInstance::commit_program_live(
	std::shared_ptr<ProgramInstance>& new_prog) const
{
	std::shared_ptr<ProgramInstance> current;
	/* Make a reference to the current program, keeping it alive */
	if (!new_prog->main_vm->is_debug()) {
		current = std::atomic_load(&this->program);
	} else {
		current = std::atomic_load(&this->debug_program);
	}

	if (current != nullptr) {
		TenantInstance::serialize_storage_state(current, new_prog);
	}

	/* Increment live-update counter from old to new program */
	new_prog->stats.live_updates = current->stats.live_updates + 1;

	/* Swap out old program with new program. */
	if (!new_prog->main_vm->is_debug())
	{
		std::atomic_exchange(&this->program, new_prog);
	} else {
		std::atomic_exchange(&this->debug_program, new_prog);
	}
}

void TenantInstance::reload_program_live(bool debug)
{
	std::shared_ptr<ProgramInstance> null_prog = nullptr;
	std::shared_ptr<ProgramInstance> old_prog;

	/* This will unload the current program. */
	if (!debug) {
		old_prog = std::atomic_load(&this->program);
		std::atomic_exchange(&this->program, null_prog);
	} else {
		old_prog = std::atomic_load(&this->debug_program);
		std::atomic_exchange(&this->debug_program, null_prog);
	}

	/* XXX: There will be a few instances of denied requests.
	   This will cause the current program to be reinitialized
	   upon taking a reference. */
	this->m_started_init = false;

	/* No point in reloading the program if there's nothing to
	   serialize from the old storage to the new. It will be
	   loaded by the first request to it. */
	if (old_prog == nullptr || old_prog->has_storage() == false)
		return;

	/* Take a reference to new program (forcing it to reload). */
	if (auto new_prog = this->ref(debug))
	{
		/* Transfer storage state from old to new program. */
		TenantInstance::serialize_storage_state(old_prog, new_prog);
	}
}

void TenantInstance::logf(const char* fmt, ...) const
{
	char buffer[2048];
	va_list va;
	va_start(va, fmt);
	/* NOTE: vsnprintf has an insane return value. */
	const int len = vsnprintf(buffer, sizeof(buffer), fmt, va);
	va_end(va);
	if (len >= 0 && (size_t)len < sizeof(buffer)) {
		this->do_log(std::string_view{buffer, (size_t)len});
	} else {
		throw std::runtime_error("Log format buffer exceeded");
	}
}

void TenantInstance::do_log(std::string_view data) const
{
	if (m_logger)
		m_logger(const_cast<TenantInstance*>(this), data);
	else
		fprintf(stderr, "%.*s", (int)data.size(), data.begin());
}

} // kvm
