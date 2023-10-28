#include "live_update.hpp"

#include "tenant_instance.hpp"
#include "program_instance.hpp"
#include <atomic>

namespace kvm {
bool file_writer(const std::string& file, const std::vector<uint8_t>&);

static LiveUpdateResult update_result(const std::string& text, bool success) {
	return { text, success };
}

LiveUpdateResult TenantInstance::live_update(const LiveUpdateParams& params)
{
	/* ELF loader will not be run for empty binary */
	if (UNLIKELY(params.binary.empty())) {
		return update_result("Empty file received", false);
	}
	try {
	#ifdef ENABLE_TIMING
		TIMING_LOCATION(t0);
	#endif
		/* If this throws an exception, we instantly fail the update */
		auto inst = std::make_shared<ProgramInstance>(
			params.binary, params.binary, this, params.is_debug);
		const auto& live_binary = inst->request_binary;

		/* Complex dance to replace the currently running program */
		inst->wait_for_initialization();
		this->commit_program_live(inst);

	#ifdef ENABLE_TIMING
		TIMING_LOCATION(t1);
		printf("Time spent updating: %ld ns\n", nanodiff(t0, t1));
	#endif
		/* Don't save debug binaries and empty filenames. */
		const auto& filename = this->config.request_program_filename();
		if (!params.is_debug && !filename.empty())
		{
			/* Filename is not empty, so we can now check to see if it's a URI. */
			if (filename.at(0) != '/' || filename.find("://") != std::string::npos) {
				/* It is not an absolute path, or it is a URI.
				   Still a success, but we choose not to store locally. */
				return update_result("Update successful (not stored)\n", true);
			}
			/* If we arrive here, the initialization was successful,
			   and we can proceed to store the program to disk. */
			bool ok = kvm::file_writer(filename, live_binary.to_vector());
			if (!ok) {
				/* Writing the tenant program to file failed */
				return update_result("Update successful, but could not persist to '" + filename + "'", true);
			}
		}
		return update_result("Update successful (stored)\n", true);
	} catch (const tinykvm::MachineException& e) {
		/* Pass machine error back to the client */
		char buffer[2048];
		snprintf(buffer, sizeof(buffer),
			"Machine exception: %s (data: 0x%lX)\n", e.what(), e.data());
		return update_result(buffer, false);
	} catch (const std::exception& e) {
		/* Pass unknown error back to the client */
		return update_result(e.what(), false);
	}
}

bool file_writer(const std::string& filename, const std::vector<uint8_t>& binary)
{
	FILE* f = fopen(filename.c_str(), "wb");
	if (f == NULL)
		return false;

	const size_t n = fwrite(binary.data(), 1, binary.size(), f);
	fclose(f);
	return n == binary.size();
}

} // kvm
