#include "tenants.hpp"

#include "common_defs.hpp"
#include "curl_fetch.hpp"
#include "tenant_instance.hpp"
#include "utils/crc32.hpp"
#include <string_view>
#include <thread>
#include <nlohmann/json.hpp>
#define KVM_TENANTS_MAGIC  0xc465573f
using json = nlohmann::json;

namespace kvm {
extern std::vector<uint8_t> file_loader(const std::string&);
const std::string TenantConfig::guest_state_file = "state";

TenantConfig::TenantConfig(
	std::string n, std::string f, std::string k,
	TenantGroup grp, std::string uri)
	: name(std::move(n)), hash{crc32c_hw(n)}, group{std::move(grp)},
	  filename(std::move(f)), key(std::move(k)),
	  uri(std::move(uri))
{
	this->allowed_file = filename + ".state";
}
TenantConfig::~TenantConfig() {}

bool Tenants::load_tenant(const TenantConfig& config, bool initialize)
{
	try {
		/* Create hash from tenant/program name. */
		const uint32_t hash = crc32c_hw(config.name);

		/* Insert tenant/program as active tenant instance. */
		const auto [it, inserted] =
			this->m_tenants.try_emplace(hash, std::move(config), false);
		if (UNLIKELY(!inserted)) {
			throw std::runtime_error("Tenant already existed: " + config.name);
		}
		/* If initialization needed, create program immediately. */
		if (initialize) {
			it->second.begin_initialize();
		}
		return true;

	} catch (const std::exception& e) {
		fprintf(stderr,
			"kvm: Exception when creating tenant '%s': %s",
			config.name.c_str(), e.what());
		return false;
	}
}

template <typename It>
static void add_remapping(kvm::TenantGroup& group, const It& obj)
{
	if (!obj.value().is_array() || obj.value().size() != 2) {
		throw std::runtime_error("Remapping must be an array of two elements");
	}
	// Reset errno
	errno = 0;
	// Append remappings
	auto& arr = obj.value();
	size_t size = 0;
	char *end;
	unsigned long long address = strtoull(arr[0].template get<std::string>().c_str(), &end, 16);
	if (address < 0x20000) {
		throw std::runtime_error("Remapping address was not a number, or invalid");
	} else if (errno != 0) {
		throw std::runtime_error("Remapping does not fit in 64-bit address");
	}

	if (arr[1].is_string()) {
		// Allow for string representation of size, in which case it's the end address
		size = strtoull(arr[1].template get<std::string>().c_str(), &end, 16);
		if (size < address) {
			throw std::runtime_error("Remapping size was not a number, or is smaller than address");
		} else if (errno != 0) {
			throw std::runtime_error("Remapping does not fit in 64-bit address");
		}
		// Calculate size from address
		size = (size - address) >> 20U;
	} else {
		// Allow for integer representation of size, in which case it's the size in MiB
		size = arr[1].template get<size_t>();
	}

	tinykvm::VirtualRemapping vmem {
		.phys = 0x0,
		.virt = address,
		.size = size << 20U,
		.writable   = true,
		.executable = obj.key() == "executable_remapping",
		.blackout   = obj.key() == "blackout_area"
	};
	group.vmem_remappings.push_back(vmem);
}

template <typename It>
static void configure_group(const std::string& name, kvm::TenantGroup& group, const It& obj)
{
	// All group parameters are treated as optional and can be defined in a
	// tenant configuration or in a group configuration.
	if (obj.key() == "max_boot_time")
	{
		group.max_boot_time = obj.value();
	}
	else if (obj.key() == "max_request_time")
	{
		group.max_req_time = obj.value();
	}
	else if (obj.key() == "max_storage_time")
	{
		group.max_req_time = obj.value();
	}
	else if (obj.key() == "max_memory")
	{
		// Limits the memory of the Main VM.
		group.set_max_memory(obj.value());
	}
	else if (obj.key() == "address_space")
	{
		// Limits the address space of the Main VM.
		group.set_max_address(obj.value());
	}
	else if (obj.key() == "max_request_memory")
	{
		// Limits the memory of an ephemeral VM. Ephemeral VMs are used to handle
		// requests (and faults in pages one by one using CoW). They are based
		// off of the bigger Main VMs which use "max_memory" (and are identity-mapped).
		group.set_max_workmem(obj.value());
	}
	else if (obj.key() == "req_mem_limit_after_reset")
	{
		// Limits the memory of an ephemeral VM after request completion.
		// Without a limit, the request memory is kept in order to make future
		// requests faster due to not having to create memory banks.
		group.set_limit_workmem_after_req(obj.value());
	}
	else if (obj.key() == "shared_memory")
	{
		// Sets the size of shared memory between VMs.
		// Cannot be larger than half of max memory.
		group.set_shared_mem(obj.value());
	}
	else if (obj.key() == "concurrency")
	{
		group.max_concurrency = obj.value();
	}
	else if (obj.key() == "storage")
	{
		group.has_storage = obj.value();
	}
	else if (obj.key() == "hugepages")
	{
		group.hugepages = obj.value();
	}
	else if (obj.key() == "hugepage_arena_size")
	{
		group.hugepage_arena_size = uint32_t(obj.value()) * 1048576ul;
		if (group.hugepage_arena_size < 0x200000L && group.hugepage_arena_size != 0) {
			throw std::runtime_error("Hugepage arena size must be at least 2MB");
		}
		if (group.hugepage_arena_size > 512ULL * 1024 * 1024 * 1024) {
			throw std::runtime_error("Hugepage arena size must be less than 512GB");
		}
		if (group.hugepage_arena_size % 0x200000L != 0) {
			throw std::runtime_error("Hugepage arena size must be a multiple of 2MB");
		}
		// Enable hugepages if arena size is set
		group.hugepages = group.hugepage_arena_size != 0;
	}
	else if (obj.key() == "request_hugepages" || obj.key() == "request_hugepage_arena_size")
	{
		group.hugepage_requests_arena = uint32_t(obj.value()) * 1048576ul;
		if (group.hugepage_requests_arena < 0x200000L && group.hugepage_requests_arena != 0) {
			throw std::runtime_error("Hugepage requests arena size must be at least 2MB");
		}
		if (group.hugepage_requests_arena > 512ULL * 1024 * 1024 * 1024) {
			throw std::runtime_error("Hugepage requests arena size must be less than 512GB");
		}
		if (group.hugepage_requests_arena % 0x200000L != 0) {
			throw std::runtime_error("Hugepage requests arena size must be a multiple of 2MB");
		}
	}
	else if (obj.key() == "split_hugepages")
	{
		group.split_hugepages = obj.value();
	}
	else if (obj.key() == "transparent_hugepages")
	{
		group.transparent_hugepages = obj.value();
	}
	else if (obj.key() == "stdout")
	{
		group.print_stdout = obj.value();
	}
	else if (obj.key() == "smp")
	{
		group.max_smp = obj.value();
		// TinyKVM does not support more than 16 extra vCPUs (for now)
		group.max_smp = std::min(size_t(16), group.max_smp);
	}
	else if (obj.key() == "allow_debug")
	{
		group.allow_debug = obj.value();
	}
	else if (obj.key() == "remote_debug_on_exception")
	{
		group.remote_debug_on_exception = obj.value();
	}
	else if (obj.key() == "control_ephemeral")
	{
		// Allow guest to control ephemeral using system call
		group.control_ephemeral = obj.value();
	}
	else if (obj.key() == "ephemeral")
	{
		// Set the default ephemeralness for this group/tenant
		group.ephemeral = obj.value();
	}
	else if (obj.key() == "ephemeral_keep_working_memory")
	{
		// A combination of ephemeral and keep_working_memory, which
		// is a common mode for larger programs. Ephemeral can only
		// be set to true. Only 'ephemeral_keep_working_memory' can be toggled.
		group.ephemeral = group.ephemeral || obj.value();
		group.ephemeral_keep_working_memory = obj.value();
	}
	else if (obj.key() == "experimental_keep_working_memory")
	{
		group.ephemeral_keep_working_memory = obj.value();
	}
	else if (obj.key() == "relocate_fixed_mmap")
	{
		// Force fixed mmap to be relocated to current mmap address
		group.relocate_fixed_mmap = obj.value();
	}
	else if (obj.key() == "main_arguments")
	{
		auto& vec = group.main_arguments;
		vec = std::make_shared<std::vector<std::string>>();
		for (const auto& arg : obj.value()) {
			vec->push_back(arg);
		}
	}
	else if (obj.key() == "environment")
	{
		// Append environment variables (NOTE: unable to overwrite defaults)
		auto vec = obj.value().template get<std::vector<std::string>>();
		group.environ.insert(group.environ.end(), vec.begin(), vec.end());
	}
	else if (obj.key() == "remapping" || obj.key() == "executable_remapping" || obj.key() == "blackout_area")
	{
		if (obj.value().is_array() && obj.value().size() == 2) {
			add_remapping(group, obj);
		} else if (obj.value().is_object()) {
			for (const auto& it : obj.value().items()) {
				add_remapping(group, it);
			}
		} else {
			throw std::runtime_error("Remapping must be an array of two elements or an object");
		}
	}
	else if (obj.key() == "executable_heap")
	{
		group.vmem_heap_executable = obj.value();
	}
	else if (obj.key() == "allowed_paths")
	{
		group.allowed_paths = obj.value().template get<std::vector<std::string>>();
	}
	else if (obj.key() == "verbose") {
		group.verbose = obj.value();
	}
	else if (obj.key() == "verbose_pagetables") {
		group.verbose_pagetable = obj.value();
	}
	else if (obj.key() == "server") {
		// Server is an object with port
		// and address. The address is optional.
		if (obj.value().is_object()) {
			auto& obj2 = obj.value();
			if (obj2.contains("port")) {
				group.server_port = obj2["port"];
			} else {
				throw std::runtime_error("Server must have a port");
			}
			if (obj2.contains("address")) {
				group.server_address = obj2["address"];
			}
		} else {
			throw std::runtime_error("Server must be an object with at least a port");
		}
	}
	else if (obj.key() == "group") { /* Silently ignore. */ }
	else if (obj.key() == "key")   { /* Silently ignore. */ }
	else if (obj.key() == "uri")   { /* Silently ignore. */ }
	else if (obj.key() == "filename") { /* Silently ignore. */ }
	else
	{
		fprintf(stderr,
			"kvm: Unknown configuration key for '%s': %s\n",
			name.c_str(), obj.key().c_str());
	}
}

/* This function is not strictly necessary - we are just trying to find the intention of
   the user. If any of these are present, we believe the intention of the user is to
   create a program definition. However, if group is missing, it is ultimately incomplete. */
template <typename T>
static inline bool is_tenant(const T& obj)
{
	return obj.contains("group") || obj.contains("filename") || obj.contains("uri");
}

void Tenants::init_tenants(
	const std::string_view json_strview, const std::string& source, bool initialize)
{
	(void) source;
	/* Parse JSON with comments enabled. */
	const json j = json::parse(json_strview.begin(), json_strview.end(), nullptr, true, true);

	// The 'compute' group is automatically created using defaults
	std::map<std::string, kvm::TenantGroup> groups { {"compute", kvm::TenantGroup{"compute"}} };

	for (const auto& it : j.items())
	{
		const auto& obj = it.value();
		if (is_tenant(obj)) continue;

		const auto& grname = it.key();
		auto grit = groups.find(grname);

		if (grit == groups.end()) {
			const auto& ret = groups.emplace(
				std::piecewise_construct,
				std::forward_as_tuple(grname),
				std::forward_as_tuple(grname));
			grit = ret.first;
		}
		auto& group = grit->second;

		// Set group settings
		for (auto it = obj.begin(); it != obj.end(); ++it) {
			configure_group(grname, group, it);
		}
	}
	for (const auto& it : j.items())
	{
		const auto& obj = it.value();
		// Tenant configuration
		if (is_tenant(obj))
		{
			const std::string grname =
				!obj.contains("group") ? "compute" : obj["group"];
			auto grit = groups.find(grname);
			if (UNLIKELY(grit == groups.end())) {
				throw std::runtime_error("Could not find group " + grname + " for '" + it.key() + "'");
			}
			// Make a copy of the selected group
			auto group = grit->second;

			// Override both group and tenant settings in one place
			for (auto it = obj.begin(); it != obj.end(); ++it) {
				configure_group(grname, group, it);
			}

			/* Filenames are optional. */
			std::string filename = "";
			if (obj.contains("filename")) filename = obj["filename"];
			/* Keys are optional. No/empty key = no live update. */
			std::string lvu_key = "";
			if (obj.contains("key")) lvu_key = obj["key"];
			/* URI is used to fetch a program remotely. */
			std::string uri = "";
			if (obj.contains("uri")) uri = obj["uri"];
			/* Verify: No filename and no key is an unreachable program. */
			if (filename.empty() && uri.empty())
				throw std::runtime_error("kvm: Unreachable program " + it.key() + " has no URI or filename");

			/* Use the group data except filename */
			this->load_tenant(kvm::TenantConfig{
				it.key(),
				std::move(filename),
				std::move(lvu_key),
				std::move(group),
				std::move(uri)
			}, initialize);
		}
	}

	/* Skip initialization here if not @initialize.
	   NOTE: Early return.  */
	if (initialize == false)
		return;

	/* Finish initialization, but do not bail if program
		initialization fails. It is a recoverable error. */
	for (auto& it : this->m_tenants) {
		auto& tenant = it.second;
		try {
			tenant.wait_for_initialization();
		}
		catch (const std::exception &e) {
			fprintf(stderr,
				"Exception when creating machine '%s' from source '%s': %s\n",
				tenant.config.name.c_str(), tenant.config.filename.c_str(), e.what());
			/* XXX: This can be racy if the same tenant is specified
				more than once, and is still initializing... */
			tenant.program = nullptr;
		}
	}
}

TenantInstance* Tenants::find(const std::string& name)
{
	const uint32_t hash = kvm::crc32c_hw(name.c_str(), name.size());
	// regular tenants
	auto it = this->m_tenants.find(hash);
	if (LIKELY(it != this->m_tenants.end()))
		return &it->second;
	return nullptr;
}

void Tenants::foreach(foreach_t func)
{
	for (auto& it : this->m_tenants) {
		func(&it.second);
	}
}

TenantInstance* Tenants::find_key(const std::string& name, const std::string& key)
{
	auto* tenant = this->find(name);
	if (tenant != nullptr) {
		if (tenant->config.key == key) return tenant;
	}
	return nullptr;
}

bool Tenants::init_json(const std::string& filename, std::string_view json, bool init)
{
	/* Load tenants from a JSON string, with the filename used for logging purposes. */
	try {
		this->init_tenants(json, filename, init);
		return true;
	} catch (const std::exception& e) {
		fprintf(stderr,
			"kvm: Exception when loading tenants from string '%s': %s\n",
			filename.c_str(), e.what());
		return false;
	}
}

bool Tenants::init(const std::string& filename, bool init)
{
	/* Load tenants from a local JSON file. */
	try {
		const auto json = kvm::file_loader(filename);
		const std::string_view json_strview {(const char *)json.data(), json.size()};
		this->init_tenants(json_strview, filename, init);
		return true;
	} catch (const std::exception& e) {
		fprintf(stderr,
			"kvm: Exception when loading tenants from file '%s': %s\n",
			filename.c_str(), e.what());
		return false;
	}
}


bool Tenants::init_uri(const std::string& uri, bool init)
{
	/* Load tenants from a remote JSON file. */
	long res = curl_fetch(uri,
	[&] (long, struct MemoryStruct *chunk) {
		const std::string_view json { chunk->memory, chunk->size };
		try {
			this->init_tenants(json, uri, init);
		} catch (const std::exception& e) {
			fprintf(stderr,
				"kvm: Exception when loading tenants from URI '%s': %s\n",
				uri.c_str(), e.what());
		}
	});
	return (res == 0);
}

bool Tenants::configure(TenantInstance* ten, const std::string_view json)
{
	/* Override program configuration from a JSON string. */
	try {
		/* Parse JSON with comments enabled. */
		const auto j = nlohmann::json::parse(json.begin(), json.end(), nullptr, true, true);
		/* Iterate through all elements, pass to tenants "group" config. */
		for (auto it = j.begin(); it != j.end(); ++it) {
			kvm::configure_group(ten->config.name, ten->config.group, it);
		}
		return true;
	} catch (const std::exception& e) {
		fprintf(stderr,
			"kvm: Exception when overriding program configuration '%s': %s\n",
			ten->config.name.c_str(), e.what());
		fprintf(stderr, "JSON: %s\n", json.begin());
		return false;
	}
}

bool Tenants::main_arguments(TenantInstance* ten, std::vector<std::string> args)
{
	/* Set program main() argument from a string. */
	try {
		auto vec = std::make_shared<std::vector<std::string>> (std::move(args));
		std::atomic_exchange(&ten->config.group.main_arguments, vec);
		return true;
	} catch (const std::exception& e) {
		fprintf(stderr,
			"kvm: Exception when adding program argument '%s': %s\n",
			ten->config.name.c_str(), e.what());
		return false;
	}
}

} // kvm
