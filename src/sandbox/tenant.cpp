#include "tenants.hpp"

#include "../settings.hpp"
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
	std::string n, std::string f, std::string sf, std::string k,
	TenantGroup grp, std::string uri)
	: name(std::move(n)), hash{crc32c_hw(n)}, group{std::move(grp)},
	  filename(std::move(f)), storage_filename(std::move(sf)), key(std::move(k)),
	  uri(std::move(uri))
{
	this->allowed_file = filename + ".state";
	// Defaults from global settings
	this->group.ephemeral = g_settings.ephemeral;
	if (g_settings.concurrency > 0) {
		this->group.max_concurrency = g_settings.concurrency;
	} else {
		// Use default concurrency
		this->group.max_concurrency = std::thread::hardware_concurrency();
	}
	// If double_buffered is enabled, we need double the concurrency
	if (this->group.double_buffered) {
		this->group.max_concurrency *= 2;
	}
}
TenantConfig::~TenantConfig() {}

static std::string apply_dollar_vars(std::string str)
{
	// Replace $HOME with the home directory
	auto find_home = str.find("$HOME");
	if (find_home != std::string::npos) {
		const char* home = getenv("HOME");
		if (home != nullptr) {
			str.replace(find_home, 5, std::string(home));
		}
	}
	// Replace $PWD with the current working directory
	auto find_pwd = str.find("$PWD");
	if (find_pwd != std::string::npos) {
		char cwd[PATH_MAX];
		if (getcwd(cwd, sizeof(cwd)) != nullptr) {
			str.replace(find_pwd, 4, std::string(cwd));
		}
	}
	return str;
}

bool Tenants::load_tenant(const TenantConfig& config, bool initialize)
{
	try {
		/* Create hash from tenant/program name. */
		const uint32_t hash = crc32c_hw(config.name);

		/* Insert tenant/program as active tenant instance. */
		const auto [it, inserted] =
			this->m_tenants.try_emplace(hash, std::move(config), false);
		if (UNLIKELY(!inserted)) {
			fprintf(stderr,
				"kvm: Tenant '%s' already exists, cannot create again.\n",
				config.name.c_str());
			return false;
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
static void add_remapping(kvm::TenantGroup& group, const std::string& key, const It& obj)
{
	if (!obj.value().is_array() || obj.value().size() < 2) {
		throw std::runtime_error("Remapping must be an array of two elements");
	}
	bool is_storage = false;
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
	if (arr.size() > 2 && arr[2].is_string()) {
		std::string type = arr[2].template get<std::string>();
		if (type == "storage") {
			is_storage = true;
		}
	}

	tinykvm::VirtualRemapping vmem {
		.phys = 0x0,
		.virt = address,
		.size = size << 20U,
		.writable   = true,
		.executable = key == "executable_remapping",
		.blackout   = key == "blackout_area"
	};
	if (is_storage)
		group.storage_remappings.push_back(vmem);
	else
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
	else if (obj.key() == "max_storage_memory" || obj.key() == "storage_memory")
	{
		// Limits the memory of the Storage VM.
		group.max_storage_memory = uint64_t(obj.value()) * 1048576ul;
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
	else if (obj.key() == "cold_start_file")
	{
		group.cold_start_file = apply_dollar_vars(obj.value());
	}
	else if (obj.key() == "dylink_address_hint" || obj.key() == "storage_dylink_address_hint")
	{
		auto& group_hint = obj.key() == "dylink_address_hint" ?
		                 group.dylink_address_hint : group.storage_dylink_address_hint;
		if (obj.value().is_string()) {
			// Parse from hex string
			auto str = obj.value().template get<std::string>();
			if (str.size() > 2 && str[0] == '0' && str[1] == 'x') {
				str = str.substr(2);
			}
			group_hint = std::stoul(str, nullptr, 16);
		} else if (obj.value().is_number()) {
			// Treat as offset in megabytes
			group_hint = uint32_t(obj.value()) * 1048576ul;
		} else {
			throw std::runtime_error(obj.key() + ": Dylink address hint was not a number");
		}
	}
	else if (obj.key() == "heap_address_hint")
	{
		group.heap_address_hint = uint32_t(obj.value()) * 1048576ul;
	}
	else if (obj.key() == "concurrency")
	{
		group.max_concurrency = obj.value();
	}
	else if (obj.key() == "double_buffered")
	{
		group.double_buffered = obj.value();
	}
	else if (obj.key() == "storage")
	{
		group.has_storage = obj.value();
	}
	else if (obj.key() == "storage_1_to_1")
	{
		if (obj.value().is_string()) {
			if (obj.value() == "permanent") {
				group.storage_perm_remote = true;
				group.storage_1_to_1 = true;
			} else {
				throw std::runtime_error("storage_1_to_1 must be a boolean or the string 'permanent'");
			}
		} else {
			group.storage_1_to_1 = obj.value();
		}
	}
	else if (obj.key() == "storage_serialized")
	{
		group.storage_serialized = obj.value();
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
	else if (obj.key() == "main_arguments")
	{
		auto& vec = group.main_arguments;
		vec = std::make_shared<std::vector<std::string>>();
		for (const auto& arg : obj.value()) {
			vec->push_back(apply_dollar_vars(arg.template get<std::string>()));
		}
	}
	else if (obj.key() == "storage_arguments")
	{
		auto& vec = group.storage_arguments;
		vec = std::make_shared<std::vector<std::string>>();
		for (const auto& arg : obj.value()) {
			vec->push_back(apply_dollar_vars(arg.template get<std::string>()));
		}
	}
	else if (obj.key() == "environment")
	{
		// Append environment variables (NOTE: unable to overwrite defaults)
		auto vec = obj.value().template get<std::vector<std::string>>();
		// Replace $HOME with the home directory, if present
		for (auto& it : vec) {
			it = apply_dollar_vars(it);
		}
		group.environ.insert(group.environ.end(), vec.begin(), vec.end());
	}
	else if (obj.key() == "remapping" || obj.key() == "executable_remapping" || obj.key() == "blackout_area")
	{
		if (obj.value().is_array() && obj.value().size() == 2) {
			add_remapping(group, obj.key(), obj);
		} else if (obj.value().is_object()) {
			for (const auto& it : obj.value().items()) {
				add_remapping(group, obj.key(), it);
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
		// Rewrite paths is a JSON array of objects of virtual path to real paths
		if (!obj.value().is_array()) {
			throw std::runtime_error("Allowed paths must be an array of strings/objects");
		}
		auto& arr = obj.value();
		for (const auto& it : arr) {
			TenantGroup::VirtualPath path;
			if (it.is_string()) {
				path.real_path = apply_dollar_vars(it.template get<std::string>());
				path.virtual_path = path.real_path;
			} else if (it.is_object()) {
				// Objects have "virtual" and "real" keys
				if (!it.contains("real")) {
					throw std::runtime_error("Allowed paths must have a real path");
				}
				path.real_path = apply_dollar_vars(it["real"].template get<std::string>());
				if (path.real_path.empty()) {
					throw std::runtime_error("Allowed paths must have a non-empty real path");
				}
				if (it.contains("virtual")) {
					path.virtual_path = it["virtual"].template get<std::string>();
				}
				if (!path.virtual_path.empty()) {
					// Record the index of the virtual path in the allowed paths
					// that contains a specific virtual path.
					group.rewrite_path_indices.insert_or_assign(
						path.virtual_path, group.allowed_paths.size());
				} else {
					// If the virtual path is empty, we will use 1:1 mapping
					path.virtual_path = path.real_path;
				}
				if (it.contains("prefix")) {
					path.prefix = it["prefix"].template get<bool>();
				}
				if (it.contains("writable")) {
					path.writable = it["writable"].template get<bool>();
				} else if (it.contains("symlink")) {
					// A symlink must contain both a real and a virtual path
					if (path.virtual_path.empty()) {
						throw std::runtime_error("Symlink must have a virtual path");
					}
					if (path.real_path.empty()) {
						throw std::runtime_error("Symlink must have a real path");
					}
					// If both real and virtual are the same, it's an error
					if (path.real_path == path.virtual_path) {
						throw std::runtime_error("Symlink must have different real and virtual paths");
					}
					path.symlink = it["symlink"].template get<bool>();
				}
			} else {
				throw std::runtime_error("Allowed paths must be an array of strings/objects");
			}
			group.allowed_paths.push_back(std::move(path));
		}
	}
	else if (obj.key() == "current_working_directory") {
		group.current_working_directory = apply_dollar_vars(obj.value());
	}
	else if (obj.key() == "verbose") {
		group.verbose = obj.value();
	}
	else if (obj.key() == "verbose_syscalls") {
		group.verbose_syscalls = obj.value();
	}
	else if (obj.key() == "verbose_pagetables") {
		group.verbose_pagetable = obj.value();
	}
	else if (obj.key() == "profiling") {
		if (obj.value().is_boolean()) {
			if (obj.value()) {
				// If profiling is globally enabled, enable it for this tenant too
				if (g_settings.profiling) {
					group.profiling_interval = g_settings.profiling_interval;
				} else {
					group.profiling_interval = 1000; // Some default
				}
			} else {
				group.profiling_interval = 0;
			}
		} else if (obj.value().is_number()) {
			// If a number is given, use it as the profiling interval
			group.profiling_interval = obj.value();
		} else {
			throw std::runtime_error("Profiling must be a boolean or a number");
		}
	}
	else if (obj.key() == "server") {
		// Server is an object with path (UNIX socket) or port (TCP socket)
		// and the number of epoll systems to create.
		if (obj.value().is_object()) {
			auto& obj2 = obj.value();
			if (obj2.contains("port")) {
				group.server_port = obj2["port"];
			} else if (obj2.contains("path")) {
				group.server_port = 0;
				group.server_address = obj2["path"];
			} else {
				throw std::runtime_error("Server must have a port or path");
			}
			if (obj2.contains("address")) {
				group.server_address = obj2["address"];
			}
			if (obj2.contains("systems")) {
				group.epoll_systems = obj2["systems"];
			} else {
				group.epoll_systems = 1;
			}
		} else {
			throw std::runtime_error("Server must be an object with at least a port");
		}
	}
	else if (obj.key() == "websocket_server") {
		// Websocket server is an object with a TCP port and the number of
		// websocket systems (threads) to create.
		if (obj.value().is_object()) {
			auto& obj2 = obj.value();
			if (obj2.contains("port")) {
				group.ws_server_port = obj2["port"];
			} else {
				throw std::runtime_error("Websocket server must have a TCP port");
			}
			if (obj2.contains("address")) {
				group.ws_server_address = obj2["address"];
			}
			if (obj2.contains("systems")) {
				group.websocket_systems = obj2["systems"];
			} else {
				group.websocket_systems = 1;
			}
		} else {
			throw std::runtime_error("WebSocket server must be an object with at least a port");
		}
	} else if (obj.key() == "warmup") {
		// Warmup is a designed HTTP request that will be called a given
		// number of times mocking a real request. This is used to warm up the
		// VM before forks are created and it enters real request handling.
		if (obj.value().is_object()) {
			auto& obj2 = obj.value();
			group.warmup = std::make_shared<kvm::TenantGroup::Warmup>();
			if (obj2.contains("num_requests")) {
				group.warmup->num_requests = obj2["num_requests"];
			} else {
				group.warmup->num_requests = 20;
			}
			if (obj2.contains("url")) {
				group.warmup->url = obj2["url"];
			}
			if (obj2.contains("method")) {
				group.warmup->method = obj2["method"];
			}
			if (obj2.contains("headers")) {
				auto& headers = obj2["headers"];
				for (const auto& header : headers) {
					group.warmup->headers.insert(header);
				}
			}
		} else {
			throw std::runtime_error("Warmup must be an object");
		}
	}
	else if (obj.key() == "group") { /* Silently ignore. */ }
	else if (obj.key() == "key")   { /* Silently ignore. */ }
	else if (obj.key() == "uri")   { /* Silently ignore. */ }
	else if (obj.key() == "filename") { /* Silently ignore. */ }
	else if (obj.key() == "storage_filename") { /* Silently ignore. */ }
	else if (obj.key() == "default") { /* Silently ignore. */ }
	else if (obj.key() == "start") { /* Silently ignore. */ }
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
			// If profiling is globally enabled, enable it for this tenant too
			if (g_settings.profiling) {
				group.profiling_interval = g_settings.profiling_interval;
			}
			// If verbose is globally enabled, enable it for this tenant too
			if (g_settings.verbose) {
				group.verbose = true;
				group.verbose_syscalls = true;
			}
			// If double_buffered is globally enabled, enable it for this tenant too
			if (g_settings.double_buffered) {
				group.double_buffered = true;
			}

			/* One tenant can be made default */
			if (obj.contains("default") && obj["default"].is_boolean() && obj["default"]) {
				g_settings.default_tenant = it.key();
			}
			/* Filenames are optional. */
			std::string filename = "";
			if (obj.contains("filename")) filename = apply_dollar_vars(obj["filename"]);
			/* Storage filename is optional. */
			std::string storage_filename = "";
			if (obj.contains("storage_filename")) {
				storage_filename = apply_dollar_vars(obj["storage_filename"]);
			}
			/* Keys are optional. No/empty key = no live update. */
			std::string lvu_key = "";
			if (obj.contains("key")) lvu_key = obj["key"];
			/* URI is used to fetch a program remotely. */
			std::string uri = "";
			if (obj.contains("uri")) uri = obj["uri"];
			/* Verify: No filename and no key is an unreachable program. */
			if (filename.empty() && uri.empty())
				throw std::runtime_error("kvm: Unreachable program " + it.key() + " has no URI or filename");
			/* A program can be configured to start immediately, overriding
			   the default behavior. */
			bool initialize_or_configured_to_start = initialize;
			if (obj.contains("start") && obj["start"].is_boolean()) {
				initialize_or_configured_to_start = obj["start"];
			}

			/* Use the group data except filename */
			this->load_tenant(kvm::TenantConfig{
				it.key(),
				std::move(filename),
				std::move(storage_filename),
				std::move(lvu_key),
				std::move(group),
				std::move(uri)
			}, initialize_or_configured_to_start);
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
