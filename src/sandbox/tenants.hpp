#pragma once
#include "tenant_instance.hpp"
#include <unordered_map>

namespace kvm {
class TenantInstance;

struct Tenants {
	bool init(const std::string& filename, bool init);
	bool init_json(const std::string& filename, std::string_view json, bool init);
	bool init_uri(const std::string& uri, bool init);

	TenantInstance* find(const std::string& name);
	TenantInstance* find_key(const std::string& name, const std::string& key);

	using foreach_t = std::function<void(TenantInstance*)>;
	void foreach(foreach_t);

	bool configure(TenantInstance* ten, const std::string_view json);
	bool main_arguments(TenantInstance* ten, std::vector<std::string> args);

private:
	bool load_tenant(const TenantConfig& config, bool initialize);
	void init_tenants(const std::string_view json_strview, const std::string& source, bool initialize);

	std::unordered_map<uint32_t, TenantInstance> m_tenants;
};

} // kvm
