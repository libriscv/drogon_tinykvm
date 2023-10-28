#include <drogon/drogon.h>
#include "sandbox/tenants.hpp"
static constexpr bool USE_RESERVATIONS = true;
using namespace drogon;

extern void kvm_compute(kvm::TenantInstance& tenant,
	const HttpRequestPtr& req, HttpResponsePtr& resp);

static kvm::Tenants tenants;
int main()
{
	tenants.init("tenants.json", false);
	kvm::TenantInstance::set_logger([] (auto* tenant, auto stuff) {
		LOG_WARN << "[" << tenant->config.name << "] " << stuff;
	});
	static auto* default_tenant = tenants.find("test.com");
	assert(default_tenant);

	app().setLogPath("./")
		.setLogLevel(trantor::Logger::kWarn)
		.addListener("127.0.0.1", 8080)
		.setThreadNum(USE_RESERVATIONS ? 160 : 32)
		.registerSyncAdvice(
		[] (const HttpRequestPtr& req) -> HttpResponsePtr {
			auto resp = HttpResponse::newHttpResponse();
			const auto& path = req->path();
			if (path == "/drogon")
			{
				resp->setBody("Hello World!");
				resp->setContentTypeCode(CT_TEXT_PLAIN);
			}
			else if (path == "/drogon/counter")
			{
				static unsigned counter = 0;
				__sync_fetch_and_add(&counter, 1);
				resp->setBody("Hello " + std::to_string(counter) + " World!");
				resp->setContentTypeCode(CT_TEXT_PLAIN);
			}
			else if (path == "/stats")
			{
				nlohmann::json j;
				tenants.foreach([&] (auto* tenant) {
					tenant->gather_stats(j);
				});

				resp->setBody(j.dump());
				resp->setContentTypeCode(CT_APPLICATION_JSON);
			}
			else
			{
				const auto& host = req->getHeader("Host");
				if (host == "127.0.0.1:8080") {
					kvm_compute(*default_tenant, req, resp);
				}
				else if (auto* tenant = tenants.find(host); LIKELY(tenant != nullptr)) {
					kvm_compute(*tenant, req, resp);
				}
				else {
					resp->setStatusCode(k500InternalServerError);
				}
			}
			return resp;
		});
	app().run();
}
