#include <drogon/drogon.h>
#include "sandbox/tenants.hpp"
#include "settings.hpp"
Settings g_settings;
using namespace drogon;

extern void kvm_compute(kvm::TenantInstance& tenant,
	const HttpRequestPtr& req, HttpResponsePtr& resp);

static void usage(const char* progname)
{
	fprintf(stderr, "Usage: %s [options]\n", progname);
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  --reservations       Enable reservations\n");
	fprintf(stderr, "  --json <file>        Specify JSON configuration file (default: tenants.json)\n");
	exit(1);
}

static void init_settings(int argc, char** argv)
{
	g_settings.reservations = false;

	// Parse command line arguments
	for (int i = 1; i < argc; ++i) {
		std::string arg = argv[i];
		if (arg == "--reservations") {
			g_settings.reservations = true;
		}
		else if (arg == "--json") {
			if (i + 1 < argc) {
				g_settings.json = argv[++i];
			}
		} else {
			// Unknown argument
			fprintf(stderr, "Unknown argument: %s\n", arg.c_str());
			usage(argv[0]);
		}
	}

	printf("* Reservations: %s\n", g_settings.reservations ? "enabled" : "disabled");
	printf("* JSON config file: %s\n", g_settings.json.c_str());
}

static kvm::Tenants tenants;
int main(int argc, char** argv)
{
	init_settings(argc, argv);
	tenants.init(g_settings.json, false);
	kvm::TenantInstance::set_logger([] (auto* tenant, auto stuff) {
		LOG_WARN << "[" << tenant->config.name << "] " << stuff;
	});
	static auto* default_tenant = tenants.find("test.com");
	assert(default_tenant);

	app().setLogPath("./")
		.setLogLevel(trantor::Logger::kWarn)
		.addListener("127.0.0.1", 8080)
		.setThreadNum(g_settings.reservations ? 160 : 0)
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
