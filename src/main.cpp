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
	fprintf(stderr, "  --reservations|-r    Enable reservations\n");
	fprintf(stderr, "  --concurrency|-c <n> Set concurrent VMs per tenant\n");
	fprintf(stderr, "  --config <file>      Specify JSON configuration file (default: tenants.json)\n");
	fprintf(stderr, "  --default|-d         Set default tenant (default: test.com)\n");
	fprintf(stderr, "  --debug-boot         Start remote GDB at boot\n");
	fprintf(stderr, "  --debug-prefork      Start remote GDB just before forking VMs\n");
	fprintf(stderr, "  --ephemeral|-e       Enable ephemeral VMs (default: true)\n");
	fprintf(stderr, "  --no-ephemeral       Disable ephemeral VMs\n");
	fprintf(stderr, "  --double-buffered    Enable double-buffered VM resets (default: false)\n");
	fprintf(stderr, "  --profiling|-p       Enable profiling (default: false)\n");
	fprintf(stderr, "  --verbose|-v         Enable verbose output (default: false)\n");
	fprintf(stderr, "  --help               Show this help message\n");
	exit(1);
}

static void init_settings(int argc, char** argv)
{
	g_settings.drogon_library_path = std::filesystem::current_path().string() + "/program/libdrogon.so";
	g_settings.reservations = false;

	// Parse command line arguments
	for (int i = 1; i < argc; ++i) {
		std::string arg = argv[i];
		if (arg == "--reservations" || arg == "-r") {
			g_settings.reservations = true;
		}
		else if (arg == "--json" || arg == "--config") {
			if (i + 1 < argc) {
				g_settings.json = argv[++i];
			}
		} else if (arg == "--default" || arg == "-d") {
			if (i + 1 < argc) {
				g_settings.default_tenant = argv[++i];
			}
		} else if (arg == "--concurrency" || arg == "-c") {
			if (i + 1 < argc) {
				g_settings.concurrency = std::stoi(argv[++i]);
			}
		} else if (arg == "--debug-boot") {
			g_settings.debug_boot = true;
		} else if (arg == "--debug-prefork") {
			g_settings.debug_prefork = true;
		} else if (arg == "--ephemeral" || arg == "-e") {
			g_settings.ephemeral = true;
		} else if (arg == "--no-ephemeral") {
			g_settings.ephemeral = false;
		} else if (arg == "--double-buffered") {
			g_settings.double_buffered = true;
		} else if (arg == "--profiling" || arg == "-p") {
			g_settings.profiling = true;
		} else if (arg == "--verbose" || arg == "-v") {
			g_settings.verbose = true;
		} else if (arg == "--help" || arg == "-h") {
			usage(argv[0]);
		} else {
			// Unknown argument
			fprintf(stderr, "Unknown argument: %s\n", arg.c_str());
			usage(argv[0]);
		}
	}
}

static kvm::Tenants tenants;
int main(int argc, char** argv)
{
	init_settings(argc, argv);
	tenants.init(g_settings.json, false);

	printf("* Reservations: %s\n", g_settings.reservations ? "enabled" : "disabled");
	printf("* JSON config file: %s\n", g_settings.json.c_str());
	printf("* Default tenant: %s\n", g_settings.default_tenant.c_str());
	printf("* Ephemeral VMs: %s\n", g_settings.ephemeral ? "enabled" : "disabled");
	const char* dbs = g_settings.double_buffered ? " double-buffered" : "";
	if (g_settings.concurrency > 0) {
		printf("* Tenant concurrency: %d%s (override)\n", g_settings.concurrency, dbs);
	} else {
		printf("* Tenant concurrency: hardware specified (%u)%s\n", std::thread::hardware_concurrency(), dbs);
	}

	kvm::TenantInstance::set_logger([] (auto* tenant, auto stuff) {
		LOG_WARN << "[" << tenant->config.name << "] " << stuff;
	});
	static auto* default_tenant = tenants.find(g_settings.default_tenant);
	if (default_tenant == nullptr) {
		fprintf(stderr, "kvm: Default tenant '%s' not found\n",
			g_settings.default_tenant.c_str());
		return 1;
	}

	app().setLogPath("./")
		.setLogLevel(trantor::Logger::kWarn)
		.addListener(g_settings.host, g_settings.port)
		.setThreadNum(g_settings.num_threads())
		.registerSyncAdvice(
		[] (const HttpRequestPtr& req) -> HttpResponsePtr {
			auto resp = HttpResponse::newHttpResponse();
			const auto& path = req->path();
			if (path == "/drogon")
			{
				resp->setBody("Hello World!");
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
				if (auto* tenant = tenants.find(host); LIKELY(tenant != nullptr)) {
					kvm_compute(*tenant, req, resp);
				}
				else if (host == "127.0.0.1:8080") {
					kvm_compute(*default_tenant, req, resp);
				}
				else {
					resp->setBody("No such tenant: " + host);
					resp->setStatusCode(k500InternalServerError);
				}
			}
			return resp;
		});
	uint64_t rss = 0;
	FILE *f = fopen("/proc/self/statm", "r");
	if (f) {
		uint64_t pages;
		if (fscanf(f, "%*s %lu", &pages) == 1) {
			rss = pages * 4096 / 1024 / 1024;
		}
		fclose(f);
	}
	printf("* Server started on %s:%d (RSS: %lu MiB, threads: %d)\n",
		g_settings.host.c_str(), g_settings.port,
		rss,
		g_settings.num_threads());
	app().run();
}
