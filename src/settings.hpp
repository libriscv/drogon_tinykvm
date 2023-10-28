#pragma once
#include <string>
#include <thread>

struct Settings
{
	bool reservations = false;
	bool ephemeral = true;
	bool double_buffered = false;
	bool profiling = false;
	bool verbose = false;
	bool debug_boot = false;
	bool debug_prefork = false;
	int  profiling_interval = 1000;
	int  concurrency = 0;
	std::string json = "tenants.json";
	std::string default_tenant = "test.com";
	std::string host = "127.0.0.1";
	int port = 8080;
	std::string drogon_library_path = "./program/libdrogon.so";

	int num_threads() const {
		if (reservations) {
			return 160; // Fixed number of threads for reservations
		} else if (concurrency > 0) {
			return concurrency;
		} else {
			return std::thread::hardware_concurrency(); // Default to hardware concurrency
		}
	}
};
extern Settings g_settings;
