#pragma once
#include <string>

struct Settings
{
	bool reservations = false;
	bool ephemeral = true;
	bool profiling = false;
	int  profiling_interval = 1000;
	int  concurrency = 0;
	std::string json = "tenants.json";
	std::string default_tenant = "test.com";
};
extern Settings g_settings;
