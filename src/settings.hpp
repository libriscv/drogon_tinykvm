#pragma once
#include <string>

struct Settings
{
	bool reservations = false;
	std::string json = "tenants.json";
};
extern Settings g_settings;
