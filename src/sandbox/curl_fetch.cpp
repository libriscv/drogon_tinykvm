#include "curl_fetch.hpp"

#include <curl/curl.h>
#include <cstring>
#include <exception>
#include <malloc.h>
typedef size_t (*write_callback)(char *, size_t, size_t, void *);
typedef void (*internal_curl_callback)(void *usr, long status, kvm::MemoryStruct *chunk);

namespace kvm
{

extern "C" size_t
kvm_WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
	const size_t realsize = size * nmemb;
	MemoryStruct *mem = (MemoryStruct *)userp;

	char *ptr = (char *)realloc(mem->memory, mem->size + realsize + 1);
	if (!ptr) {
		/* Out of memory! Let's not try to print or log anything. */
		free(mem->memory);
		mem->memory = NULL;
		mem->size = 0;
		return 0;
	}

	mem->memory = ptr;
	memcpy(&(mem->memory[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = 0;

	return realsize;
}

int curl_fetch(
	const std::string& url, kvm_curl_callback callback, const char *condhdr)
{
	struct curl_slist *req_list = NULL;
	int retvalue = -1;

	MemoryStruct chunk {
		.memory = (char *)malloc(1),
		.size = 0
	};
	if (chunk.memory == NULL || url.size() < 8u) {
		return (-1);
	}

	CURL *curl = curl_easy_init();
	curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, (write_callback)kvm_WriteMemoryCallback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &chunk);

	const bool is_http = (memcmp(url.c_str(), "http", 4) == 0);
	if (is_http)
	{
		/* Many URLs go straight to redirects, and it is disabled by default. */
		curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);

		if (condhdr != nullptr && condhdr[0] != 0) {
			//printf("Adding header: %s\n", condhdr);
			req_list = curl_slist_append(req_list, condhdr);
			curl_easy_setopt(curl, CURLOPT_HTTPHEADER, req_list);
		}
	}

	CURLcode res = curl_easy_perform(curl);

	long status;
	if (is_http) {
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
	} else {
		status = (res == CURLE_OK) ? 200 : -1;
	}

	curl_slist_free_all(req_list);
	curl_easy_cleanup(curl);

	if (res != CURLE_OK) {
		fprintf(stderr,
			"kvm.curl_fetch(): cURL failed for '%s': %s\n", url.c_str(), curl_easy_strerror(res));
		retvalue = -1;
	}
	else {
		try {
			callback(status, &chunk);
			retvalue = 0;
		}
		catch (const std::exception& e) {
			fprintf(stderr,
				"kvm.curl_fetch(): cURL failed: %s\n", e.what());
			retvalue = -1;
		}
	}

	free(chunk.memory);

	return (retvalue);
}

} // kvm
