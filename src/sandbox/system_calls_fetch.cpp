#include <curl/curl.h>

#include <atomic>
#include <string>
#include "kvm_settings.h"

namespace kvm {
typedef size_t (*read_callback)(char *buffer, size_t size, size_t nitems, void *);
typedef size_t (*write_callback)(char *, size_t, size_t, void *);
typedef size_t (*header_callback)(char *buffer, size_t size, size_t nitems, void *);

static constexpr bool GLOBAL_CURL_ALTSVC_CACHE = false;
static constexpr size_t CURL_REQ_URL_MAX_LENGTH = 1024u;
static constexpr size_t CURL_RESP_HEADERS_MIN_LENGTH = 64;
static constexpr size_t CONTENT_TYPE_LEN = 128;
static constexpr size_t CURL_FIELDS_NUM = 12;
/* We can over-allocate the buffer because we are immediately
	relaxing it after finishing the fetch operation. */
static constexpr uint64_t CURL_BUFFER_MAX = 256UL * 1024UL * 1024UL;
/* The current self-request URI */
static std::string self_request_uri = "";
static std::string self_request_prefix = "http://127.0.0.1:6081";
static std::atomic_int self_request_concurrency {0};

struct writeop {
	tinykvm::Machine& machine;
	uint64_t dst;
	uint64_t max_addr;
};
struct readop {
	tinykvm::Machine* machine;
	uint64_t src;
	size_t   bytes;
};
struct curl_options {
	uint64_t  interface;
	uint64_t  unused;
	int8_t    follow_location; /* Follow Location in 301. */
	int8_t    dummy_fetch;    /* Does not allocate content. */
	int8_t    tcp_fast_open;  /* Enables TCP Fast Open. */
	int8_t    dont_verify_host;
	uint32_t  unused_opt5;
};
struct opfields {
	uint64_t addr[CURL_FIELDS_NUM];
	uint16_t len[CURL_FIELDS_NUM];
};
struct opresult {
	uint32_t status;
	uint32_t post_buflen;
	uint64_t post_addr;
	uint64_t headers;
	uint32_t headers_length;
	uint32_t unused1;
	uint64_t content_addr;
	uint32_t content_length;
	uint32_t ct_length;
	char     ctype[CONTENT_TYPE_LEN];
};

static void syscall_curl_fetch_helper(
	vCPU& vcpu, MachineInstance& inst,
	const std::string& url,
	const uint64_t op_buffer,
	const uint64_t fields_buffer,
	const uint64_t options_buffer,
	const std::string& unix_path)
{
	auto& regs = vcpu.registers();
	const int CONN_TIMEOUT = 5;
	const int READ_TIMEOUT = 8;
	bool is_self_request = false;

	opresult opres;
	vcpu.machine().copy_from_guest(&opres, op_buffer, sizeof(opresult));

	// Retrieve request header fields into string vector
	std::array<std::string, CURL_FIELDS_NUM> fields;
	if (fields_buffer != 0x0) {
		struct opfields of;
		vcpu.machine().copy_from_guest(&of, fields_buffer, sizeof(of));
		/* Iterate through all the request fields. */
		for (size_t i = 0; i < CURL_FIELDS_NUM; i++) {
			if (of.addr[i] != 0x0 && of.len[i] != 0x0) {
				// Add to our temporary request field vector
				fields[i].resize(of.len[i]);
				vcpu.machine().copy_from_guest(fields[i].data(), of.addr[i], of.len[i]);
			}
		}
	}

	// XXX: Fixme, mmap is basic/unreliable
	bool managed_content_addr = false;
	if (opres.content_addr == 0x0) {
		opres.content_addr = vcpu.machine().mmap_allocate(CURL_BUFFER_MAX);
		opres.content_length = CURL_BUFFER_MAX;
		managed_content_addr = true;
	}
	const bool is_post = (opres.post_addr != 0x0 && opres.post_buflen != 0x0);

	inst.logf("Fetch: %s (%s, %s)", url.c_str(),
		unix_path.empty() ? "TCP" : "UNIX",
		is_post ? "POST" : "GET");

	/* We need to read the first character for Unix Domain Sockets. */
	if (UNLIKELY(url.empty()))
	{
		regs.rax = -CURLE_URL_MALFORMAT;
		vcpu.set_registers(regs);
		return;
	}

	writeop op {
		.machine = vcpu.machine(),
		.dst     = opres.content_addr,
		.max_addr = std::max(opres.content_addr, opres.content_addr + opres.content_length)
	};

	// NOTE: Up to this point we have not created anything that could leak,
	// so it is ok to not handle exceptions. After this we will need to start
	// destroying cURL resources after throw exceptions.
	CURL *curl = curl_easy_init();
	struct curl_slist *req_list = NULL;
	struct curl_slist *post_list = NULL;
	std::string headers;
	try
	{
#ifdef CURLOPT_ALTSVC
		if constexpr (GLOBAL_CURL_ALTSVC_CACHE) {
			/* The cache file ends up in the current directory, which is fine. */
			curl_easy_setopt(curl, CURLOPT_ALTSVC, "altsvc-cache.txt");
			curl_easy_setopt(curl, CURLOPT_ALTSVC_CTRL,
				(long) CURLALTSVC_H1|CURLALTSVC_H2|CURLALTSVC_H3);
		}
#endif

		if (!unix_path.empty())
		{
			is_self_request = true;

			if (kvm::self_request_concurrency++ >= kvm_settings.self_request_max_concurrency)
			{
				kvm::self_request_concurrency--;
				throw std::runtime_error("Max self-request concurrency reached");
			}

			if (int err = curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, unix_path.c_str()) != CURLE_OK) {
				inst.logf("Fetch: UDS path error %d for: %s", err, url.c_str());
				regs.rax = -err;
				vcpu.set_registers(regs);
				return;
			}
		}

		if (int err = curl_easy_setopt(curl, CURLOPT_URL, url.c_str()) != CURLE_OK) {
			inst.logf("Fetch: URL error %d for URL: %s", err, url.c_str());
			regs.rax = -err;
			vcpu.set_registers(regs);
			return;
		}

		curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, CONN_TIMEOUT);
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, READ_TIMEOUT); /* Seconds */
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, (write_callback)
		[] (char *ptr, size_t size, size_t nmemb, void *poop) -> size_t {
			auto& woop = *(writeop *)poop;
			const size_t total = size * nmemb;
			/* Avoid overwriting buffer (not a security issue). */
			if (woop.dst + total > woop.max_addr)
				return 0;
			try {
				woop.machine.copy_to_guest(woop.dst, ptr, total);
				woop.dst += total;
				return total;
			} catch (...) {
				return 0;
			}
		});
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &op);

		/* Response header fields. */
		if (opres.headers_length >= CURL_RESP_HEADERS_MIN_LENGTH)
		{
			curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, (header_callback)
			[] (char *buffer, size_t size, size_t nitems, void *usr) -> size_t
			{
				auto *headers = (std::string *)usr;
				try {
					headers->append(buffer, nitems * size);
					return nitems * size;
				} catch (...) {
					return 0;
				}
			});
			curl_easy_setopt(curl, CURLOPT_HEADERDATA, &headers);
		}

		/* Extra cURL options. */
		bool option_dummy_request = false;
		if (options_buffer != 0x0)
		{
			struct curl_options options;
			inst.machine().copy_from_guest(&options, options_buffer, sizeof(options));
			/* Custom interface/source IP. */
			if (options.interface != 0x0) {
				const auto ifname = vcpu.machine().copy_from_cstring(options.interface);
				curl_easy_setopt(curl, CURLOPT_INTERFACE, ifname.c_str());
			}
			/* Enable following 301 Location. */
			if (options.follow_location) {
				curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
			}
			/* Enable TCP Fast Open. */
			if (options.tcp_fast_open) {
				curl_easy_setopt(curl, CURLOPT_TCP_FASTOPEN, 1);
			}
			if (options.dont_verify_host) {
				curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
			}
			option_dummy_request = options.dummy_fetch;
			if (option_dummy_request) {
				curl_easy_setopt(curl, CURLOPT_NOBODY, 1);
			}
		} else {
			/* When no options provided, we default to following 301 redirects. */
			curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
		}

		/* Request header fields. */
		if (!fields.empty()) {
			for (const auto& field : fields) {
				if (!field.empty()) {
					inst.logf("Fetch: ReqHdr  %s", field.c_str());
					req_list = curl_slist_append(req_list, field.c_str());
				}
				else break;
			}
			/* Optional Content-Type override for POSTs. */
			if (opres.ct_length > 0 && opres.ct_length < CONTENT_TYPE_LEN)
			{
				/* Copy Content-Type from guest opres into string.
					TODO: Improve this to avoid a heap allocation. cURL copies the string. */
				std::string ct = "Content-Type: ";
				ct.resize(ct.size() + opres.ct_length);
				std::memcpy(&ct[14], opres.ctype, opres.ct_length);

				inst.logf("Fetch: ReqHdr  %s", ct.c_str());
				req_list = curl_slist_append(req_list, ct.c_str());
			}
			curl_easy_setopt(curl, CURLOPT_HTTPHEADER, req_list);
		}

		/* Optional POST: We need a valid buffer and size. */
		readop rop;
		if (is_post)
		{
			curl_easy_setopt(curl, CURLOPT_POST, 1);
			curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, opres.post_buflen);
			rop = readop {
				.machine = &inst.machine(),
				.src = opres.post_addr,
				.bytes = opres.post_buflen,
			};
			curl_easy_setopt(curl, CURLOPT_READFUNCTION, (read_callback)
			[] (char *ptr, size_t size, size_t nmemb, void *poop) -> size_t {
				auto& rop = *(readop *)poop;
				const size_t total = std::min(rop.bytes, size * nmemb);
				try {
					rop.machine->copy_from_guest(ptr, rop.src, total);
					rop.src += total;
					return total;
				} catch (...) {
					return 0;
				}
			});
			curl_easy_setopt(curl, CURLOPT_READDATA, &rop);
		}

		CURLcode res = curl_easy_perform(curl);
		if (res == 0) {
			/* Calculate content length */
			opres.content_length = op.dst - opres.content_addr;
			/* Adjust and set new mmap base. XXX: Log failed relaxations */
			if (managed_content_addr) {
				vcpu.machine().mmap_relax(opres.content_addr, CURL_BUFFER_MAX, opres.content_length);
			}
			/* Get response status and Content-Type */
			long status;
			res = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
			opres.status = status;
			const char* ctype = nullptr;
			res = curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &ctype);
			/* We have an expectation of at least CONTENT_TYPE_LEN bytes available for
			writing back Content-Type, directly into opres structure. */
			if (res == 0 && ctype != nullptr) {
				const size_t ctlen = std::min(strlen(ctype)+1, CONTENT_TYPE_LEN);
				opres.ct_length = ctlen;
				std::memcpy(opres.ctype, ctype, ctlen);
			}
			else {
				opres.ct_length = 0;
			}
			/* Allocate and copy the response headers, if any. */
			if (!headers.empty())
			{
				uint32_t len_with_zero = headers.size()+1;
				if (opres.headers == 0x0) {
					/* Automatically over-allocate headers using mmap. */
					opres.headers = vcpu.machine().mmap_allocate(len_with_zero);
					opres.headers_length = headers.size();
				} else {
					/* Guest has pre-allocated a buffer for headers. */
					len_with_zero = std::min(len_with_zero, opres.headers_length);
					/* Let guest know the length with hidden zero at the end. */
					opres.headers_length = (len_with_zero > 0) ? (len_with_zero-1) : 0;
				}
				vcpu.machine().copy_to_guest(opres.headers, headers.data(), len_with_zero);
			}
			// OP result back to guest
			vcpu.machine().copy_to_guest(op_buffer, &opres, sizeof(opres));

			inst.logf("Fetch: transfer complete, status=%ld (%s) %u bytes",
				status, ctype, opres.content_length);
			regs.rax = 0;
		} else {
			inst.logf("Fetch error: %s (%d)", curl_easy_strerror(res), res);

			/* Free the over-allocated fetch buffer. */
			if (managed_content_addr) {
				vcpu.machine().mmap_relax(opres.content_addr, CURL_BUFFER_MAX, 0u);
			}
			regs.rax = -res;
		}
	}
	catch (...)
	{
		/* Free the over-allocated fetch buffer. */
		if (managed_content_addr) {
			vcpu.machine().mmap_relax(opres.content_addr, CURL_BUFFER_MAX, 0u);
		}
		regs.rax = -1;
	}

	if (is_self_request) {
		kvm::self_request_concurrency--;
	}

	curl_slist_free_all(req_list);
	curl_slist_free_all(post_list);
	curl_easy_cleanup(curl);
	vcpu.set_registers(regs);
} // curl_fetch

static void syscall_fetch(vCPU& vcpu, MachineInstance& inst)
{
	auto& regs = vcpu.registers();
	/**
	 * rdi = URL
	 * rsi = URL length
	 * rdx = result buffer
	 * rcx = fields buffer
	 * r8  = options buffer
	 **/
	const uint64_t op_buffer = regs.rdx;
	const uint64_t fields_buffer = regs.rcx;
	const uint64_t options_buffer = regs.r8;

	/* URL */
	std::string url = 
		vcpu.machine().buffer_to_string(regs.rdi, regs.rsi, CURL_REQ_URL_MAX_LENGTH);

	/* Automatically turn into self-request if URL starts with slash */
	bool is_self_request = false;
	if (!url.empty() && url[0] == '/') {
		is_self_request = true;
		/* Self-requests have a prefix attached, usually http://127.0.0.1. */
		url = kvm::self_request_prefix + url;
	}

	opresult opres;
	vcpu.machine().copy_from_guest(&opres, op_buffer, sizeof(opresult));

	syscall_curl_fetch_helper(
		vcpu, inst,
		url,
		op_buffer,
		fields_buffer,
		options_buffer,
		is_self_request ? kvm::self_request_uri : "");
}

} // kvm

#include "self_request.cpp"
