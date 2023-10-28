const fetch = require('sync-fetch')
const koffi = require("koffi");
const lib = koffi.load('/home/gonzo/github/drogon_kvm/program/libdrogon.so');

/**
struct kvm_request_header {
	const char *field;
	uint32_t    field_colon; // Index of the colon in the field. //
	uint32_t    field_len;   // Length of the entire key: value pair. //
};
struct kvm_request {
	const char * method;
	const char * url;
	const char * arg;
	const char * content_type;
	uint16_t    method_len;
	uint16_t    url_len;
	uint16_t    arg_len;
	uint16_t    content_type_len;
	const uint8_t * content; // Can be NULL. //
	size_t         content_len;
	// HTTP headers //
	struct kvm_request_header * headers;
	uint16_t num_headers;
	uint16_t info_flags; // 0x1 = request is a warmup request. //
	uint32_t reserved0;    // Reserved for future use. //
	uint64_t reserved1[2]; // Reserved for future use. //
};
**/
const kvm_request_header = koffi.struct('kvm_request_header', {
	field: 'const char*',
	field_colon: 'uint32_t',
	field_len: 'uint32_t',
});
const kvm_request = koffi.struct('kvm_request', {
	method: 'const char*',
	url: 'const char*',
	arg: 'const char*',
	content_type: 'const char*',
	method_len: 'uint16_t',
	url_len: 'uint16_t',
	arg_len: 'uint16_t',
	content_type_len: 'uint16_t',
	content: 'uint8_t*',
	content_len: 'size_t',
	headers: koffi.pointer(kvm_request_header),
	num_headers: 'uint16_t',
	info_flags: 'uint16_t',
});
function is_warmup_request(req) {
	return req.info_flags & 0x1;
}
const wait_for_requests = lib.func('void wait_for_requests_paused(_Out_ kvm_request *req)');
const send_response = lib.func('void sys_backend_response(int16_t status, const void *t, size_t, const void *c, size_t, const void* extra)');

// Fetch an image from:
// https://filebin.varnish-software.com/tinykvm_programs/spooky.jpg
// and send it using send_response.
//let image_url = "https://filebin.varnish-software.com/tinykvm_programs/spooky.jpg";
//let content_type = "image/jpeg";
//const response = fetch(image_url);
//if (!response.ok) {
//	console.error("Failed to fetch image: ", response.statusText);
//}
//const buffer = response.buffer();
//if (!buffer) {
//	console.error("Failed to read image buffer");
//}

async function main()
{
	while (true) {
		let req = {};
		wait_for_requests(req);
		if (false && !is_warmup_request(req)) {
			console.log("Request: ", req);
			let headers = koffi.decode(req.headers, kvm_request_header, req.num_headers);
			console.log("Headers: ", headers);

			// Send the image using send_response.
			send_response(200,
				content_type, content_type.length,
				buffer, buffer.length,
				null
			);
		}

		//const resp = fetch("https://filebin.varnish-software.com/tinykvm_programs/spooky.jpg");
		//if (!resp.ok) {
		//	console.error("Failed to fetch image: ", resp.statusText);
		//	continue;
		//}
		//const buffer = await resp.buffer();
		//if (!buffer) {
		//	console.error("Failed to read image buffer");
		//	continue;
		//}

		send_response(200,
			"text/plain", "text/plain".length,
			"Hello, World!", "Hello, World!".length,
			null
		);
	}
}

main().catch(err => {
	console.error("Error: ", err);
});
