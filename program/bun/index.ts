import { dlopen, ptr, FFIType, CString, suffix } from "bun:ffi";

const lib = dlopen("/home/gonzo/github/drogon_kvm/program/libdrogon.so", {
  wait_for_requests_paused: {
	args: [FFIType.ptr], // pointer to a request buffer
  },
  sys_backend_response: {
	args: [
		FFIType.i32, // status code
		FFIType.cstring, // content type
		FFIType.i32, // content type length
		FFIType.ptr, // content
		FFIType.i32, // content length
		FFIType.ptr  // extra data (headers, etc.)
	]
  },
});

console.log("Hello via Bun!");

const request_buffer = new ArrayBuffer(1024);
while (true) {
	lib.symbols.wait_for_requests_paused(ptr(request_buffer));

	// Create a hello world response
	const contentType = Buffer.from("text/plain", "utf-8");
	const helloWorld = Buffer.from("Hello World from Bun!", "utf-8");
	lib.symbols.sys_backend_response(200, contentType, contentType.length, ptr(helloWorld), helloWorld.length, 0);
}
