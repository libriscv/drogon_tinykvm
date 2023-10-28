//import { connect } from "jsr:@db/redis";

console.log("Hello from Deno inside TinyKVM");
const drogon = Deno.dlopen("/home/gonzo/github/drogon_kvm/program/libdrogon.so", {
	wait_for_requests_paused: { parameters: ["buffer"], result: "void" },
	backend_response_str: { parameters: ["i32", "buffer", "buffer"], result: "void" },
	vcpureqid: { parameters: [], result: "i32" },

	remote_resume: { parameters: ["buffer", "usize"], result: "void" },
});
function asCString(str: string): Uint8Array {
	// Convert a string to a C-style string (null-terminated)
	const encoder = new TextEncoder();
	const encoded = encoder.encode(str);
	const buffer = new Uint8Array(encoded.length + 1);
	buffer.set(encoded);
	buffer[encoded.length] = 0; // Null-terminate the string
	return buffer;
}
function getZeroTerminatedString(buffer, encoding = 'utf8') {
    const nullByteIndex = buffer.indexOf(0x00);
	const slice = nullByteIndex !== -1 ? buffer.slice(0, nullByteIndex) : buffer;
	return new TextDecoder(encoding).decode(slice);
}

while (true) {
	const remote_buffer = new Uint8Array(256);
	drogon.symbols.wait_for_requests_paused(remote_buffer);

	// Get remote_buffer as a zero-terminated string
	//drogon.symbols.remote_resume(remote_buffer, BigInt(remote_buffer.byteLength));
	let remote_str = "getZeroTerminatedString(remote_buffer)";

	drogon.symbols.backend_response_str(200,
		asCString("text/plain"),
		asCString(remote_str));
}

drogon.close();
