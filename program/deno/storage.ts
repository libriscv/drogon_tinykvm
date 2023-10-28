import { connect } from "jsr:@db/redis";

console.log("Hello from Deno Storage inside TinyKVM");
const drogon = Deno.dlopen("/home/gonzo/github/drogon_kvm/program/libdrogon_storage.so", {
	wait_for_requests_paused: { parameters: ["buffer"], result: "void" },
	backend_response_str: { parameters: ["i32", "buffer", "buffer"], result: "void" },
	vcpureqid: { parameters: [], result: "i32" },

	wait_for_storage_task_paused: { parameters: ["buffer"], result: "void" },
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

const buffer = new Uint8Array(104);
while (true) {
	drogon.symbols.wait_for_storage_task_paused(buffer);

	//console.log("Storage: Processing storage task...");
}

drogon.close();
