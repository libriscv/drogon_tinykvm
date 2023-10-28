import { connect } from "jsr:@db/redis";

console.log("Hello from Deno Storage inside TinyKVM");
const drogon = Deno.dlopen("./libdrogon.so", {
	vcpureqid: { parameters: [], result: "i32" },

	wait_for_storage_task_paused: { parameters: [], result: "pointer" },
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

//const redisClient = await connect({ hostname: "127.0.0.1", port: 6379 });
//await redisClient.set("value", "0");
const response = "Hello from Deno storage inside TinyKVM";
const encoder = new TextEncoder();
while (true) {
	// Wait for a UInt8Array buffer from C
	const bufptr = drogon.symbols.wait_for_storage_task_paused();
	// View it as a Uint8Array of length 256
	const arrayBuffer = Deno.UnsafePointerView.getArrayBuffer(bufptr, 256);
	const buffer = new Uint8Array(arrayBuffer);

	//const redis_answer = await redisClient.incr("value");
	// Copy redis_answer to buffer
	//const response = "Hello from Deno inside TinyKVM, counter: " + redis_answer;
	let encoded = encoder.encode(response);
	// Copy to buffer, but leave space for null terminator
	if (encoded.length > 255) {
		encoded = encoded.slice(0, 255);
	}
	buffer.set(encoded); // Leave space for null terminator
	buffer[encoded.length] = 0; // Null-terminate
}

//redisClient.close();
drogon.close();
