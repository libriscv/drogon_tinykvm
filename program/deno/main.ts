import { connect } from "jsr:@db/redis";

console.log("Hello from Deno inside TinyKVM");

const drogon = Deno.dlopen("./libdrogon.so", {
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
function getZeroTerminatedString(buffer: Uint8Array, encoding = 'utf8') {
    const nullByteIndex = buffer.indexOf(0x00);
	const slice = nullByteIndex !== -1 ? buffer.slice(0, nullByteIndex) : buffer;
	return new TextDecoder(encoding).decode(slice);
}

//await redisClient.set("value", "0");
while (true) {
	const remote_buffer = new Uint8Array(256);
	drogon.symbols.wait_for_requests_paused(remote_buffer);
	// Measure the time it takes to do the request
	let timer_start = performance.now();
	let response: string;

	if (true) {
		// Get remote_buffer as a zero-terminated string
		drogon.symbols.remote_resume(remote_buffer, BigInt(remote_buffer.byteLength));
		response = getZeroTerminatedString(remote_buffer);
	} else {
		const redisClient = await connect({ hostname: "127.0.0.1", port: 6379 });
		const redis_answer = await redisClient.incr("value");
		response = "Hello from Deno inside TinyKVM, counter: " + redis_answer;
		redisClient.close();
	}

	let timer_end = performance.now();
	// Measure the time it takes to do the request in microseconds
	console.log(`Deno handled request in ${ (timer_end - timer_start).toFixed(3) * 1000 } µs`);

	drogon.symbols.backend_response_str(200,
		asCString("text/plain"),
		asCString(response));
}

drogon.close();
