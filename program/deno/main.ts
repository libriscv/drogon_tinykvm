import { connect } from "jsr:@db/redis";

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

const buffer = new Uint8Array(104); // should be large enough. I think the struct is 88 bytes
while (true) {
	drogon.symbols.wait_for_requests_paused(buffer);

	//const redisClient = await connect({ hostname: "127.0.0.1", port: 6379 });
	//let redis_answer = await redisClient.get("hoge");
	//redisClient.close();
	//let response = "Hello from deno inside TinyKVM, redis answer: " + redis_answer;
	//let counter = drogon.symbols.check_remote_function();

	drogon.symbols.remote_resume(buffer, buffer.byteLength);

	let counter = 42;
	let response = "Hello from deno inside TinyKVM counter: " + counter;

	drogon.symbols.backend_response_str(200,
		asCString("text/plain"),
		asCString(response));
}

drogon.close();
