// Connect to '127.0.0.1:8080' by continously retrying
// and print time taken to connect
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <chrono>
#include <cstring>
#include <iostream>
#include <thread>

int main() {
	const char* ip = "127.0.0.1";
	int port = 8080;
	int max_retries = 25000;
	long retry_delay_us = 150; // 150 microseconds

	struct sockaddr_in server_addr;
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	inet_pton(AF_INET, ip, &server_addr.sin_addr);
	const int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		std::cerr << "Socket creation error: " << strerror(errno)
					<< std::endl;
		return 1;
	}

	auto start_time = std::chrono::high_resolution_clock::now();
	for (int i = 0; i < max_retries; ++i)
	{
		if (connect(sock, (struct sockaddr*)&server_addr,
					sizeof(server_addr)) == 0)
		{
			// HTTP/1.1 GET / with Host: deno
			std::string request = "GET / HTTP/1.1\r\nHost: deno\r\nConnection: close\r\n\r\n";
			send(sock, request.c_str(), request.size(), 0);
			char buffer[1024];
			recv(sock, buffer, sizeof(buffer), 0);

			auto end_time = std::chrono::high_resolution_clock::now();
			auto duration = std::chrono::duration_cast<std::chrono::microseconds>(
				end_time - start_time).count();
			//std::cout << "Connected to " << ip << ":" << port
			//			<< " after " << i + 1 << " retries, time taken: "
			//			<< duration << " microseconds" << std::endl;
			std::cout << duration << std::endl;
			close(sock);
			return 0;
		}

		std::this_thread::sleep_for(
			std::chrono::microseconds(retry_delay_us));
	}
	std::cerr << "Failed to connect after " << max_retries
				<< " retries" << std::endl;
	close(sock);
	return 1;
}
// Compile with: g++ -o measure measure.cpp -std=c++20 -pthread
