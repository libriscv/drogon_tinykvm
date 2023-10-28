#include "kvm_api.h"
#include <cmath>
#include <array>
#include <string>
#include <vector>

static void my_backend(const char*, const char*)
{
	const char ctype[] = "text/plain";
	const char result[] = "Hello World";

	backend_response(200, ctype, sizeof(ctype)-1,
		result, sizeof(result)-1);
}

static const char response[] =
	"HTTP/1.1 200 OK\r\n"
	"Server: Drogon Compute Server\r\n"
//	"Connection: Close\r\n"
	"Content-Type: text/plain\r\n"
	"Content-Length: 13\r\n"
	"\r\n"
	"Hello World!\n";


static void prepare_tcp(int)
{
	std::vector<kvm_socket_event> write_events;
	while (true)
	{
		/* Accept new connection */
		std::array<kvm_socket_event, 4> sev;
		int n = wait_for_socket_events_paused(sev.data(), sev.size());
		for (int i = 0; i < n; i++)
		{
			kvm_socket_event& ev = sev[i];
			switch (ev.event)
			{
			case SOCKET_CONNECT:
				//Print("Socket %d connected: %s\n", ev.fd, ev.remote);
				break;
			case SOCKET_READ:
				//Print("Socket %d read: %zu bytes\n", ev.fd, ev.data_len);
				break;
			case SOCKET_WRITABLE:
				//Print("Socket %d writable\n", ev.fd);
				/* Write to the socket. */
				write_events.push_back({
					.fd = ev.fd,
					.event = SOCKET_WRITABLE,
					.remote = nullptr,
					.arg = nullptr,
					.data = (const uint8_t *)response,
					.data_len = sizeof(response) - 1
				});
				break;
			case SOCKET_DISCONNECT:
				//Print("Socket %d disconnected: %s\n", ev.fd, ev.remote);
				break;
			}
		} // for
		if (!write_events.empty())
		{
			/* Write to the socket. */
			sys_sockets_write(write_events.data(), write_events.size());
			write_events.clear();
		}
		/* Continue waiting for events. */
	}
}

int main()
{
	printf("-== Hello World program ready ==-\n");
	set_backend_get(my_backend);
	//set_socket_prepare_for_pause(prepare_tcp);
	wait_for_requests();
}
