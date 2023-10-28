#include "kvm_api.h"
#include <cmath>
#include <array>
#include <string>

extern "C"
void my_backend(const char*, const char*)
{
	const char ctype[] = "text/plain";
	const char result[] = "Hello World";

	backend_response(200, ctype, sizeof(ctype)-1,
		result, sizeof(result)-1);
}

int main()
{
	printf("-== Hello World program ready ==-\n");
	set_backend_get(my_backend);
	wait_for_requests();
}
