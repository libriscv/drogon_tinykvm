#include "kvm_api.h"
#include <stdio.h>
#define DECLARE_REMOTE_FUNCTION(name, ...) \
	extern int call_ ## name(__VA_ARGS__); \
	asm(".global call_" #name "\n" \
		"call_" #name ":\n" \
		"    movabs $" #name ", %rax\n" \
		"    jmp *%rax\n");
//DECLARE_REMOTE_FUNCTION(remote_return_to_deno)
extern void sys_storage_resume(const void* data, size_t len);

void remote_resume(const void *buffer, size_t len) {
	sys_storage_resume(buffer, len);
}
