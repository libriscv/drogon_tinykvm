#include "kvm_api.h"
#define DECLARE_REMOTE_FUNCTION(name, ...) \
	extern int call_ ## name(__VA_ARGS__); \
	asm(".global call_" #name "\n" \
		"call_" #name ":\n" \
		"    movabs $" #name ", %rax\n" \
		"    jmp *%rax\n");
//DECLARE_REMOTE_FUNCTION(remote_return_to_deno)
extern void sys_storage_resume(void* data, size_t len);

void remote_resume(void *buffer, size_t len) {
	sys_storage_resume(buffer, len);
}

void* wait_for_storage_task_paused()
{
	void *ptr = NULL;
	//const size_t bytes = wait_for_permanent_ipre_resume_paused(&ptr);
	const size_t bytes = wait_for_storage_resume_paused(&ptr);
	return ptr;
}
