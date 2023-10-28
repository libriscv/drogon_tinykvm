#include "kvm_api.h"

void* wait_for_storage_task_paused()
{
	void *ptr = NULL;
	//const size_t bytes = wait_for_permanent_ipre_resume_paused(&ptr);
	const size_t bytes = wait_for_storage_resume_paused(&ptr);
	return ptr;
}
