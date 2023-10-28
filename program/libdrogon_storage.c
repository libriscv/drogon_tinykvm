#include "kvm_api.h"
#include <stdio.h>

void wait_for_storage_task_paused(struct kvm_request* req)
{
	wait_for_requests_paused(req);
}
