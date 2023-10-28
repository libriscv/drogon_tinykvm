#include <stdint.h>

#include "kvm_settings.h"

struct VMBuffer {
	const char *data;
	ssize_t size;
};

struct backend_result {
	const char *type;
	uint16_t tsize; /* Max 64KB Content-Type */
	int16_t  status;
	/* When content length > 0 and bufcount == 0, it is a streamed response. */
	size_t  content_length;
	size_t  bufcount;
	union {
		/* The result is either a list of buffers. */
		struct VMBuffer buffers[0];
	};
};
