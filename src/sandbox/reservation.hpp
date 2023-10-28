#pragma once

namespace kvm {
struct VMPoolItem;

struct Reservation {
	VMPoolItem* slot;
	void (*free) (void*);
	
	~Reservation() { free(this); }
};

} // kvm
