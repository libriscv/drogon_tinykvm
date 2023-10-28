use std::arch::asm;
// A global counter
static mut COUNTER: u64 = 0;

#[no_mangle]
extern "C" fn remote_function() -> u64 {
	unsafe {
		COUNTER += 1;
		COUNTER
	}
}

#[inline]
#[allow(dead_code)]
pub fn wait_for_requests() -> !
{
	unsafe {
		asm!("out 0x0, eax",
			in("eax") 0x10001,
			options(noreturn)
		);
	}
}

fn main()
{
	println!("Hello, Storage World!");
	wait_for_requests();
}
