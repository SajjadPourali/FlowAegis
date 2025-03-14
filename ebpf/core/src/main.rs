#![no_std]
#![no_main]

use aya_ebpf::{macros::map, maps::Array};
use aya_log_ebpf::info;
// use ebpf_common::rule;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // loop {}
    unsafe { core::hint::unreachable_unchecked() }
}


#[map]
pub static RULES: Array<[u8; 32]> = Array::with_max_entries(100, 0);