#![no_std]
#![no_main]

use aya_ebpf::{macros::map, maps::LruHashMap};

mod cgroups;
mod sched;

#[map]
pub static PID_RULE_MAP: LruHashMap<u32, u32> = LruHashMap::with_max_entries(1024, 0);

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // loop {}
    unsafe { core::hint::unreachable_unchecked() }
}
