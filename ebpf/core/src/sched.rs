use aya_ebpf::{
    EbpfContext,
    helpers::bpf_probe_read_kernel_str_bytes,
    macros::{map, tracepoint},
    maps::{LpmTrie, lpm_trie::Key},
    programs::TracePointContext,
};
use ebpf_common::PathKey;

use crate::PID_RULE_MAP;

#[map]
pub static PATH_RULES: LpmTrie<PathKey, u32> = LpmTrie::with_max_entries(256, 0);

#[tracepoint]
pub fn sched_process_exec(ctx: TracePointContext) -> u32 {
    unsafe {
        let pid = ctx.read_at::<i32>(12).unwrap();
        let mut data = core::mem::zeroed::<ebpf_common::PathKey>();
        data.flags = 0;
        data.pid = 0;

        data.path = {
            let mut buf = [0u8; 128];
            let Ok(_path) = ctx.read_at::<u8>(8).and_then(|ptr| {
                bpf_probe_read_kernel_str_bytes(
                    ctx.as_ptr().offset(ptr as isize) as *const u8,
                    &mut buf,
                )
            }) else {
                return 0;
            };
            buf
        };
        // r4.path_len = data_path_len as u8;

        // let filename = core::str::from_utf8_unchecked(&data.path[..r4.path_len as usize]);
        // info!(&ctx, "Executed binary: {}, {} - {}", filename, pid,ctx.pid());
        // data.path_len = path.len() as u8;
        let key = Key {
            prefix_len: (size_of_val(&data) * 8) as u32,
            data,
        };

        if let Some(rule_id) = PATH_RULES.get(&key).or({
            data.flags = 1;
            data.pid = pid as u32;
            PATH_RULES.get(&key)
        }) {
            // info!(&ctx, "Allowed binary: {} {}", filename,pid);
            PID_RULE_MAP.insert(&(pid as u32), rule_id, 0).unwrap();
        }
    }
    0
}

#[tracepoint]
pub fn sched_process_exit(ctx: TracePointContext) -> u32 {
    if let Ok(pid) = unsafe { ctx.read_at::<i32>(24) } {
        _ = PID_RULE_MAP.remove(&(pid as u32));
    }

    0
}
