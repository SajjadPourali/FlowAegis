use core::u32;

use aya_ebpf::{
    EbpfContext,
    helpers::bpf_probe_read_kernel_str_bytes,
    macros::{map, tracepoint},
    maps::{LpmTrie, lpm_trie::Key},
    programs::TracePointContext,
};
use aya_log_ebpf::info;

use crate::PID_RULE_MAP;

#[map]
pub static PATH_RULES: LpmTrie<[u8; 128], u32> = LpmTrie::with_max_entries(256, 0);

#[tracepoint]
pub fn sched_process_exec(ctx: TracePointContext) -> u32 {
    // let pid = unsafe { ctx.read_at::<i32>(12).unwrap() };
    // let mut data = unsafe { core::mem::zeroed::<ebpf_common::PathKey>() };
    // data.flags = 0;
    // data.pid = 0;

    // data.path = {
    let mut buf = [0u8; 128];
    let Ok(_path) = unsafe { ctx.read_at::<u8>(8) }.and_then(|ptr| unsafe {
        bpf_probe_read_kernel_str_bytes(ctx.as_ptr().offset(ptr as isize) as *const u8, &mut buf)
    }) else {
        return 0;
    };

    let maximum_len = _path.len().min(buf.len());

    let pid = ctx.pid();
    let mut last_path_id: Option<&u32> = None;

    for i in 0..=maximum_len {
        let index = maximum_len.saturating_sub(i);
        let key = Key {
            prefix_len: (index * 8) as u32,
            data: buf,
        };
        if let Some(path_id) = PATH_RULES.get(&key) {
            match last_path_id {
                Some(lpid) if lpid == path_id => continue,
                Some(lpid) => {
                    PID_RULE_MAP
                        .insert(&(pid, *lpid), &(pid, *path_id), 0)
                        .unwrap();
                }
                None => {
                    PID_RULE_MAP
                        .insert(&(pid, u32::MAX), &(pid, *path_id), 0)
                        .unwrap();
                }
            }
            last_path_id = Some(path_id);
        } else {
            break;
        }
    }
    let key = Key {
        prefix_len: (buf.len() * 8) as u32,
        data: buf,
    };
    if let Some(path_id) = PATH_RULES.get(&key) {
        if let Some(lpid) = last_path_id.filter(|id| path_id != *id) {
            PID_RULE_MAP
                .insert(&(pid, *lpid), &(pid, *path_id), 0)
                .unwrap();
        }
        last_path_id = Some(path_id);
    }
    if let Some(lpid) = last_path_id {
        PID_RULE_MAP
            .insert(&(pid, *lpid), &(pid, u32::MAX), 0)
            .unwrap();
    }

    0
}

#[tracepoint]
pub fn sched_process_exit(ctx: TracePointContext) -> u32 {
    let pid = ctx.pid();
    let mut last_path_id = u32::MAX;
    let mut max_traversal: u32 = 128;
    while max_traversal > 0 {
        match unsafe { PID_RULE_MAP.get(&(pid, last_path_id)) } {
            Some((_, path_id)) => {
                _ = PID_RULE_MAP.remove(&(pid, last_path_id));
                if *path_id == u32::MAX {
                    break;
                }
                last_path_id = *path_id;
            }
            None => break,
        }
        max_traversal -= 1;
    }
    0
}
