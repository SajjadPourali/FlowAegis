#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext,
    helpers::r#gen::bpf_get_prandom_u32,
    macros::{cgroup_sock_addr, map, sock_ops},
    maps::{Array, LruHashMap, PerfEventArray},
    programs::{SockAddrContext, SockOpsContext},
};

// use aya_log_ebpf::info;

use ebpf_common::{Action, CgroupInfo, MainProgramInfo, NetworkTuple, Rule, SocketAddrCompat};

#[map]
pub static TCP_RULES: Array<Rule> = Array::with_max_entries(256, 0);

#[map]
pub static MAIN_APP_INFO: Array<MainProgramInfo> = Array::with_max_entries(100, 0);

#[map]
pub static NETWORK_TUPLE: PerfEventArray<NetworkTuple> = PerfEventArray::new(0);

#[map]
pub static CGROUP_INFO: PerfEventArray<CgroupInfo> = PerfEventArray::new(0);

#[map]
pub static SOCKET_MARK_MAP: LruHashMap<u32, CgroupInfo> = LruHashMap::with_max_entries(1024, 0);

pub fn set_socket_mark(bpf_socket: *mut core::ffi::c_void, tag: u32) {
    unsafe {
        aya_ebpf::helpers::r#gen::bpf_setsockopt(
            bpf_socket,
            aya_ebpf::bindings::SOL_SOCKET as i32,
            aya_ebpf::bindings::SO_MARK as i32,
            &tag as *const _ as *mut core::ffi::c_void,
            core::mem::size_of_val(&tag) as i32,
        );
    };
}

pub fn get_socket_mark(bpf_socket: *mut core::ffi::c_void) -> u32 {
    let mut tag: u32 = 0;
    let tag_size = core::mem::size_of_val(&tag) as i32;

    unsafe {
        aya_ebpf::helpers::r#gen::bpf_getsockopt(
            bpf_socket,
            aya_ebpf::bindings::SOL_SOCKET as i32,
            aya_ebpf::bindings::SO_MARK as i32,
            &mut tag as *mut _ as *mut core::ffi::c_void,
            tag_size,
        );
    }
    tag
}

pub fn mark_socket(bpf_socket: *mut core::ffi::c_void, mut cgroup_info: CgroupInfo) -> u32 {
    let old_socket_mark = get_socket_mark(bpf_socket);
    let mut tag = unsafe { bpf_get_prandom_u32() };
    if tag == 0 || tag == old_socket_mark {
        tag = unsafe { bpf_get_prandom_u32() };
    }
    cgroup_info.tag = tag;

    SOCKET_MARK_MAP.insert(&tag, &cgroup_info, 0).unwrap();
    set_socket_mark(bpf_socket, tag);
    tag
}

pub fn unmark_socket<'a>(bpf_socket: *mut core::ffi::c_void) -> Option<&'a CgroupInfo> {
    let marked_value = get_socket_mark(bpf_socket);
    let tag = unsafe { SOCKET_MARK_MAP.get(&marked_value)? };
    set_socket_mark(bpf_socket, tag.tag);
    Some(tag)
}

#[cgroup_sock_addr(connect4)]
pub fn connect4(ctx: SockAddrContext) -> i32 {
    let Some(main_program_info) = MAIN_APP_INFO.get(0) else {
        return 1;
    };

    let bpf_sock_addr = unsafe { *ctx.sock_addr };
    let uid = ctx.uid();
    let pid = ctx.pid();
    if bpf_sock_addr.protocol != 6 || main_program_info.uid == uid {
        // TCP
        return 1;
    }
    let mut ip = [0u32; 4];
    ip[2] = u32::MAX;
    ip[3] = bpf_sock_addr.user_ip4.swap_bytes();
    let port = (bpf_sock_addr.user_port as u16).swap_bytes();

    let addr = SocketAddrCompat {
        ip,
        port,
        is_ipv6: false,
    };

    let mut rule_id = u32::MAX;
    let mut action = Action::Allow;
    for i in 0..(main_program_info.number_of_active_rules).min(256) {
        let Some(rule) = TCP_RULES.get(i) else {
            return 1;
        };
        if rule.host.matches_ipv4(addr)
            && rule.port.matches(port as u32)
            && rule.uid.matches(uid)
            && rule.pid.matches(pid)
        {
            action = rule.action;
            rule_id = i;
            break;
        }
    }
    let mut cgroup_info = unsafe { core::mem::zeroed::<CgroupInfo>() };
    cgroup_info.dst = addr;
    cgroup_info.uid = uid;
    cgroup_info.gid = ctx.gid();
    cgroup_info.pid = pid;
    cgroup_info.tgid = ctx.gid();
    cgroup_info.rule = rule_id;
    cgroup_info.tag = 0;

    mark_socket(
        ctx.sock_addr as *const _ as *mut core::ffi::c_void,
        cgroup_info,
    );

    match action {
        Action::Deny => 0,
        Action::Allow => 1,
        Action::Proxy => unsafe {
            (*ctx.sock_addr).user_ip4 =
                u32::from_ne_bytes(main_program_info.proxy_v4_address.ip().octets());
            (*ctx.sock_addr).user_port =
                main_program_info.proxy_v4_address.port().swap_bytes() as u32;
            1
        },
        Action::Forward => unsafe {
            (*ctx.sock_addr).user_ip4 =
                u32::from_ne_bytes(main_program_info.forward_v4_address.ip().octets());
            (*ctx.sock_addr).user_port =
                main_program_info.forward_v4_address.port().swap_bytes() as u32;
            1
        },
    }
}

#[cgroup_sock_addr(connect6)]
pub fn connect6(ctx: SockAddrContext) -> i32 {
    let Some(main_program_info) = MAIN_APP_INFO.get(0) else {
        return 1;
    };

    let bpf_sock_addr = unsafe { *ctx.sock_addr };
    let uid = ctx.uid();
    let pid = ctx.pid();
    if bpf_sock_addr.protocol != 6 || main_program_info.uid == uid {
        // TCP
        return 1;
    }

    let mut ip = [0u32; 4];
    ip[0] = bpf_sock_addr.user_ip6[0].swap_bytes();
    ip[1] = bpf_sock_addr.user_ip6[1].swap_bytes();
    ip[2] = bpf_sock_addr.user_ip6[2].swap_bytes();
    ip[3] = bpf_sock_addr.user_ip6[3].swap_bytes();

    let port = (bpf_sock_addr.user_port as u16).swap_bytes();

    let addr = SocketAddrCompat {
        ip,
        port,
        is_ipv6: true,
    };

    let mut rule_id = u32::MAX;
    let mut action = Action::Allow;
    for i in 0..(main_program_info.number_of_active_rules).min(256) {
        let Some(rule) = TCP_RULES.get(i) else {
            return 1;
        };
        if rule.host.matches_ipv6(addr)
            && rule.port.matches(port as u32)
            && rule.uid.matches(uid)
            && rule.pid.matches(pid)
        {
            action = rule.action;
            rule_id = i;
            break;
        }
    }
    let mut cgroup_info = unsafe { core::mem::zeroed::<CgroupInfo>() };
    cgroup_info.dst = addr;
    cgroup_info.uid = uid;
    cgroup_info.gid = ctx.gid();
    cgroup_info.pid = pid;
    cgroup_info.tgid = ctx.gid();
    cgroup_info.rule = rule_id;
    cgroup_info.tag = 0;

    mark_socket(
        ctx.sock_addr as *const _ as *mut core::ffi::c_void,
        cgroup_info,
    );

    match action {
        Action::Deny => 0,
        Action::Allow => 1,
        Action::Proxy => unsafe {
            let ipv6 = u128_to_u32_array(main_program_info.proxy_v6_address.ip().to_bits());
            (*ctx.sock_addr).user_ip6[0] = ipv6[0].swap_bytes();
            (*ctx.sock_addr).user_ip6[1] = ipv6[1].swap_bytes();
            (*ctx.sock_addr).user_ip6[2] = ipv6[2].swap_bytes();
            (*ctx.sock_addr).user_ip6[3] = ipv6[3].swap_bytes();
            (*ctx.sock_addr).user_port =
                main_program_info.proxy_v6_address.port().swap_bytes() as u32;
            1
        },
        Action::Forward => unsafe {
            let ipv6 = u128_to_u32_array(main_program_info.forward_v6_address.ip().to_bits());
            (*ctx.sock_addr).user_ip6[0] = ipv6[0].swap_bytes();
            (*ctx.sock_addr).user_ip6[1] = ipv6[1].swap_bytes();
            (*ctx.sock_addr).user_ip6[2] = ipv6[2].swap_bytes();
            (*ctx.sock_addr).user_ip6[3] = ipv6[3].swap_bytes();
            (*ctx.sock_addr).user_port =
                main_program_info.forward_v6_address.port().swap_bytes() as u32;
            1
        },
    }
}

// #[inline(always)]
// fn u32_array_to_u128(arr: [u32; 4]) -> u128 {
//     ((arr[0].swap_bytes() as u128) << 96)
//         | ((arr[1].swap_bytes() as u128) << 64)
//         | ((arr[2].swap_bytes() as u128) << 32)
//         | (arr[3].swap_bytes() as u128)
//     // (arr[3] as u128) << 96 | (arr[2] as u128) << 64 | (arr[1] as u128) << 32 | (arr[0] as u128)
// }

#[inline(always)]
fn u128_to_u32_array(value: u128) -> [u32; 4] {
    [
        (value >> 96) as u32,
        (value >> 64) as u32,
        (value >> 32) as u32,
        (value & 0xFFFF_FFFF) as u32,
    ]
}

#[sock_ops]
pub fn bpf_sockops(ctx: SockOpsContext) -> u32 {
    let Some(cgroup_info) = unmark_socket(ctx.ops as *mut core::ffi::c_void) else {
        return 1;
    };
    // info!(
    //     &ctx,
    //     "{}",
    //     get_socket_mark(ctx.ops as *mut core::ffi::c_void)
    // );
    // match unmark_socket(ctx.ops as *mut core::ffi::c_void) {
    //     Some(x) => {
    //         info!(&ctx, "{}", x);
    //     }
    //     None => {
    //         info!(&ctx, "{}", "NONE");
    //     }
    // };
    // return 1;
    if ctx.op() != 4 {
        // BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB
        return 0;
    }

    // let mut tag: u32 = 0;
    // let tag_size = core::mem::size_of_val(&tag) as i32;

    // unsafe {
    //     aya_ebpf::helpers::r#gen::bpf_getsockopt(
    //         ctx.ops as *mut core::ffi::c_void,
    //         aya_ebpf::bindings::SOL_SOCKET as i32,
    //         aya_ebpf::bindings::SO_MARK as i32,
    //         &mut tag as *mut _ as *mut core::ffi::c_void,
    //         tag_size,
    //     );
    // }
    // if tag == u32::MAX {
    //     return 1;
    // }
    let remote_port = ctx.remote_port().swap_bytes() as u16;
    let local_port = ctx.local_port() as u16;
    let (src, dst) = if ctx.family() == 2 {
        // IPv4
        let mut local_ip = [0u32; 4];
        local_ip[2] = u32::MAX;
        local_ip[3] = ctx.local_ip4().swap_bytes();
        let mut remote_ip = [0u32; 4];
        remote_ip[2] = u32::MAX;
        remote_ip[3] = ctx.remote_ip4().swap_bytes();

        (
            SocketAddrCompat {
                ip: local_ip,
                port: local_port,
                is_ipv6: false,
            },
            SocketAddrCompat {
                ip: remote_ip,
                port: remote_port,
                is_ipv6: false,
            },
        )
    } else if ctx.family() == 10 {
        // IPv6
        let local_ip = ctx.local_ip6();
        let remote_ip = ctx.remote_ip6();

        (
            SocketAddrCompat {
                ip: [
                    local_ip[0].swap_bytes(),
                    local_ip[1].swap_bytes(),
                    local_ip[2].swap_bytes(),
                    local_ip[3].swap_bytes(),
                ],
                port: local_port,
                is_ipv6: true,
            },
            SocketAddrCompat {
                ip: [
                    remote_ip[0].swap_bytes(),
                    remote_ip[1].swap_bytes(),
                    remote_ip[2].swap_bytes(),
                    remote_ip[3].swap_bytes(),
                ],
                port: remote_port,
                is_ipv6: true,
            },
        )
    } else {
        return 0;
    };
    NETWORK_TUPLE.output(
        &ctx,
        &NetworkTuple {
            src,
            dst,
            actual_dst: cgroup_info.dst,
            uid: cgroup_info.uid,
            gid: cgroup_info.gid,
            pid: cgroup_info.pid,
            tgid: cgroup_info.tgid,
            rule: cgroup_info.rule,
        },
        0,
    );
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // loop {}
    unsafe { core::hint::unreachable_unchecked() }
}
