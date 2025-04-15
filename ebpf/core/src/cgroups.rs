use aya_ebpf::{
    EbpfContext,
    macros::{cgroup_sock_addr, map, sock_ops},
    maps::{Array, LpmTrie, LruHashMap, PerfEventArray, lpm_trie::Key},
    programs::{SockAddrContext, SockOpsContext},
};

use aya_log_ebpf::info;

use ebpf_common::{
    Action, CgroupInfo, LpmValue, MainProgramInfo, NetworkTuple, SocketAddrCompat,
    u128_to_u32_array,
};

use crate::PID_RULE_MAP;

#[map]
pub static V4_RULES: LpmTrie<ebpf_common::RuleV4, LpmValue> = LpmTrie::with_max_entries(256, 0);

#[map]
pub static V6_RULES: LpmTrie<ebpf_common::RuleV6, LpmValue> = LpmTrie::with_max_entries(256, 0);

#[map]
pub static MAIN_APP_INFO: Array<MainProgramInfo> = Array::with_max_entries(100, 0);

#[map]
pub static TRANSPORT: Array<SocketAddrCompat> = Array::with_max_entries(100, 0);

#[map]
pub static NETWORK_TUPLE: PerfEventArray<NetworkTuple> = PerfEventArray::new(0);

#[map]
pub static SOCKET_MARK_MAP: LruHashMap<u64, CgroupInfo> = LruHashMap::with_max_entries(1024, 0);

#[cgroup_sock_addr(connect4)]
pub fn connect4(ctx: SockAddrContext) -> i32 {
    let Some(main_program_info) = MAIN_APP_INFO.get(0) else {
        return 1;
    };

    // info!(&ctx, "connect4xx {}", sock_cookie);

    // for x in 0..100{
    //     if x == 62 {
    //         continue;
    //     }
    //     set_socket_markx(
    //         ctx.sock_addr as *const _ as *mut core::ffi::c_void,
    //         9999,
    //         x as i32,
    //     );
    //     let r = get_socket_markx(
    //         ctx.sock_addr as *const _ as *mut core::ffi::c_void,
    //         x as i32,
    //     );
    //     info!(&ctx, "connect4 {} {}", x, r);
    // }

    let bpf_sock_addr = unsafe { *ctx.sock_addr };
    let uid = ctx.uid();
    let pid = ctx.pid();
    let gid = ctx.gid();
    let tgid = ctx.tgid();

    if bpf_sock_addr.protocol != 6 || main_program_info.pid == tgid {
        let sock = unsafe { *ctx.sock_addr };
        let o = unsafe { *bpf_sock_addr.__bindgen_anon_1.sk }.src_port;
        info!(&ctx, "connect udp {}", o as u16);
        // TCP
        return 1;
    }

    let ip = [0, 0, u32::MAX, bpf_sock_addr.user_ip4.swap_bytes()];
    let port = (bpf_sock_addr.user_port as u16).swap_bytes();

    let addr = SocketAddrCompat {
        ip,
        port,
        is_ipv6: false,
    };

    let mut rule = u32::MAX;
    let mut action = Action::Allow;
    let mut transport_id = u32::MAX;
    let mut r4 = unsafe { core::mem::zeroed::<ebpf_common::RuleV4>() };
    let base_offset = ((core::mem::size_of_val(&r4) - 4) * 8) as u32;
    r4.dst = ip[3].swap_bytes();
    for flags in [7, 6, 5, 4, 3, 2, 1, 0] {
        r4.flags = flags;
        r4.port = 0;
        r4.uid = 0;

        if (flags & 2) == 2 {
            r4.port = port;
        }
        if (flags & 1) == 1 {
            r4.uid = uid;
        }
        let key = Key::new(base_offset + 32, r4);
        if let Some(v) = V4_RULES.get(&key) {
            if (flags & 4) == 4 {
                // has path
                if unsafe { PID_RULE_MAP.get(&(tgid, v.path_id)) }.is_some() {
                    // info!(&ctx, "path_id {}", *path_id);
                    // if path_id == &(v.path_id as u32) {
                    rule = v.rule_id;
                    action = v.action;
                    transport_id = v.transport_id;
                    break;
                    // }
                }
                continue;
                // r4.pid = pid;
            }
            rule = v.rule_id;
            action = v.action;
            transport_id = v.transport_id;
            break;
        }
    }
    if matches!(action, Action::Deny) {
        NETWORK_TUPLE.output(
            &ctx,
            &NetworkTuple {
                src: SocketAddrCompat {
                    ip: [0u32; 4],
                    port: 0,
                    is_ipv6: false,
                },
                dst: addr,
                actual_dst: addr,
                transport: u32::MAX,
                uid,
                gid,
                pid,
                tgid,
                rule,
            },
            0,
        );
        return 0;
    }
    let mut cgroup_info = unsafe { core::mem::zeroed::<CgroupInfo>() };
    cgroup_info.dst = addr;
    cgroup_info.uid = uid;
    cgroup_info.gid = gid;
    cgroup_info.pid = pid;
    cgroup_info.tgid = tgid;
    cgroup_info.rule = rule;
    cgroup_info.tag = 0;
    cgroup_info.transport = transport_id;
    // info!(
    //     &ctx,
    //     "connect4: {} {} ",
    //     cgroup_info.pid,
    //     cgroup_info.tgid,
    // );

    // sock_cookie

    // let tag = mark_socket(
    //     ctx.sock_addr as *const _ as *mut core::ffi::c_void,
    //     cgroup_info,
    // );
    let sock_cookie = unsafe {
        aya_ebpf::helpers::r#gen::bpf_get_socket_cookie(
            ctx.sock_addr as *const _ as *mut core::ffi::c_void,
        )
    };
    SOCKET_MARK_MAP
        .insert(&sock_cookie, &cgroup_info, 0)
        .unwrap();
    // info!(&ctx, "connect4 {}", tag);

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
        Action::Forward => {
            let Some(socket) = TRANSPORT.get(transport_id) else {
                return 0;
            };
            unsafe {
                (*ctx.sock_addr).user_ip4 = socket.ip[3].swap_bytes();
                (*ctx.sock_addr).user_port = socket.port.swap_bytes() as u32;
                1
            }
        }
    }
}

#[cgroup_sock_addr(connect6)]
pub fn connect6(ctx: SockAddrContext) -> i32 {
    let Some(main_program_info) = MAIN_APP_INFO.get(0) else {
        return 1;
    };

    let bpf_sock_addr = unsafe { *ctx.sock_addr };
    let uid = ctx.uid();
    let gid = ctx.gid();
    let pid = ctx.pid();
    let tgid = ctx.tgid();

    if bpf_sock_addr.protocol != 6 || main_program_info.pid == tgid {
        // TCP
        return 1;
    }

    let ip = [
        bpf_sock_addr.user_ip6[0].swap_bytes(),
        bpf_sock_addr.user_ip6[1].swap_bytes(),
        bpf_sock_addr.user_ip6[2].swap_bytes(),
        bpf_sock_addr.user_ip6[3].swap_bytes(),
    ];

    let port = (bpf_sock_addr.user_port as u16).swap_bytes();

    let addr = SocketAddrCompat {
        ip,
        port,
        is_ipv6: true,
    };

    let mut rule = u32::MAX;
    let mut action = Action::Allow;
    let mut transport_id = u32::MAX;
    let mut r6 = unsafe { core::mem::zeroed::<ebpf_common::RuleV6>() };
    let base_offset = ((core::mem::size_of_val(&r6) - 16) * 8) as u32;

    r6.dst = ip;
    for flags in [7, 6, 5, 4, 3, 2, 1, 0] {
        r6.flags = flags;
        // r6.pid = 0;
        r6.port = 0;
        r6.uid = 0;

        if (flags & 2) == 2 {
            r6.port = port;
        }
        if (flags & 1) == 1 {
            r6.uid = uid;
        }

        let key = Key::new(base_offset + 128, r6);
        if let Some(v) = V6_RULES.get(&key) {
            if (flags & 4) == 4 {
                // has path
                if unsafe { PID_RULE_MAP.get(&(tgid, v.path_id)) }.is_some() {
                    // if rid == &(v.rule_id as u32) {
                    rule = v.rule_id;
                    action = v.action;
                    transport_id = v.transport_id;
                    break;
                    // }
                }
                continue;
                // r4.pid = pid;
            }
            rule = v.rule_id;
            action = v.action;
            transport_id = v.transport_id;
            break;
        }
    }
    if matches!(action, Action::Deny) {
        NETWORK_TUPLE.output(
            &ctx,
            &NetworkTuple {
                src: SocketAddrCompat {
                    ip: [0u32; 4],
                    port: 0,
                    is_ipv6: true,
                },
                dst: addr,
                actual_dst: addr,
                transport: u32::MAX,
                uid,
                gid,
                pid,
                tgid,
                rule,
            },
            0,
        );
        return 0;
    }
    let mut cgroup_info = unsafe { core::mem::zeroed::<CgroupInfo>() };
    cgroup_info.dst = addr;
    cgroup_info.uid = uid;
    cgroup_info.gid = gid;
    cgroup_info.pid = pid;
    cgroup_info.tgid = tgid;
    cgroup_info.rule = rule;
    cgroup_info.tag = 0;
    cgroup_info.transport = transport_id;

    let sock_cookie = unsafe {
        aya_ebpf::helpers::r#gen::bpf_get_socket_cookie(
            ctx.sock_addr as *const _ as *mut core::ffi::c_void,
        )
    };
    SOCKET_MARK_MAP
        .insert(&sock_cookie, &cgroup_info, 0)
        .unwrap();
    // mark_socket(
    //     ctx.sock_addr as *const _ as *mut core::ffi::c_void,
    //     cgroup_info,
    // );

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
        Action::Forward => {
            let Some(socket) = TRANSPORT.get(transport_id) else {
                return 0;
            };
            unsafe {
                (*ctx.sock_addr).user_ip6[0] = socket.ip[0].swap_bytes();
                (*ctx.sock_addr).user_ip6[1] = socket.ip[1].swap_bytes();
                (*ctx.sock_addr).user_ip6[2] = socket.ip[2].swap_bytes();
                (*ctx.sock_addr).user_ip6[3] = socket.ip[3].swap_bytes();
                (*ctx.sock_addr).user_port = socket.port.swap_bytes() as u32;
                1
            }
        }
    }
}

#[sock_ops]
pub fn bpf_sockops(ctx: SockOpsContext) -> u32 {
    return 1;
    let is_ipv6 = match ctx.family() {
        2 => false,
        10 => true,
        _ => {
            return 1;
        }
    };

    let sock_cookie = unsafe {
        aya_ebpf::helpers::r#gen::bpf_get_socket_cookie(
            ctx.ops as *const _ as *mut core::ffi::c_void,
        )
    };

    let Some(cgroup_info) = (unsafe { SOCKET_MARK_MAP.get(&sock_cookie) }) else {
        return 1;
    };

    if ctx.op() != 4 {
        // BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB
        return 0;
    }
    let remote_port = ctx.remote_port().swap_bytes() as u16;
    let local_port = ctx.local_port() as u16;

    let src = SocketAddrCompat {
        ip: ctx.local_ip6().map(|x| x.swap_bytes()),
        port: local_port,
        is_ipv6,
    };

    let dst = SocketAddrCompat {
        ip: ctx.remote_ip6().map(|x| x.swap_bytes()),
        port: remote_port,
        is_ipv6,
    };

    NETWORK_TUPLE.output(
        &ctx,
        &NetworkTuple {
            src,
            dst,
            actual_dst: cgroup_info.dst,
            transport: cgroup_info.transport,
            uid: cgroup_info.uid,
            gid: cgroup_info.gid,
            pid: cgroup_info.pid,
            tgid: cgroup_info.tgid,
            rule: cgroup_info.rule,
        },
        0,
    );
    1
}
