use aya_ebpf::{
    EbpfContext,
    helpers::r#gen::bpf_get_prandom_u32,
    macros::{cgroup_sock_addr, map, sock_ops},
    maps::{Array, LpmTrie, LruHashMap, PerfEventArray, lpm_trie::Key},
    programs::{SockAddrContext, SockOpsContext},
};

use aya_log_ebpf::info;

use ebpf_common::{Action, CgroupInfo, LpmValue, MainProgramInfo, NetworkTuple, SocketAddrCompat};

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
pub static CGROUP_INFO: PerfEventArray<CgroupInfo> = PerfEventArray::new(0);

#[map]
pub static SOCKET_MARK_MAP: LruHashMap<u32, CgroupInfo> = LruHashMap::with_max_entries(1024, 0);

pub fn set_socket_mark(bpf_socket: *mut core::ffi::c_void, tag: u32) {
    unsafe {
        aya_ebpf::helpers::r#gen::bpf_setsockopt(
            bpf_socket,
            aya_ebpf::bindings::SOL_SOCKET as i32,
            aya_ebpf::bindings::SO_PRIORITY as i32,
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
            aya_ebpf::bindings::SO_PRIORITY as i32,
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
    let tgid = ctx.tgid();

    if bpf_sock_addr.protocol != 6 || main_program_info.pid == tgid {
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
    let mut transport_id = 0;
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
                if let Some(rid) = unsafe { PID_RULE_MAP.get(&tgid) } {
                    if rid == &(v.rule_id as u32) {
                        rule_id = v.rule_id;
                        action = v.action;
                        transport_id = v.transport_id;
                        break;
                    }
                }
                continue;
                // r4.pid = pid;
            }
            rule_id = v.rule_id;
            action = v.action;
            transport_id = v.transport_id;
            break;
        }
    }

    let mut cgroup_info = unsafe { core::mem::zeroed::<CgroupInfo>() };
    cgroup_info.dst = addr;
    cgroup_info.uid = uid;
    cgroup_info.gid = ctx.gid();
    cgroup_info.pid = pid;
    cgroup_info.tgid = tgid;
    cgroup_info.rule = rule_id;
    cgroup_info.tag = 0;
    // info!(
    //     &ctx,
    //     "connect4: {} {} ",
    //     cgroup_info.pid,
    //     cgroup_info.tgid,
    // );
    mark_socket(
        ctx.sock_addr as *const _ as *mut core::ffi::c_void,
        cgroup_info,
    );
    info!(&ctx, "connect4: {} {}", transport_id, rule_id);
    match action {
        Action::Deny => 0,
        Action::Allow => 1,
        Action::Proxy | Action::Forward => {
            let Some(socket) = TRANSPORT.get(transport_id) else {
                return 0;
            };
            unsafe {
                (*ctx.sock_addr).user_ip4 = socket.ip[3];
                (*ctx.sock_addr).user_port = (socket.port as u32).swap_bytes();
                1
            }
        } // Action::Forward => unsafe {
          //     (*ctx.sock_addr).user_ip4 =
          //         u32::from_ne_bytes(main_program_info.forward_v4_address.ip().octets());
          //     (*ctx.sock_addr).user_port =
          //         main_program_info.forward_v4_address.port().swap_bytes() as u32;
          //     1
          // },
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
    let tgid = ctx.tgid();

    if bpf_sock_addr.protocol != 6 || main_program_info.pid == tgid {
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
    let mut transport_id = 0;
    let mut r6 = unsafe { core::mem::zeroed::<ebpf_common::RuleV6>() };
    let base_offset = ((core::mem::size_of_val(&r6) - 4) * 8) as u32;
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
                if let Some(rid) = unsafe { PID_RULE_MAP.get(&tgid) } {
                    if rid == &(v.rule_id as u32) {
                        rule_id = v.rule_id;
                        action = v.action;
                        transport_id = v.transport_id;
                        break;
                    }
                }
                continue;
                // r4.pid = pid;
            }
            rule_id = v.rule_id;
            action = v.action;
            transport_id = v.transport_id;
            break;
        }
    }

    let mut cgroup_info = unsafe { core::mem::zeroed::<CgroupInfo>() };
    cgroup_info.dst = addr;
    cgroup_info.uid = uid;
    cgroup_info.gid = ctx.gid();
    cgroup_info.pid = pid;
    cgroup_info.tgid = tgid;
    cgroup_info.rule = rule_id;
    cgroup_info.tag = 0;

    mark_socket(
        ctx.sock_addr as *const _ as *mut core::ffi::c_void,
        cgroup_info,
    );

    match action {
        Action::Deny => 0,
        Action::Allow => 1,
        Action::Proxy | Action::Forward => {
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
        } // Action::Forward => unsafe {
          //     let ipv6 = u128_to_u32_array(main_program_info.forward_v6_address.ip().to_bits());
          //     (*ctx.sock_addr).user_ip6[0] = ipv6[0].swap_bytes();
          //     (*ctx.sock_addr).user_ip6[1] = ipv6[1].swap_bytes();
          //     (*ctx.sock_addr).user_ip6[2] = ipv6[2].swap_bytes();
          //     (*ctx.sock_addr).user_ip6[3] = ipv6[3].swap_bytes();
          //     (*ctx.sock_addr).user_port =
          //         main_program_info.forward_v6_address.port().swap_bytes() as u32;
          //     1
          // },
    }
}

#[sock_ops]
pub fn bpf_sockops(ctx: SockOpsContext) -> u32 {
    let Some(cgroup_info) = unmark_socket(ctx.ops as *mut core::ffi::c_void) else {
        return 1;
    };
    if ctx.op() != 4 {
        // BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB
        return 0;
    }
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
