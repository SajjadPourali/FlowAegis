#![no_std]
#![no_main]
use core::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use aya_ebpf::{
    EbpfContext,
    helpers::r#gen::bpf_get_prandom_u32,
    macros::{cgroup_sock_addr, map, sock_ops},
    maps::{Array, PerfEventArray},
    programs::{SockAddrContext, SockOpsContext},
};

use aya_log_ebpf::info;

use ebpf_common::{Action, CgroupInfo, MainProgramInfo, NetworkTuple, Rule};

#[map]
pub static TCP_RULES: Array<Rule> = Array::with_max_entries(256, 0);

#[map]
pub static MAIN_APP_INFO: Array<MainProgramInfo> = Array::with_max_entries(100, 0);

#[map]
pub static NETWORK_TUPLE: PerfEventArray<NetworkTuple> = PerfEventArray::new(0);

#[map]
pub static CGROUP_INFO: PerfEventArray<CgroupInfo> = PerfEventArray::new(0);

#[cgroup_sock_addr(connect4)]
pub fn connect4(ctx: SockAddrContext) -> i32 {
    
    let Some(main_program_info) = MAIN_APP_INFO.get(0) else {
        return 1;
    };

    let bpf_sock_addr = unsafe { *ctx.sock_addr };
    if bpf_sock_addr.protocol != 6 {
        // TCP
        return 1;
    }
    let dst_ip = Ipv4Addr::from_bits(bpf_sock_addr.user_ip4.swap_bytes());

    // Tagging the socket with the tag value
    let tag = unsafe {
        let tag = bpf_get_prandom_u32();
        aya_ebpf::helpers::r#gen::bpf_setsockopt(
            ctx.sock_addr as *const _ as *mut core::ffi::c_void,
            aya_ebpf::bindings::SOL_SOCKET as i32,
            aya_ebpf::bindings::SO_MARK as i32,
            &tag as *const _ as *mut core::ffi::c_void,
            core::mem::size_of_val(&tag) as i32,
        );
        tag
    };
    let port = (bpf_sock_addr.user_port as u16).swap_bytes();
    let uid = ctx.uid();
    let pid = ctx.pid();
    let mut rule_id = 0;
    let mut action = None;
    for i in 0..(main_program_info.number_of_active_rules).min(256) {
        let Some(rule) = TCP_RULES.get(i) else {
            return 1;
        };
        if rule.host.matches_ipv4(dst_ip)
            && rule.port.matches(port as u32)
            && rule.uid.matches(uid)
            && rule.pid.matches(pid)
        {
            action = Some(rule.action);
            rule_id = i;
            break;
        }
    }
    let Some(action) = action else { return 1 };

    let cgroup_info = CgroupInfo {
        dst: SocketAddr::V4(SocketAddrV4::new(dst_ip, port as u16)),
        uid,
        gid: ctx.gid(),
        pid,
        tgid: ctx.tgid(),
        rule: rule_id,
        tag,
    };

    CGROUP_INFO.output(&ctx, &cgroup_info, 0);
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
    if bpf_sock_addr.protocol != 6 {
        // TCP
        return 1;
    }
    let dst_ip = Ipv6Addr::from_bits(u32_array_to_u128(bpf_sock_addr.user_ip6));
    // Tagging the socket with the tag value
    let tag = unsafe {
        let tag = bpf_get_prandom_u32();
        aya_ebpf::helpers::r#gen::bpf_setsockopt(
            ctx.sock_addr as *const _ as *mut core::ffi::c_void,
            aya_ebpf::bindings::SOL_SOCKET as i32,
            aya_ebpf::bindings::SO_MARK as i32,
            &tag as *const _ as *mut core::ffi::c_void,
            core::mem::size_of_val(&tag) as i32,
        );
        tag
    };
    let port = (bpf_sock_addr.user_port as u16).swap_bytes();
    let uid = ctx.uid();
    let pid = ctx.pid();
    let mut rule_id = 0;
    let mut action = None;
    for i in 0..main_program_info.number_of_active_rules.min(256) {
        let Some(rule) = TCP_RULES.get(i) else {
            return 1;
        };
        if rule.host.matches_ipv6(dst_ip)
            && rule.port.matches(port as u32)
            && rule.uid.matches(uid)
            && rule.pid.matches(pid)
        {
            action = Some(rule.action);
            rule_id = i;
            break;
        }
    }

    let Some(action) = action else { return 1 };

    let cgroup_info = CgroupInfo {
        dst: SocketAddr::V6(SocketAddrV6::new(dst_ip, port as u16, 0, 0)),
        uid,
        gid: ctx.gid(),
        pid,
        tgid: ctx.tgid(),
        rule: rule_id,
        tag,
    };
    CGROUP_INFO.output(&ctx, &cgroup_info, 0);
    match action {
        Action::Deny => 0,
        Action::Allow => 1,
        Action::Proxy => 1,
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

#[inline(always)]
fn u32_array_to_u128(arr: [u32; 4]) -> u128 {
    (arr[0].swap_bytes() as u128) << 96
        | (arr[1].swap_bytes() as u128) << 64
        | (arr[2].swap_bytes() as u128) << 32
        | (arr[3].swap_bytes() as u128)
    // (arr[3] as u128) << 96 | (arr[2] as u128) << 64 | (arr[1] as u128) << 32 | (arr[0] as u128)
}

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
    if ctx.op() != 4 {
        // BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB
        return 0;
    }

    let mut tag: u32 = 0;
    let tag_size = core::mem::size_of_val(&tag) as i32;

    unsafe {
        aya_ebpf::helpers::r#gen::bpf_getsockopt(
            ctx.ops as *mut core::ffi::c_void,
            aya_ebpf::bindings::SOL_SOCKET as i32,
            aya_ebpf::bindings::SO_MARK as i32,
            &mut tag as *mut _ as *mut core::ffi::c_void,
            tag_size,
        );
    }
    let remote_port = ctx.remote_port().swap_bytes();
    let local_port = ctx.local_port();
    let (src, dst) = if ctx.family() == 2 {
        // IPv4
        (
            SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from_bits(ctx.local_ip4().swap_bytes()),
                local_port as u16,
            )),
            SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from_bits(ctx.remote_ip4().swap_bytes()),
                remote_port as u16,
            )),
        )
    } else if ctx.family() == 10 {
        // IPv6
        (
            SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(u32_array_to_u128(ctx.local_ip6())),
                local_port as u16,
                0,
                0,
            )),
            SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(u32_array_to_u128(ctx.remote_ip6())),
                remote_port as u16,
                0,
                0,
            )),
        )
    } else {
        return 0;
    };
    NETWORK_TUPLE.output(&ctx, &NetworkTuple { src, dst, tag }, 0);
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // loop {}
    unsafe { core::hint::unreachable_unchecked() }
}
