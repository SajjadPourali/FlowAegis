#![no_std]
#![no_main]
use core::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use aya_ebpf::{
    EbpfContext,
    macros::{cgroup_sock_addr, map, sock_ops},
    maps::{Array, PerfEventArray},
    programs::{SockAddrContext, SockOpsContext},
};

use aya_log_ebpf::info;

use ebpf_common::{Action, CgroupInfo, MainProgramInfo, NetworkTuple, Rule};

#[map]
pub static RULES: Array<Rule> = Array::with_max_entries(256, 0);

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
    let port = (bpf_sock_addr.user_port as u16).swap_bytes();
    let uid = ctx.uid();
    let pid = ctx.pid();
    let mut rule_id = 0;
    let mut action = None;
    for i in 0..(main_program_info.number_of_active_rules).min(256) {
        let Some(rule) = RULES.get(i) else { return 1 };
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
    };

    CGROUP_INFO.output(&ctx, &cgroup_info, 0);
    match action {
        Action::Deny => 0,
        Action::Allow => 1,
        Action::Proxy => 1,
        Action::Forward => unsafe {
            info!(
                &ctx,
                "connect 4 {}",
                aya_ebpf::helpers::r#gen::bpf_get_current_task()
            );
            // (*(*ctx.sock_addr).__bindgen_anon_1.sk).src_port = 1;
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
    let dst_ip = Ipv6Addr::from_bits(u32_array_to_u128(bpf_sock_addr.user_ip6).swap_bytes());
    let port = bpf_sock_addr.user_port.swap_bytes() as u32;
    let uid = ctx.uid();
    let pid = ctx.pid();
    let mut rule_id = 0;
    let mut action = None;
    for i in 0..main_program_info.number_of_active_rules.min(256) {
        let Some(rule) = RULES.get(i) else { return 1 };
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
    };
    CGROUP_INFO.output(&ctx, &cgroup_info, 0);
    !matches!(action, Action::Deny) as i32
}

#[inline(always)]
fn u32_array_to_u128(arr: [u32; 4]) -> u128 {
    (arr[0] as u128) << 96 | (arr[1] as u128) << 64 | (arr[2] as u128) << 32 | (arr[3] as u128)
}

#[sock_ops]
pub fn bpf_sockops(ctx: SockOpsContext) -> u32 {
    if ctx.op() != 4 {
        // BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB
        return 0;
    }
    unsafe {
        info!(
            &ctx,
            "bpf_sockops {}",
            aya_ebpf::helpers::r#gen::bpf_get_current_task()
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
                Ipv6Addr::from(u32_array_to_u128(ctx.local_ip6()).swap_bytes()),
                local_port as u16,
                0,
                0,
            )),
            SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(u32_array_to_u128(ctx.remote_ip6()).swap_bytes()),
                remote_port as u16,
                0,
                0,
            )),
        )
    } else {
        return 0;
    };
    NETWORK_TUPLE.output(&ctx, &NetworkTuple { src, dst }, 0);
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // loop {}
    unsafe { core::hint::unreachable_unchecked() }
}
