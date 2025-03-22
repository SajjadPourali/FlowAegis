#![no_std]
#![no_main]
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use aya_ebpf::{
    EbpfContext,
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_uid_gid, r#gen::bpf_ktime_get_ns},
    macros::{cgroup_sock_addr, map, sock_ops},
    maps::{Array, PerfEventArray},
    programs::{SockAddrContext, SockOpsContext},
};
use aya_log_ebpf::info;
use ebpf_common::{main_program_info::ACTIVE_RULES_NUM, NetworkTuple, Num, Rule};

#[map]
pub static RULES: Array<Rule> = Array::with_max_entries(2048, 0);

#[map]
pub static MAIN_APP_INFO: Array<u32> = Array::with_max_entries(100, 0);

#[map]
pub static SCHED_PROCESS_FORK_EVENT: PerfEventArray<NetworkTuple> = PerfEventArray::new(0);

#[cgroup_sock_addr(connect4)]
pub fn connect4(ctx: SockAddrContext) -> i32 {
    // let uid = bpf_get_current_uid_gid() as u32;
    let Some(num_rules) = MAIN_APP_INFO.get(ACTIVE_RULES_NUM) else {
        return 1;
    };
    let mut bpf_sock_addr = unsafe { *ctx.sock_addr };
    let dst_ip = IpAddr::V4(Ipv4Addr::from_bits(bpf_sock_addr.user_ip4.swap_bytes()));
    let o = *num_rules;
    info!(&ctx, "connect4 {}", *num_rules);
    // let i = RULES.get_ptr(1).unwrap();
    for i in 0..o.min(2048) {
        // info!(&ctx, "connect4 {}", i);
        let rule = RULES.get(i).unwrap();
        // if rule.host.matches(dst_ip) {
        if rule.gid == Num::Any {
            info!(&ctx, "connect4 {}",1);
        }
        // }
    }

    bpf_sock_addr.user_ip6[0] = 100;

    let transport_protocol = bpf_sock_addr.user_ip6[0] as u16;
    // unsafe{(*ctx.sock_addr).user_ip4 = 0};
    let transport_protocol = unsafe { *ctx.sock_addr }.user_ip4;
    // let cookie = unsafe{bpf_get_socket_cookie(transport_protocol)};
    // #[derive(Debug)]
    // pub struct CgroupInfo {
    //     pub action: Action,
    //     pub dst: SocketAddr,
    //     pub uid: u32,
    //     pub pid: u32,
    //     pub tgid: u32,
    // }
    info!(
        &ctx,
        "connect4 {} - {}",
        unsafe { bpf_ktime_get_ns() },
        transport_protocol
    );

    let bpf_sock_addr = unsafe { *ctx.sock_addr };
    let transport_protocol = bpf_sock_addr.protocol as u16;
    1
}

#[cgroup_sock_addr(connect6)]
pub fn connect6(ctx: SockAddrContext) -> i32 {
    // let uid = bpf_get_current_uid_gid() as u32;
    info!(&ctx, "connect6 {}", 1);
    let bpf_sock_addr = unsafe { *ctx.sock_addr };
    let transport_protocol = bpf_sock_addr.protocol as u16;

    1
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
    SCHED_PROCESS_FORK_EVENT.output(&ctx, &NetworkTuple { src, dst }, 0);
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // loop {}
    unsafe { core::hint::unreachable_unchecked() }
}
