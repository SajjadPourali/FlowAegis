#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{TC_ACT_OK, TC_ACT_PIPE, TC_ACT_SHOT},
    macros::{cgroup_skb, cgroup_sock, cgroup_sock_addr, classifier, map},
    maps::LruHashMap,
    programs::{SkBuffContext, SockAddrContext, SockContext, TcContext},
};
use aya_log_ebpf::info;
use cgroups::{NETWORK_TUPLE, SOCKET_MARK_MAP};
use ebpf_common::{NetworkTuple, SocketAddrCompat};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{self, IpHdr, IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

mod cgroups;
mod sched;

#[map]
pub static PID_RULE_MAP: LruHashMap<u32, u32> = LruHashMap::with_max_entries(1024, 0);

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IP6: u16 = 0x86DD;
// const SK_DROP: i32 = aya_ebpf::bindings::sk_action::SK_DROP as i32;
const SK_PASS: i32 = aya_ebpf::bindings::sk_action::SK_PASS as i32;

#[cgroup_skb]
pub fn cgroup_skb(ctx: SkBuffContext) -> i32 {
    let tag = unsafe { *ctx.skb.skb }.priority;

    let Some(cgroup_info) = (unsafe { SOCKET_MARK_MAP.get(&tag) }) else {
        return SK_PASS;
    };
    SOCKET_MARK_MAP.remove(&tag).unwrap();
    unsafe {
        (*ctx.skb.skb).priority = cgroup_info.tag;
    }

    let protocol = unsafe { (*ctx.skb.skb).protocol as u16 }.swap_bytes();

    let (src_addr, dst_addr, ipv6, proto) = match protocol {
        ETH_P_IP => {
            let ipv4hdr: Ipv4Hdr = ctx.load(0).map_err(|_| ()).unwrap();
            let src_addr = [0, 0, u32::MAX, ipv4hdr.src_addr];
            let dst_addr = [0, 0, u32::MAX, ipv4hdr.dst_addr];

            (src_addr, dst_addr, false, ipv4hdr.proto)
        }
        ETH_P_IP6 => {
            let ipv6hdr: Ipv6Hdr = ctx.load(0).map_err(|_| ()).unwrap();
            let src_addr = unsafe { ipv6hdr.src_addr.in6_u.u6_addr32 };
            let dst_addr = unsafe { ipv6hdr.dst_addr.in6_u.u6_addr32 };
            (src_addr, dst_addr, true, ipv6hdr.next_hdr)
        }
        _ => return SK_PASS,
    };
    let transport_base_offset = if ipv6 { Ipv6Hdr::LEN } else { Ipv4Hdr::LEN };
    match proto {
        IpProto::Tcp => {
            let tcphdr: TcpHdr = ctx.load(transport_base_offset).map_err(|_| ()).unwrap();

            let src = SocketAddrCompat {
                ip: src_addr.map(|x| x.swap_bytes()),
                port: tcphdr.source.swap_bytes(),
                is_ipv6: ipv6,
            };
            let dst = SocketAddrCompat {
                ip: dst_addr.map(|x| x.swap_bytes()),
                port: tcphdr.dest,
                is_ipv6: ipv6,
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
        }
        IpProto::Udp => {
            let udphdr: UdpHdr = ctx.load(transport_base_offset).map_err(|_| ()).unwrap();
            info!(&ctx, "udp");
        }
        _ => return SK_PASS,
    }
    SK_PASS
}
