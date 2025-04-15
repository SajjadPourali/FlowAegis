#![no_std]

// pub mod main_program_info {
//     pub const ACTIVE_RULES_NUM: u32 = 0;
//     pub const FORWARD_IPV4: u32 = 1;
//     pub const PROXY_IPV4: u32 = 2;
//     pub const FORWARD_IPV6_OCT1: u32 = 3;
//     pub const FORWARD_IPV6_OCT2: u32 = 4;
//     pub const FORWARD_IPV6_OCT3: u32 = 5;
//     pub const FORWARD_IPV6_OCT4: u32 = 6;
//     pub const PROXY_IPV6_OCT1: u32 = 7;
//     pub const PROXY_IPV6_OCT2: u32 = 8;
//     pub const PROXY_IPV6_OCT3: u32 = 9;
//     pub const PROXY_IPV6_OCT4: u32 = 10;
// }

#[derive(Clone, Copy, Debug)]
pub struct MainProgramInfo {
    pub uid: u32,
    pub pid: u32,
    pub forward_v4_address: SocketAddrV4,
    pub proxy_v4_address: SocketAddrV4,
    pub forward_v6_address: SocketAddrV6,
    pub proxy_v6_address: SocketAddrV6,
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for MainProgramInfo {}

#[cfg(feature = "user")]
use core::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use core::net::{SocketAddrV4, SocketAddrV6};

#[derive(Debug, Clone, Copy, Default)]
pub enum Action {
    #[default]
    Allow,
    Deny,
    Forward,
    Proxy,
}

#[derive(Debug, Default, PartialEq, Clone, Copy)]
pub enum Host {
    Ipv4(u32, u32),
    Ipv6(u128, u128),
    #[default]
    Any,
}

impl Host {
    pub fn matches_ipv4(&self, ipv4: SocketAddrCompat) -> bool {
        if ipv4.is_ipv6 && ipv4.ip[2] != u32::MAX {
            return false;
        };
        match self {
            Host::Any => true,
            Host::Ipv4(ip, mask) => {
                let ip = ip.to_be();
                let mask = mask.to_be();
                let ipv4 = ipv4.ip[3];
                (ip & mask) == (ipv4 & mask)
            }
            Host::Ipv6(_, _) => false,
        }
    }
    pub fn matches_ipv6(&self, ipv6: SocketAddrCompat) -> bool {
        if !ipv6.is_ipv6 {
            return false;
        };

        match self {
            Host::Any => true,
            Host::Ipv4(_, _) => false,
            Host::Ipv6(ip, mask) => {
                let ip = ip.to_be();
                let mask = mask.to_be();
                // let ipv6 = ipv6.to_bits().to_be();
                let ipv6 = (((ipv6.ip[0] as u128) << 96)
                    | ((ipv6.ip[1] as u128) << 64)
                    | ((ipv6.ip[2] as u128) << 32)
                    | (ipv6.ip[3] as u128))
                    .to_be();
                (ip & mask) == (ipv6 & mask)
            }
        }
    }
}

#[inline(always)]
pub fn u128_to_u32_array(value: u128) -> [u32; 4] {
    [
        (value >> 96) as u32,
        (value >> 64) as u32,
        (value >> 32) as u32,
        (value & 0xFFFF_FFFF) as u32,
    ]
}

#[repr(C, packed)]
pub struct NetworkTuple {
    pub src: SocketAddrCompat,
    pub dst: SocketAddrCompat,
    pub actual_dst: SocketAddrCompat,
    pub transport: u32,
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
    pub tgid: u32,
    pub rule: u32,
}

pub struct CgroupInfo {
    pub dst: SocketAddrCompat,
    pub transport: u32,
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
    pub tgid: u32,
    pub rule: u32,
    pub tag: u32,
}

#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct SocketAddrCompat {
    pub ip: [u32; 4],
    pub port: u16,
    pub is_ipv6: bool,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SocketAddrCompat {}
#[cfg(feature = "user")]
impl SocketAddrCompat {
    pub fn to_socket_addr(&self) -> SocketAddr {
        if self.is_ipv6 {
            SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from_bits(
                    ((self.ip[0] as u128) << 96)
                        | ((self.ip[1] as u128) << 64)
                        | ((self.ip[2] as u128) << 32)
                        | (self.ip[3] as u128),
                ),
                self.port,
                0,
                0,
            ))
        } else {
            SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from_bits(self.ip[3]),
                self.port,
            ))
        }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for RuleV4 {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for RuleV6 {}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct RuleV4 {
    pub flags: u16, // 1 = has port, 2 = has uid , 4 = has path
    pub port: u16,
    pub uid: u32,
    // pub pid: u32,
    pub dst: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct RuleV6 {
    pub flags: u16, // 1 = has port, 2 = has uid , 4 = has path
    pub port: u16,
    pub uid: u32,
    // pub pid: u32,
    pub dst: [u32; 4],
}

#[cfg(feature = "user")]
pub enum _Rule<V4, V6> {
    V4(V4),
    V6(V6),
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for LpmValue {}
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct LpmValue {
    pub rule_id: u32,
    pub transport_id: u32,
    pub path_id: u32,
    pub action: Action,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PathKey {}
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct PathKey {
    pub flags: u16, // 1 = has uid
    // pub path_len: u8,
    pub pid: u32,
    pub path: [u8; 128],
}
