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
    pub number_of_active_rules: u32,
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
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default)]
pub enum Action {
    #[default]
    Allow,
    Deny,
    Forward,
    Proxy,
}
#[derive(Debug, Clone, Copy)]
pub struct Rule {
    pub action: Action,
    pub host: Host,
    pub port: Num,
    pub uid: Num,
    pub gid: Num,
    pub pid: Num,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Rule {}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Clone, Copy)]
pub enum Num {
    Singular(u32),
    Range(u32, u32),
    // Multi([u32; 10]),
    #[default]
    Any,
}

impl Num {
    pub fn matches(&self, num: u32) -> bool {
        match self {
            Num::Any => true,
            Num::Singular(n) => *n == num,
            Num::Range(start, end) => num >= *start && num <= *end,
        }
    }
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
        if ipv6.is_ipv6 == false {
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
#[repr(C, packed)]
pub struct NetworkTuple {
    pub src: SocketAddrCompat,
    pub dst: SocketAddrCompat,
    pub actual_dst: SocketAddrCompat,
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
    pub tgid: u32,
    pub rule: u32,
}

pub struct CgroupInfo {
    pub dst: SocketAddrCompat,
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
    pub tgid: u32,
    pub rule: u32,
    pub tag: u32,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct SocketAddrCompat {
    pub ip: [u32; 4],
    pub port: u16,
    pub is_ipv6: bool,
}

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
            return SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from_bits(self.ip[3]),
                self.port,
            ));
        }
    }
}
