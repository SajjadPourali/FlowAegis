#![no_std]

pub mod main_program_info {
    pub const ACTIVE_RULES_NUM: u32 = 0;
}

use core::net::{IpAddr, SocketAddr};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub enum Action {
    Allow,
    Deny,
    Forward,
}
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
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

#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Clone, Copy)]
pub enum Host {
    Ip(IpAddr, u8),
    #[default]
    Any,
}

impl Host {
    pub fn matches(&self, ip: IpAddr) -> bool {
        match self {
            Host::Any => true,
            Host::Ip(subnet, subnet_len) => match (ip, subnet) {
                (IpAddr::V4(ipv4), IpAddr::V4(subnet_ipv4)) => {
                    let ip_u32 = u32::from(ipv4);
                    let subnet_u32 = u32::from(*subnet_ipv4);
                    let netmask_u32 = !((1u32 << (32 - subnet_len)) - 1);

                    (ip_u32 & netmask_u32) == (subnet_u32 & netmask_u32)
                }
                (IpAddr::V6(ipv6), IpAddr::V6(subnet_ipv6)) => {
                    let ip_u128 = u128::from(ipv6);
                    let subnet_u128 = u128::from(*subnet_ipv6);
                    let mask_u128 = !((1u128 << (128 - subnet_len)) - 1);

                    (ip_u128 & mask_u128) == (subnet_u128 & mask_u128)
                }
                _ => false,
            },
        }
    }
}

// impl TryInto<[u8; 100]> for &Rule {
//     type Error = ();
//     fn try_into(self) -> Result<[u8; 100], ()> {
//         let mut buf = [0u8; 100];
//         let output = postcard::to_slice(self, &mut buf).unwrap();
//         for i in 0..output.len() {
//             buf[i] = 250;
//         }
//         Ok(buf)
//     }
// }

// impl TryFrom<&[u8]> for Rule {
//     type Error = ();
//     fn try_from(buf: &[u8]) -> Result<Self, ()> {
//         let out = postcard::from_bytes(buf).unwrap();
//         Ok(out)
//     }
// }

#[derive(Debug)]
pub struct NetworkTuple {
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

// impl TryFrom<&[u8]> for NetworkTuple {
//     type Error = ();
//     fn try_from(buf: &[u8]) -> Result<Self, ()> {
//         let out = postcard::from_bytes(buf).unwrap();

//         Ok(out)
//     }
// }
// impl Into<[u8; 36]> for &NetworkTuple {
//     fn into(self) -> [u8; 36] {
//         let mut buf = [2u8; 36];
//         let output = postcard::to_slice(self, &mut buf).unwrap();
//         // for i in 0..output.len() {
//         //     buf[i] = 250;
//         // }
//         buf
//     }
// }

#[derive(Debug)]
pub struct CgroupInfo {
    pub action: Action,
    pub dst: SocketAddr,
    pub uid: u32,
    pub pid: u32,
    pub tgid: u32,
}
