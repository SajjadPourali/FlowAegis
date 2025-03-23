use ebpf_common::Action;
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, num::IntErrorKind};

fn default<T: Default + PartialEq>(t: &T) -> bool {
    *t == Default::default()
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Rule {
    pub action: Action,
    // #[serde(skip_serializing_if = "default")]
    // pub protocol: Protocol,
    #[serde(flatten)]
    #[serde(skip_serializing_if = "default")]
    pub host: Host,
    #[serde(default)]
    #[serde(skip_serializing_if = "default")]
    pub port: Num,
    #[serde(default)]
    #[serde(skip_serializing_if = "default")]
    pub uid: Num,
    #[serde(default)]
    #[serde(skip_serializing_if = "default")]
    pub gid: Num,
    #[serde(default)]
    #[serde(skip_serializing_if = "default")]
    pub pid: Num,
}
// #[derive(Serialize, Deserialize, Debug, Default, PartialEq)]
// pub enum Protocol {
//     #[default]
//     Tcp,
//     Udp,
// }

#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Clone, Copy)]
pub enum Host {
    Ip(IpAddr, u8),
    #[default]
    Any,
}

#[derive(Debug, Default, PartialEq)]
pub enum Num {
    Singular(u32),
    Range(u32, u32),
    // Multi(Vec<u32>),
    #[default]
    Any,
}

impl<'de> Deserialize<'de> for Num {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?
            .chars()
            .filter(|f| !f.is_whitespace())
            .collect::<String>();

        if s.is_empty() {
            return Ok(Num::Any);
        }
        if let Ok(n) = s.parse::<u32>() {
            return Ok(Num::Singular(n));
        }
        if let Some((start, end)) = s.split_once('-').and_then(|(s, e)| {
            s.parse::<u32>()
                .map_err(|e| {
                    if *e.kind() == IntErrorKind::Empty {
                        Some(0)
                    } else {
                        None
                    }
                })
                .ok()
                .and_then(|s| {
                    e.parse::<u32>()
                        .map_err(|e| {
                            if *e.kind() == IntErrorKind::Empty {
                                Some(0)
                            } else {
                                None
                            }
                        })
                        .ok()
                        .map(|e| (s, e))
                })
        }) {
            return Ok(Num::Range(start, end));
        }

        // if s.contains(',') {
        //     let nums: Result<Vec<u32>, _> = s.split(',').map(|x| x.parse::<u32>()).collect();
        //     if let Ok(values) = nums {
        //         return Ok(Num::Multi(values));
        //     }
        // }

        Err(serde::de::Error::custom("Invalid Format"))
    }
}

impl Serialize for Num {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Num::Any => serializer.serialize_str(""),
            Num::Singular(n) => serializer.serialize_str(&n.to_string()),
            Num::Range(start, end) => serializer.serialize_str(&format!("{}-{}", start, end)),
            // Num::Multi(nums) => {
            //     let nums_str = nums
            //         .iter()
            //         .map(|n| n.to_string())
            //         .collect::<Vec<_>>()
            //         .join(",");
            //     serializer.serialize_str(&nums_str)
            // }
        }
    }
}

impl From<Rule> for ebpf_common::Rule {
    fn from(v: Rule) -> Self {
        ebpf_common::Rule {
            action: v.action,
            host: ebpf_common::Host::from(v.host),
            port: ebpf_common::Num::from(v.port),
            uid: ebpf_common::Num::from(v.uid),
            gid: ebpf_common::Num::from(v.gid),
            pid: ebpf_common::Num::from(v.pid),
        }
    }
}

impl From<Host> for ebpf_common::Host {
    fn from(v: Host) -> Self {
        match v {
            Host::Ip(ip_addr, subnet_len) => match ip_addr {
                IpAddr::V4(ipv4) => {
                    ebpf_common::Host::Ipv4(u32::from(ipv4), !((1u32 << (32 - subnet_len)) - 1))
                }
                IpAddr::V6(ipv6) => {
                    ebpf_common::Host::Ipv6(u128::from(ipv6), !((1u128 << (128 - subnet_len)) - 1))
                }
            },
            Host::Any => ebpf_common::Host::Any,
        }
    }
}

impl From<Num> for ebpf_common::Num {
    fn from(v: Num) -> Self {
        match v {
            Num::Singular(v) => ebpf_common::Num::Singular(v),
            Num::Range(from, to) => ebpf_common::Num::Range(from, to),
            Num::Any => ebpf_common::Num::Any,
        }
    }
}
