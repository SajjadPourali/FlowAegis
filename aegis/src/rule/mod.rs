use ebpf_common::{_Rule, Action, RuleV4, RuleV6, u128_to_u32_array};
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, u32};

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
    pub port: Vec<u16>,
    #[serde(default)]
    #[serde(skip_serializing_if = "default")]
    pub uid: Vec<u32>,
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

impl From<Rule> for Vec<(ebpf_common::_Rule, u8)> {
    fn from(value: Rule) -> Self {
        let mut rules = Vec::new();
        let mut flags = 0;
        let ports = if value.port.is_empty() {
            vec![0]
        } else {
            flags += 2;
            value.port
        };
        let uids = if value.uid.is_empty() {
            vec![0]
        } else {
            flags += 1;
            value.uid
        };
        for port in ports {
            for uid in &uids {
                match value.host {
                    Host::Ip(ip_addr, prefix) => match ip_addr {
                        IpAddr::V4(ipv4_addr) => rules.push((
                            _Rule::V4(RuleV4 {
                                flags,
                                port,
                                uid: *uid,
                                pid: 0,
                                dst: ipv4_addr.to_bits(),
                            }),
                            prefix,
                        )),
                        IpAddr::V6(ipv6_addr) => rules.push((
                            _Rule::V6(RuleV6 {
                                flags,
                                port,
                                uid: *uid,
                                pid: 0,
                                dst: u128_to_u32_array(ipv6_addr.to_bits()),
                            }),
                            prefix,
                        )),
                    },
                    Host::Any => {
                        rules.push((
                            _Rule::V4(RuleV4 {
                                flags,
                                port,
                                uid: *uid,
                                pid: 0,
                                dst: 0,
                            }),
                            0,
                        ));
                        rules.push((
                            _Rule::V6(RuleV6 {
                                flags,
                                port,
                                uid: *uid,
                                pid: 0,
                                dst: [0, 0, 0, 0],
                            }),
                            0,
                        ));
                    }
                }
            }
        }
        rules
    }
}

impl From<Host> for ebpf_common::Host {
    fn from(v: Host) -> Self {
        match v {
            Host::Ip(ip_addr, subnet_len) => match ip_addr {
                IpAddr::V4(ipv4) => {
                    let ip = u32::from_be_bytes(ipv4.octets());
                    let mask = if subnet_len == 0 {
                        0
                    } else {
                        !((1u32 << (32 - subnet_len)) - 1)
                    };
                    ebpf_common::Host::Ipv4(ip, mask)
                }
                IpAddr::V6(ipv6) => {
                    let ip = u128::from_be_bytes(ipv6.octets());
                    let mask = if subnet_len == 0 {
                        0
                    } else {
                        !((1u128 << (128 - subnet_len)) - 1)
                    };
                    ebpf_common::Host::Ipv6(ip, mask)
                }
            },
            Host::Any => ebpf_common::Host::Any,
        }
    }
}
