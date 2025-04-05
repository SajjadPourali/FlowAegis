use ebpf_common::{_Rule, Action, RuleV4, RuleV6, u128_to_u32_array};
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, u32};

fn default<T: Default + PartialEq>(t: &T) -> bool {
    *t == Default::default()
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Rule {
    pub action: Action,
    // #[serde(flatten)]
    #[serde(skip_serializing_if = "default")]
    pub host: Option<Host>,
    #[serde(default)]
    #[serde(skip_serializing_if = "default")]
    pub port: Vec<u16>,
    #[serde(default)]
    #[serde(skip_serializing_if = "default")]
    pub uid: Vec<u32>,
    #[serde(default)]
    #[serde(skip_serializing_if = "default")]
    pub path: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Copy)]
pub struct Host(pub IpAddr, pub u8);

impl From<Rule> for Vec<(ebpf_common::_Rule<RuleV4, RuleV6>, u8)> {
    fn from(value: Rule) -> Self {
        let mut rules = Vec::new();
        let mut flags = 0;
        let ports = if value.port.is_empty() {
            vec![0]
        } else {
            flags |= 2;
            value.port
        };
        let uids = if value.uid.is_empty() {
            vec![0]
        } else {
            flags |= 1;
            value.uid
        };
        if !value.path.is_empty() {
            flags |= 4;
        }
        for port in ports {
            for uid in &uids {
                match value.host {
                    Some(Host(ip_addr, prefix)) => match ip_addr {
                        IpAddr::V4(ipv4_addr) => rules.push((
                            _Rule::V4(RuleV4 {
                                flags,
                                port,
                                uid: *uid,
                                dst: ipv4_addr.to_bits(),
                            }),
                            prefix,
                        )),
                        IpAddr::V6(ipv6_addr) => rules.push((
                            _Rule::V6(RuleV6 {
                                flags,
                                port,
                                uid: *uid,
                                dst: u128_to_u32_array(ipv6_addr.to_bits()),
                            }),
                            prefix,
                        )),
                    },
                    None => {
                        rules.push((
                            _Rule::V4(RuleV4 {
                                flags,
                                port,
                                uid: *uid,
                                dst: 0,
                            }),
                            0,
                        ));
                        rules.push((
                            _Rule::V6(RuleV6 {
                                flags,
                                port,
                                uid: *uid,
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
        let Host(ip_addr, subnet_len) = v;
        // match v {
        match ip_addr {
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
        }
        //     None => ebpf_common::Host::Any,
        // }
    }
}
