use core::net::IpAddr;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub enum Action {
    Allow,
    Deny,
    Forward,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct Rule {
    pub action: Action,
    pub host: Host,
    pub port: Num,
    pub uid: Num,
    pub pid: Num,
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq)]
pub enum Num {
    Singular(u32),
    Range(u32, u32),
    // Multi([u32; 10]),
    #[default]
    Any,
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq)]
pub enum Host {
    Ip(IpAddr, u16),
    #[default]
    Any,
}
