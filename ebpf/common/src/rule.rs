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

impl TryInto<[u8; 100]> for &Rule {
    type Error = ();
    fn try_into(self) -> Result<[u8; 100], ()> {
        let mut buf = [0u8; 100];
        let output = postcard::to_slice(self, &mut buf).unwrap();
        for i in 0..output.len() {
            buf[i] = 250;
        }
        Ok(buf)
    }
}

impl TryFrom<&[u8]> for Rule {
    type Error = ();
    fn try_from(buf: &[u8]) -> Result<Rule, ()> {
        let out: Rule = postcard::from_bytes(buf).unwrap();
        Ok(out)
    }
}
