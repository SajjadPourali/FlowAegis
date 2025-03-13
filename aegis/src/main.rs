use std::collections::HashMap;

use aya::maps::HashMap as AyaHashMap;
use rule::Rule;

mod rule;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Rules {
    rules: HashMap<String, Rule>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let r = rule::Rule {
        action: rule::Action::Forward,
        host: rule::Host::Any,
        port: rule::Num::Range(1, 10),
        uid: rule::Num::Multi(vec![1, 2, 3, 4]),
        pid: rule::Num::Any,
    };
    let r2 = rule::Rule {
        action: rule::Action::Forward,
        host: rule::Host::Domain("sss".to_string()),
        port: rule::Num::Range(1, 10),
        uid: rule::Num::Multi(vec![1, 2, 3, 4]),
        pid: rule::Num::Any,
    };
    let mut h = HashMap::default();
    h.insert("r1".to_string(), r);
    h.insert("r2".to_string(), r2);
    let rules = Rules { rules: h };
    let o = toml::to_string(&rules).unwrap();
    println!("{}", o);
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/ebpf"
    )))?;
    println!("Hello, world!");
    Ok(())
}
