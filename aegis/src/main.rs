use std::{collections::HashMap, net::Ipv4Addr};

use aya::maps::HashMap as AyaHashMap;
use aya_log::EbpfLogger;
use rule::Rule;

mod rule;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;

#[derive(Serialize, Deserialize, Debug)]
pub struct Rules {
    rules: HashMap<String, Rule>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    rlimit::increase_nofile_limit(rlimit::INFINITY).ok();
    rlimit::setrlimit(
        rlimit::Resource::MEMLOCK,
        rlimit::INFINITY,
        rlimit::INFINITY,
    )
    .unwrap();

    let mut rules_file = tokio::fs::File::open("rules.toml").await?;
    let mut rules = String::new();
    rules_file.read_to_string(&mut rules).await?;
    let rules: Rules = toml::from_str(&rules).unwrap();
    /*
    let mut rules = Rules{
        rules: HashMap::new()
    };
    let rule = Rule {
        action: ebpf_common::Action::Forward,
        host: ebpf_common::Host::Ip(std::net::IpAddr::V4(Ipv4Addr::BROADCAST), 8080),
        port: rule::Num::Any,
        uid: rule::Num::Any,
        pid: rule::Num::Any,
    };
    rules.rules.insert("a".to_string(), rule);


    println!("{:?}", rules);
    */
    let o = toml::to_string(&rules).unwrap();
    println!("{}", o);
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/ebpf"
    )))?;
    // if let Err(e) = EbpfLogger::init(&mut ebpf) {
    //     dbg!(e);
    //     // This can happen if you remove all log statements from your eBPF program.
    //     // warn!("failed to initialize eBPF logger: {}", e);
    // }
    let o = EbpfLogger::init(&mut ebpf).unwrap();
    let mut array: aya::maps::Array<&mut aya::maps::MapData, [u8; 32]> =
        aya::maps::Array::try_from(ebpf.map_mut("RULES").unwrap())?;
    let mut buf = [0u8; 32];
    for (r_name, r) in rules.rules {
        let r = ebpf_common::Rule::from(r);
        let output = postcard::to_slice(&r, &mut buf).unwrap().to_vec();
        dbg!(r);
        dbg!(output);
        dbg!(buf);

        array.set(1, buf, 0).unwrap();
    }
    // let output: Vec<u8, 11> = postcard::to_vec(&rules).unwrap().to_vec();
    // array.set(1,1u8,0);

    println!("Hello, world!");
    Ok(())
}
