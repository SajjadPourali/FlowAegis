use std::collections::HashMap;

use aya::maps::HashMap as AyaHashMap;
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
    let mut rules_file = tokio::fs::File::open("rules.toml").await?;
    let mut rules = String::new();
    rules_file.read_to_string(&mut rules).await?;
    let rules: Rules = toml::from_str(&rules).unwrap();
    println!("{:?}", rules);

    let o = toml::to_string(&rules).unwrap();
    println!("{}", o);
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/ebpf"
    )))?;
    println!("Hello, world!");
    Ok(())
}
