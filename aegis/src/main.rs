use std::{
    collections::HashMap,
    net::{SocketAddrV4, SocketAddrV6},
    ptr,
};

use aya::{
    maps::{AsyncPerfEventArray, perf::PerfBufferError},
    programs::{CgroupAttachMode, CgroupSockAddr, SockOps},
    util::online_cpus,
};
use aya_log::EbpfLogger;
use bytes::BytesMut;
use ebpf_common::{CgroupInfo, MainProgramInfo, NetworkTuple};
use rule::Rule;

mod rule;
use serde::{Deserialize, Serialize};
use tokio::{io::AsyncReadExt, select, task};

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    proxy_address_ipv4: SocketAddrV4,
    forward_address_ipv4: SocketAddrV4,
    proxy_address_ipv6: SocketAddrV6,
    forward_address_ipv6: SocketAddrV6,
    rules: HashMap<String, Rule>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    log::info!("starting up");
    rlimit::increase_nofile_limit(rlimit::INFINITY).ok();
    rlimit::setrlimit(
        rlimit::Resource::MEMLOCK,
        rlimit::INFINITY,
        rlimit::INFINITY,
    )
    .unwrap();

    let mut config_file = tokio::fs::File::open("rules.toml").await?;
    let mut rules = String::new();
    config_file.read_to_string(&mut rules).await?;
    let config: Config = toml::from_str(&rules).unwrap();
    // let r = Rule {
    //     action: ebpf_common::Action::Allow,
    //     ..Default::default()
    // };
    // let mut rules = Config {
    //     rules: HashMap::new(),
    //     proxy_address_ipv4: Ipv4Addr::BROADCAST,
    //     forward_address_ipv4: Ipv4Addr::BROADCAST,
    //     proxy_address_ipv6: Ipv6Addr::LOCALHOST,
    //     forward_address_ipv6: Ipv6Addr::LOCALHOST,
    // };

    // let o = toml::to_string(&r).unwrap();
    // println!("{}", o);
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
    let o = toml::to_string(&config).unwrap();
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
    let main_program_info = MainProgramInfo {
        uid: 0,
        pid: 0,
        number_of_active_rules: config.rules.len() as u32,
        forward_v4_address: config.forward_address_ipv4,
        proxy_v4_address: config.proxy_address_ipv4,
        forward_v6_address: config.forward_address_ipv6,
        proxy_v6_address: config.proxy_address_ipv6,
    };
    let mut main_program_info_map: aya::maps::Array<&mut aya::maps::MapData, MainProgramInfo> =
        aya::maps::Array::try_from(ebpf.map_mut("MAIN_APP_INFO").unwrap())?;
    main_program_info_map.set(0, main_program_info, 0).unwrap();

    let mut array: aya::maps::Array<&mut aya::maps::MapData, ebpf_common::Rule> =
        aya::maps::Array::try_from(ebpf.map_mut("RULES").unwrap())?;
    let mut rule_names = Vec::with_capacity(config.rules.len());
    for (index, (r_name, r)) in config.rules.into_iter().enumerate() {
        let r = ebpf_common::Rule::from(r);
        rule_names.push(r_name);
        array.set(index as u32, &r, 0).unwrap();
    }

    let cgroup = std::fs::File::open("/sys/fs/cgroup").unwrap();
    for prog in vec!["connect4", "connect6"] {
        //, "bpf_sockops"
        let program: &mut CgroupSockAddr = ebpf.program_mut(prog).unwrap().try_into().unwrap();

        program.load().unwrap();
        program.attach(&cgroup, CgroupAttachMode::Single).unwrap();
    }

    let program: &mut SockOps = ebpf.program_mut("bpf_sockops").unwrap().try_into().unwrap();
    program.load().unwrap();
    program.attach(&cgroup, CgroupAttachMode::Single).unwrap();
    let mut network_tuple =
        AsyncPerfEventArray::try_from(ebpf.take_map("NETWORK_TUPLE").unwrap()).unwrap();
    let mut cgroup_info =
        AsyncPerfEventArray::try_from(ebpf.take_map("CGROUP_INFO").unwrap()).unwrap();

    for cpu_id in online_cpus().map_err(|(_, error)| error)? {
        // open a separate perf buffer for each cpu
        let mut network_tuple_buf = network_tuple.open(cpu_id, None)?;
        let mut cgroup_info_buf = cgroup_info.open(cpu_id, None)?;

        // process each perf buffer in a separate task
        task::spawn(async move {
            let mut network_tuple_buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();
            let mut cgroup_info_buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                // wait for events
                select! {
                    Ok(events) = network_tuple_buf.read_events(&mut network_tuple_buffers) =>{
                        for i in 0..events.read {
                            let buf = &mut network_tuple_buffers[i];
                            let tuple = unsafe { ptr::read_unaligned(buf.as_ptr() as *const NetworkTuple) };
                            dbg!(tuple);
                        }
                    }
                    Ok(events) = cgroup_info_buf.read_events(&mut cgroup_info_buffers) =>{
                        for i in 0..events.read {
                            let buf = &mut cgroup_info_buffers[i];
                            let tuple = unsafe { ptr::read_unaligned(buf.as_ptr() as *const CgroupInfo) };
                            dbg!(tuple);
                        }
                    }
                }
            }

            Ok::<_, PerfBufferError>(())
        });
    }
    // prog.attach(&map_fd)?;
    println!("Hello, world!");
    let ctrl_c = tokio::signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");
    Ok(())
}
