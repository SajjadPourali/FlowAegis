use std::{collections::HashMap, mem, net::Ipv4Addr, ptr};

use aya::{
    maps::{
        AsyncPerfEventArray, HashMap as AyaHashMap, MapData, SockHash, SockMap,
        perf::PerfBufferError,
    },
    programs::{
        CgroupAttachMode, CgroupSockAddr, CgroupSockopt, SchedClassifier, SkMsg, SkSkb, SockOps,
        TcAttachType, tc,
    },
    util::online_cpus,
};
use aya_log::EbpfLogger;
use bytes::BytesMut;
use ebpf_common::{NetworkTuple, main_program_info::ACTIVE_RULES_NUM};
use rule::Rule;

mod rule;
use serde::{Deserialize, Serialize};
use tokio::{io::AsyncReadExt, task};

#[derive(Serialize, Deserialize, Debug)]
pub struct Rules {
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

    if let Err(e) = EbpfLogger::init(&mut ebpf) {
        dbg!(e);
        // This can happen if you remove all log statements from your eBPF program.
        // warn!("failed to initialize eBPF logger: {}", e);
    }
    // let o = EbpfLogger::init(&mut ebpf).unwrap();
    let mut main_app_info: aya::maps::Array<&mut aya::maps::MapData, u32> =
        aya::maps::Array::try_from(ebpf.map_mut("MAIN_APP_INFO").unwrap())?;
    main_app_info
        .set(
            rules.rules.len() as u32,
            ebpf_common::main_program_info::ACTIVE_RULES_NUM,
            0,
        )
        .unwrap();
    main_app_info
        .set(ACTIVE_RULES_NUM, rules.rules.len() as u32, 0)
        .unwrap();
    
    let mut array: aya::maps::Array<&mut aya::maps::MapData, ebpf_common::Rule> =
        aya::maps::Array::try_from(ebpf.map_mut("RULES").unwrap())?;
    for (index, (r_name, r)) in rules.rules.into_iter().enumerate() {
        let r = ebpf_common::Rule::from(r);
        // let output = postcard::to_slice(&r, &mut buf).unwrap().to_vec();
        // dbg!(r);
        // dbg!(output);
        // dbg!(buf);
        // dbg!(index);
        // let s = TryInto::<[u8; 100]>::try_into(&r).unwrap();
        // dbg!(&s);
        array.set(index as u32, &r, 0).unwrap();
    }
    // let output: Vec<u8, 11> = postcard::to_vec(&rules).unwrap().to_vec();
    // array.set(1,1u8,0);

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
    let mut sched_process_fork_event =
        AsyncPerfEventArray::try_from(ebpf.take_map("SCHED_PROCESS_FORK_EVENT").unwrap()).unwrap();

    for cpu_id in online_cpus().map_err(|(_, error)| error)? {
        // open a separate perf buffer for each cpu
        let mut buf = sched_process_fork_event.open(cpu_id, None)?;

        // process each perf buffer in a separate task
        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                // wait for events
                dbg!(1);
                let events = buf.read_events(&mut buffers).await?;
                dbg!(2);
                // events.read contains the number of events that have been read,
                // and is always <= buffers.len()
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let tuple = unsafe { ptr::read_unaligned(buf.as_ptr() as *const NetworkTuple) };
                    dbg!(tuple);
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
