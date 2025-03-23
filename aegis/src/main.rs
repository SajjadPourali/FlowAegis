use aya::{
    maps::AsyncPerfEventArray,
    programs::{CgroupAttachMode, CgroupSockAddr, SockOps},
    util::online_cpus,
};
use futures::{
    Stream, StreamExt,
    stream::{self, select_all},
};
use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6},
    pin::Pin,
    ptr,
};
// use aya_log::EbpfLogger;
use bytes::BytesMut;
use ebpf_common::{Action, CgroupInfo, MainProgramInfo, NetworkTuple};
use rule::Rule;

mod rule;
use serde::{Deserialize, Serialize};
use tokio::{io::AsyncReadExt, select};

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
    // let listener_4 = TcpListener::bind("127.0.0.1:0").await?;

    // let SocketAddr::V4(proxy_addr) = listener_4.local_addr().unwrap() else {
    //     return Ok(());
    // };
    // tokio::spawn(async move {
    //     loop {
    //         let (mut socket, _) = listener_4.accept().await.unwrap();
    //         dbg!(socket.peer_addr().unwrap());
    //         tokio::spawn(async move {
    //             let mut buf = [0; 1024];
    //             loop {
    //                 let n = socket.read(&mut buf).await.unwrap();
    //                 dbg!(&buf[..n]);
    //                 if n == 0 {
    //                     break;
    //                 }
    //             }
    //         });
    //     }
    // });
    env_logger::init();
    log::info!("starting up");

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
    // let o = toml::to_string(&config).unwrap();
    let mut ebpf = Ebpf::new();
    ebpf.set_forward_v4_address(config.forward_address_ipv4);
    ebpf.set_proxy_v4_address(config.proxy_address_ipv4);
    ebpf.set_forward_v6_address(config.forward_address_ipv6);
    ebpf.set_proxy_v6_address(config.proxy_address_ipv6);
    ebpf.set_rules(config.rules);
    ebpf.load_main_program_info();
    ebpf.load_cgroups();
    let mut o = AsyncPerfEventArrayStream::<NetworkTuple>::new(
        ebpf.inner.take_map("NETWORK_TUPLE").unwrap(),
    );
    let mut c =
        AsyncPerfEventArrayStream::<CgroupInfo>::new(ebpf.inner.take_map("CGROUP_INFO").unwrap());
    loop {
        select! {
            Some(tuple) = o.next() => {
                dbg!(tuple);
            }
            Some(cgroup_info) = c.next() => {
                dbg!(cgroup_info);
            }
        }
    }
    // let ctrl_c = tokio::signal::ctrl_c();
    // println!("Waiting for Ctrl-C...");
    // ctrl_c.await?;
    // println!("Exiting...");
    // Ok(())
}

pub struct AsyncPerfEventArrayStream<T> {
    streams: stream::SelectAll<Pin<Box<dyn Stream<Item = T>>>>,
    _marker: std::marker::PhantomData<T>,
}

impl<T> AsyncPerfEventArrayStream<T> {
    pub fn new(map: aya::maps::Map) -> Self {
        let mut async_perf_event_array = AsyncPerfEventArray::try_from(map).unwrap();
        let mut streams: Vec<Pin<Box<dyn Stream<Item = T>>>> = Vec::new();
        for cpu_id in online_cpus().map_err(|(_, error)| error).unwrap() {
            let async_perf_event_array_buffer = async_perf_event_array.open(cpu_id, None).unwrap();
            let buf = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();
            streams.push(Box::pin(stream::unfold::<_, _, _, T>(
                (async_perf_event_array_buffer, buf),
                move |(mut async_perf_event_array_buffer, mut buf)| async {
                    let events = async_perf_event_array_buffer
                        .read_events(&mut buf)
                        .await
                        .unwrap();
                    for i in 0..events.read {
                        let b = &mut buf[i];
                        let tuple = unsafe { ptr::read_unaligned(b.as_ptr() as *const T) };
                        return Some((tuple, (async_perf_event_array_buffer, buf)));
                    }
                    None
                },
            )));
        }
        Self {
            streams: select_all(streams),
            _marker: std::marker::PhantomData,
        }
    }
}

impl<T: std::marker::Unpin> futures::Stream for AsyncPerfEventArrayStream<T> {
    type Item = T;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.streams.poll_next_unpin(cx)
    }
}

pub struct ExpirableQueue {}

const CGROUP_PATH: &str = "/sys/fs/cgroup";

pub struct Ebpf {
    pub inner: aya::Ebpf,
    pub main_program_info: MainProgramInfo,
    pub rule_names: Vec<(String, Action)>,
}

impl Ebpf {
    pub fn new() -> Self {
        let ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/ebpf"
        )))
        .unwrap();
        #[link(name = "c")]
        unsafe extern "C" {
            fn geteuid() -> u32;
            fn getpid() -> u32;
        }
        rlimit::increase_nofile_limit(rlimit::INFINITY).ok();
        rlimit::setrlimit(
            rlimit::Resource::MEMLOCK,
            rlimit::INFINITY,
            rlimit::INFINITY,
        )
        .unwrap();

        // let _ = aya_log::EbpfLogger::init(&mut ebpf).unwrap();
        Self {
            inner: ebpf,
            main_program_info: MainProgramInfo {
                uid: unsafe { geteuid() },
                pid: unsafe { getpid() },
                number_of_active_rules: 0,
                forward_v4_address: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
                proxy_v4_address: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
                forward_v6_address: SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0),
                proxy_v6_address: SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0),
            },
            rule_names: Vec::new(),
        }
    }
    pub fn set_forward_v4_address(&mut self, addr: SocketAddrV4) {
        self.main_program_info.forward_v4_address = addr;
    }
    pub fn set_proxy_v4_address(&mut self, addr: SocketAddrV4) {
        self.main_program_info.proxy_v4_address = addr;
    }
    pub fn set_forward_v6_address(&mut self, addr: SocketAddrV6) {
        self.main_program_info.forward_v6_address = addr;
    }
    pub fn set_proxy_v6_address(&mut self, addr: SocketAddrV6) {
        self.main_program_info.proxy_v6_address = addr;
    }
    pub fn load_main_program_info(&mut self) {
        let mut main_program_info_map: aya::maps::Array<&mut aya::maps::MapData, MainProgramInfo> =
            aya::maps::Array::try_from(self.inner.map_mut("MAIN_APP_INFO").unwrap()).unwrap();
        main_program_info_map
            .set(0, self.main_program_info, 0)
            .unwrap();
    }
    pub fn set_rules(&mut self, rules: HashMap<String, Rule>) {
        let mut tcp_rules: aya::maps::Array<&mut aya::maps::MapData, ebpf_common::Rule> =
            aya::maps::Array::try_from(self.inner.map_mut("TCP_RULES").unwrap()).unwrap();
        for (index, (r_name, r)) in rules.into_iter().enumerate() {
            let r = ebpf_common::Rule::from(r);
            self.rule_names.push((r_name, r.action));
            tcp_rules.set(index as u32, &r, 0).unwrap();
        }
        self.main_program_info.number_of_active_rules = self.rule_names.len() as u32;
    }
    pub fn load_cgroups(&mut self) {
        let cgroup = std::fs::File::open(CGROUP_PATH).unwrap();
        for prog in vec!["connect4", "connect6"] {
            //, "bpf_sockops"
            let program: &mut CgroupSockAddr =
                self.inner.program_mut(prog).unwrap().try_into().unwrap();

            program.load().unwrap();
            program.attach(&cgroup, CgroupAttachMode::Single).unwrap();
        }

        let program: &mut SockOps = self
            .inner
            .program_mut("bpf_sockops")
            .unwrap()
            .try_into()
            .unwrap();
        program.load().unwrap();
        program.attach(&cgroup, CgroupAttachMode::Single).unwrap();
    }
}
