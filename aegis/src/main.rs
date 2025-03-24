use aya::{
    maps::AsyncPerfEventArray,
    programs::{CgroupAttachMode, CgroupSockAddr, SockOps},
    util::online_cpus,
};
use futures::{
    Stream, StreamExt,
    stream::{self, select_all},
};
use network::async_forward;
use proxy_stream::{ProxyStream, ProxyType};
use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    pin::Pin,
    ptr,
};
// use aya_log::EbpfLogger;
use bytes::BytesMut;
use ebpf_common::{Action, CgroupInfo, MainProgramInfo, NetworkTuple};
use rule::Rule;

mod rule;
use serde::{Deserialize, Serialize};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
    select,
};

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    proxy_address_ipv4: SocketAddrV4,
    forward_address_ipv4: SocketAddrV4,
    proxy_address_ipv6: SocketAddrV6,
    forward_address_ipv6: SocketAddrV6,
    rules: HashMap<String, Rule>,
}

mod network;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener_4 = TcpListener::bind("127.0.0.1:0").await?;
    let listener_6 = TcpListener::bind("[::1]:0").await?;

    let Ok(SocketAddr::V4(proxy_address_ipv4)) = listener_4.local_addr() else {
        return Ok(());
    };
    let Ok(SocketAddr::V6(proxy_address_ipv6)) = listener_6.local_addr() else {
        return Ok(());
    };

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
    ebpf.set_proxy_v4_address(proxy_address_ipv4);
    ebpf.set_forward_v6_address(config.forward_address_ipv6);
    ebpf.set_proxy_v6_address(proxy_address_ipv6);
    ebpf.set_rules(config.rules);
    ebpf.load_main_program_info();
    ebpf.load_cgroups();

    let mut e = ebpf.get_event_stream();

    let mut proxy_address_map = HashMap::new();
    let mut socket_address_map: HashMap<SocketAddr, TcpStream> = HashMap::new();
    loop {
        select! {
            Some(msg) = e.next() => {
                if let Some(stream) = socket_address_map.remove(&msg.src){
                    let proxy_stream = ProxyStream::new(ProxyType::SOCKS5);
                    tokio::spawn(async move {
                        let proxy_stream = if msg.dst.is_ipv4(){
                            let conn = TcpStream::connect(config.proxy_address_ipv4).await.unwrap();
                            proxy_stream.connect(conn, msg.dst).await.unwrap()
                        } else{
                            proxy_stream.connect(TcpStream::connect(config.proxy_address_ipv6).await.unwrap(), msg.dst).await.unwrap()

                        };
                        async_forward(proxy_stream, stream).await.unwrap();

                    });
                }else{
                    proxy_address_map.insert(msg.src, msg.dst);
                }

            }
            Ok(( stream,addr)) = listener_4.accept() => {
                if let Some(dst) = proxy_address_map.remove(&addr){
                    let proxy_stream = ProxyStream::new(ProxyType::SOCKS5);
                    tokio::spawn(async move {
                        let conn = TcpStream::connect(config.proxy_address_ipv4).await.unwrap();
                        let proxy_stream = proxy_stream.connect(conn, dst).await.unwrap();
                        async_forward(proxy_stream, stream).await.unwrap();
                    });
                } else{
                    socket_address_map.insert(addr, stream);
                }
            }
            Ok(( stream,addr)) = listener_6.accept() => {
                if let Some(dst) = proxy_address_map.remove(&addr){
                    let proxy_stream = ProxyStream::new(ProxyType::SOCKS5);
                    tokio::spawn(async move {
                        let  proxy_stream = proxy_stream.connect(TcpStream::connect(config.proxy_address_ipv6).await.unwrap(), dst).await.unwrap();
                        async_forward(proxy_stream, stream).await.unwrap();
                    });
            } else{
                    socket_address_map.insert(addr, stream);
                }
            }
        }
    }

    Ok(())

    // let ctrl_c = tokio::signal::ctrl_c();
    // println!("Waiting for Ctrl-C...");
    // ctrl_c.await?;
    // println!("Exiting...");
    // Ok(())
}

#[derive(Debug)]
pub struct EbpfMessage {
    action: EbpfMessageAction,
    src: SocketAddr,
    dst: SocketAddr,
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
    pub tgid: u32,
}

#[derive(Debug)]
pub enum EbpfMessageAction {
    Allow(u32, String),
    Deny(u32, String),
    Forward(u32, String),
    Proxy(u32, String),
    Missed,
    Interrupted(u32, String),
}
pub struct EbpfMessageStream {
    rules: Vec<(std::string::String, Action)>,
    network_tuple_stream: AsyncPerfEventArrayStream<NetworkTuple>,
    cgroup_info_stream: AsyncPerfEventArrayStream<CgroupInfo>,
    delay_queue: tokio_util::time::DelayQueue<CgroupInfo>,
    queue_map: HashMap<u32, tokio_util::time::delay_queue::Key>,
}

impl Stream for EbpfMessageStream {
    type Item = EbpfMessage;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        if let std::task::Poll::Ready(cgroup_info) = self.cgroup_info_stream.poll_next_unpin(cx) {
            match cgroup_info {
                Some(cgroup_info) => {
                    let tag = cgroup_info.tag;
                    let key = self
                        .delay_queue
                        .insert(cgroup_info, std::time::Duration::from_secs(1));
                    self.queue_map.insert(tag, key);
                }
                None => return std::task::Poll::Ready(None),
            }
        }
        if let std::task::Poll::Ready(network_tuple) = self.network_tuple_stream.poll_next_unpin(cx)
        {
            match network_tuple {
                Some(network_tuple) => {
                    let src = network_tuple.src;
                    let tag = network_tuple.tag;
                    if let Some(info) = self
                        .queue_map
                        .remove(&tag)
                        .and_then(|key| self.delay_queue.try_remove(&key))
                    {
                        let info = info.into_inner();
                        let uid: u32 = info.uid;
                        let gid: u32 = info.gid;
                        let pid: u32 = info.pid;
                        let tgid: u32 = info.tgid;
                        let dst = info.dst;
                        let action = if info.rule == u32::MAX {
                            EbpfMessageAction::Allow(info.rule, "Default".to_string())
                        } else {
                            let (rule_name, rule_action) =
                                self.rules.get(info.rule as usize).unwrap();
                            match rule_action {
                                Action::Allow => {
                                    EbpfMessageAction::Allow(info.rule, rule_name.to_owned())
                                }
                                Action::Deny => {
                                    EbpfMessageAction::Deny(info.rule, rule_name.to_owned())
                                }
                                Action::Forward => {
                                    EbpfMessageAction::Forward(info.rule, rule_name.to_owned())
                                }
                                Action::Proxy => {
                                    EbpfMessageAction::Proxy(info.rule, rule_name.to_owned())
                                }
                            }
                        };

                        return std::task::Poll::Ready(Some(EbpfMessage {
                            action,
                            src,
                            dst,
                            uid,
                            gid,
                            pid,
                            tgid,
                        }));
                    } else {
                        let dst = network_tuple.dst;
                        return std::task::Poll::Ready(Some(EbpfMessage {
                            action: EbpfMessageAction::Missed,
                            src,
                            dst,
                            uid: 0,
                            gid: 0,
                            pid: 0,
                            tgid: 0,
                        }));
                    }
                }
                None => return std::task::Poll::Ready(None),
            }
        }
        if let std::task::Poll::Ready(Some(expired)) = self.delay_queue.poll_expired(cx) {
            let src = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
            let expired = expired.into_inner();
            let uid: u32 = expired.uid;
            let gid: u32 = expired.gid;
            let pid: u32 = expired.pid;
            let tgid: u32 = expired.tgid;
            let dst = expired.dst;

            let rule_name = if expired.rule == u32::MAX {
                "Default"
            } else {
                let (rule_name, _) = self.rules.get(expired.rule as usize).unwrap();
                rule_name.as_str()
            };

            return std::task::Poll::Ready(Some(EbpfMessage {
                action: EbpfMessageAction::Interrupted(expired.rule, rule_name.to_string()),
                src,
                dst,
                uid,
                gid,
                pid,
                tgid,
            }));
        }
        std::task::Poll::Pending
    }
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
    pub fn get_event_stream(&mut self) -> EbpfMessageStream {
        EbpfMessageStream {
            rules: self.rule_names.clone(),
            network_tuple_stream: AsyncPerfEventArrayStream::<NetworkTuple>::new(
                self.inner.take_map("NETWORK_TUPLE").unwrap(),
            ),
            cgroup_info_stream: AsyncPerfEventArrayStream::<CgroupInfo>::new(
                self.inner.take_map("CGROUP_INFO").unwrap(),
            ),
            delay_queue: Default::default(),
            queue_map: Default::default(),
        }
    }
}
