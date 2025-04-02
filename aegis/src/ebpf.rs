use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    pin::Pin,
    ptr,
};

use aya::{
    maps::AsyncPerfEventArray,
    programs::{CgroupAttachMode, CgroupSockAddr, SockOps},
    util::online_cpus,
};
use bytes::BytesMut;
use ebpf_common::{Action, CgroupInfo, MainProgramInfo, NetworkTuple};
use futures::{
    Stream, StreamExt,
    stream::{self, select_all},
};

use crate::error;

#[allow(dead_code)]
#[derive(Debug)]
pub struct EbpfMessage {
    pub action: EbpfMessageAction,
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
    pub tgid: u32,
}

#[derive(Debug)]
pub enum EbpfMessageAction {
    Allow(String),
    Deny(String),
    Forward(String),
    Proxy(String),
    Missed,
    Interrupted(String),
}
pub struct EbpfMessageStream {
    rules: Vec<(std::string::String, Action)>,
    network_tuple_stream: AsyncPerfEventArrayStream<NetworkTuple>,
    // cgroup_info_stream: AsyncPerfEventArrayStream<CgroupInfo>,
    delay_queue: tokio_util::time::DelayQueue<CgroupInfo>,
    // queue_map: HashMap<u32, tokio_util::time::delay_queue::Key>,
}

impl Stream for EbpfMessageStream {
    type Item = EbpfMessage;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        // if let std::task::Poll::Ready(cgroup_info) = self.cgroup_info_stream.poll_next_unpin(cx) {
        //     match cgroup_info {
        //         Some(cgroup_info) => {
        //             let tag = cgroup_info.tag;
        //             let key = self
        //                 .delay_queue
        //                 .insert(cgroup_info, std::time::Duration::from_secs(1));
        //             self.queue_map.insert(tag, key);
        //         }
        //         None => return std::task::Poll::Ready(None),
        //     }
        // }
        if let std::task::Poll::Ready(network_tuple) = self.network_tuple_stream.poll_next_unpin(cx)
        {
            match network_tuple {
                Some(network_tuple) => {
                    let (rule_name, rule_action) =
                        self.rules.get(network_tuple.rule as usize).unwrap();
                    // match ;
                    return std::task::Poll::Ready(Some(EbpfMessage {
                        action: match rule_action {
                            Action::Allow => EbpfMessageAction::Allow(rule_name.to_owned()),
                            Action::Deny => EbpfMessageAction::Deny(rule_name.to_owned()),
                            Action::Forward => EbpfMessageAction::Forward(rule_name.to_owned()),
                            Action::Proxy => EbpfMessageAction::Proxy(rule_name.to_owned()),
                        },
                        src: network_tuple.src.to_socket_addr(),//: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
                        dst: network_tuple.actual_dst.to_socket_addr(),//,SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
                        uid: network_tuple.uid,
                        gid: network_tuple.gid,
                        pid: network_tuple.pid,
                        tgid: network_tuple.tgid,
                    }));
                    // let src = network_tuple.src;
                    // let tag = network_tuple.tag;
                    // if let Some(info) = self
                    //     .queue_map
                    //     .remove(&tag)
                    //     .and_then(|key| self.delay_queue.try_remove(&key))
                    // {
                    //     let info = info.into_inner();
                    //     let uid: u32 = info.uid;
                    //     let gid: u32 = info.gid;
                    //     let pid: u32 = info.pid;
                    //     let tgid: u32 = info.tgid;
                    //     let dst = info.dst.to_socket_addr();
                    //     let action = if info.rule == u32::MAX {
                    //         EbpfMessageAction::Allow("Default".to_string())
                    //     } else {
                    //         let (rule_name, rule_action) =
                    //             self.rules.get(info.rule as usize).unwrap();
                    //         match rule_action {
                    //             Action::Allow => EbpfMessageAction::Allow(rule_name.to_owned()),
                    //             Action::Deny => EbpfMessageAction::Deny(rule_name.to_owned()),
                    //             Action::Forward => EbpfMessageAction::Forward(rule_name.to_owned()),
                    //             Action::Proxy => EbpfMessageAction::Proxy(rule_name.to_owned()),
                    //         }
                    //     };

                    //     return std::task::Poll::Ready(Some(EbpfMessage {
                    //         action,
                    //         src,
                    //         dst,
                    //         uid,
                    //         gid,
                    //         pid,
                    //         tgid,
                    //     }));
                    // } else {
                    //     let dst = network_tuple.dst;
                    //     return std::task::Poll::Ready(Some(EbpfMessage {
                    //         action: EbpfMessageAction::Missed,
                    //         src,
                    //         dst,
                    //         uid: 0,
                    //         gid: 0,
                    //         pid: 0,
                    //         tgid: 0,
                    //     }));
                    // }
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
            let dst = expired.dst.to_socket_addr();

            let rule_name = if expired.rule == u32::MAX {
                "Default"
            } else {
                let (rule_name, _) = self.rules.get(expired.rule as usize).unwrap();
                rule_name.as_str()
            };

            return std::task::Poll::Ready(Some(EbpfMessage {
                action: EbpfMessageAction::Interrupted(rule_name.to_string()),
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
    pub fn new() -> Result<Self, error::AegisError> {
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
        // ulimit -l unlimited

        // let _ = aya_log::EbpfLogger::init(&mut ebpf).unwrap();
        Ok(Self {
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
        })
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
    pub fn set_rules(&mut self, rules: HashMap<String, crate::rule::Rule>) {
        let mut tcp_rules: aya::maps::Array<&mut aya::maps::MapData, ebpf_common::Rule> =
            aya::maps::Array::try_from(self.inner.map_mut("TCP_RULES").unwrap()).unwrap();
        for (index, (r_name, r)) in rules.into_iter().enumerate() {
            let r = ebpf_common::Rule::from(r);
            self.rule_names.push((r_name, r.action));
            tcp_rules.set(index as u32, r, 0).unwrap();
        }
        self.main_program_info.number_of_active_rules = self.rule_names.len() as u32;
    }
    pub fn load_cgroups(&mut self) {
        let cgroup = std::fs::File::open(CGROUP_PATH).unwrap();
        for prog in ["connect4", "connect6"] {
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
        // self.inner.take_map("SOCKET_MARK_MAP").unwrap();
        EbpfMessageStream {
            rules: self.rule_names.clone(),
            network_tuple_stream: AsyncPerfEventArrayStream::<NetworkTuple>::new(
                self.inner.take_map("NETWORK_TUPLE").unwrap(),
            ),
            // cgroup_info_stream: AsyncPerfEventArrayStream::<CgroupInfo>::new(
            //     self.inner.take_map("CGROUP_INFO").unwrap(),
            // ),
            delay_queue: Default::default(),
            // queue_map: Default::default(),
        }
    }
}
