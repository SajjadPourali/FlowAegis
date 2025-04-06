use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    pin::Pin,
    ptr,
};

use aya::{
    maps::{AsyncPerfEventArray, lpm_trie::Key},
    programs::{CgroupAttachMode, CgroupSockAddr, SockOps, TracePoint},
    util::online_cpus,
};
use bytes::BytesMut;
use ebpf_common::{
    Action, CgroupInfo, LpmValue, MainProgramInfo, NetworkTuple, PathKey, RuleV4, RuleV6,
};
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
    // pub path: Option<String>,
}

#[derive(Debug)]
pub enum EbpfMessageAction {
    Allow(String),
    Deny(String),
    Forward(String),
    Proxy(String),
    // Missed,
    Interrupted(String),
}
pub struct EbpfMessageStream {
    rules: Vec<(std::string::String, Action)>,
    network_tuple_stream: AsyncPerfEventArrayStream<NetworkTuple>,
    delay_queue: tokio_util::time::DelayQueue<CgroupInfo>,
    // process_map: HashMap<u32, String>,
    // queue_map: HashMap<u32, tokio_util::time::delay_queue::Key>,
}

impl Stream for EbpfMessageStream {
    type Item = EbpfMessage;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        // if let std::task::Poll::Ready(process_info) = self.process_info.poll_next_unpin(cx) {
        //     match process_info {
        //         Some(pi) => {
        //             if pi.path_len == 0 {
        //                 self.process_map.remove(&(pi.pid as u32));
        //             } else {
        //                 if let Ok(path) =
        //                     String::from_utf8(pi.path[..pi.path_len as usize].to_vec())
        //                 {
        //                     self.process_map.insert(pi.pid, path);
        //                 }
        //             }
        //         }
        //         None => return std::task::Poll::Ready(None),
        //     }
        // }
        if let std::task::Poll::Ready(network_tuple) = self.network_tuple_stream.poll_next_unpin(cx)
        {
            match network_tuple {
                Some(network_tuple) => {
                    let o = ("Default".to_string(), Action::Allow);
                    let (rule_name, rule_action) =
                        self.rules.get(network_tuple.rule as usize).unwrap_or(&o);
                    // match ;
                    return std::task::Poll::Ready(Some(EbpfMessage {
                        action: match rule_action {
                            Action::Allow => EbpfMessageAction::Allow(rule_name.to_owned()),
                            Action::Deny => EbpfMessageAction::Deny(rule_name.to_owned()),
                            Action::Forward => EbpfMessageAction::Forward(rule_name.to_owned()),
                            Action::Proxy => EbpfMessageAction::Proxy(rule_name.to_owned()),
                        },
                        src: network_tuple.src.to_socket_addr(), //: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
                        dst: network_tuple.actual_dst.to_socket_addr(), //,SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
                        uid: network_tuple.uid,
                        gid: network_tuple.gid,
                        pid: network_tuple.pid,
                        tgid: network_tuple.tgid,
                        // path: self.process_map.get(&(network_tuple.tgid as u32)).cloned(),
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
                // path: self.process_map.get(&(pid as u32)).cloned(),
            }));
        }
        std::task::Poll::Pending
    }
}

pub struct AsyncPerfEventArrayStream<T> {
    streams: stream::SelectAll<Pin<Box<dyn Stream<Item = T>>>>,
    _marker: std::marker::PhantomData<T>,
}

impl<T: 'static> AsyncPerfEventArrayStream<T> {
    pub fn new(map: aya::maps::Map) -> Self {
        let mut async_perf_event_array = AsyncPerfEventArray::try_from(map).unwrap();
        let mut streams: Vec<Pin<Box<dyn Stream<Item = T>>>> = Vec::new();
        for cpu_id in online_cpus().map_err(|(_, error)| error).unwrap() {
            let async_perf_event_array_buffer = async_perf_event_array.open(cpu_id, None).unwrap();
            let buf = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();
            let remaning = Vec::new();
            streams.push(Box::pin(stream::unfold::<_, _, _, T>(
                (async_perf_event_array_buffer, buf, remaning),
                move |(mut async_perf_event_array_buffer, mut buf, mut remaning)| async {
                    if let Some(t) = remaning.pop() {
                        return Some((t, (async_perf_event_array_buffer, buf, remaning)));
                    }
                    let events = async_perf_event_array_buffer
                        .read_events(&mut buf)
                        .await
                        .unwrap();
                    for b in buf.iter_mut().take(events.read) {
                        let tuple = unsafe { ptr::read_unaligned(b.as_ptr() as *const T) };
                        remaning.push(tuple);
                    }
                    if let Some(t) = remaning.pop() {
                        return Some((t, (async_perf_event_array_buffer, buf, remaning)));
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
        let mut addr_rule_map: HashMap<String, u32> = HashMap::new();
        for (rule_id, (r_name, r)) in rules.into_iter().enumerate() {
            let mut v4_rules = Vec::new();
            let mut v6_rules = Vec::new();
            let mut path_keys = Vec::new();

            self.rule_names.push((r_name, r.action));
            let value = LpmValue {
                rule_id: rule_id as u32,
                action: r.action,
            };
            let path_flags = (!r.uid.is_empty()) as u16;
            let mut path = [0u8; 128];
            let path_len = r.path.len() as u8;
            if !r.path.is_empty() {
                addr_rule_map.insert(r.path.clone(), rule_id as u32);
                path[..r.path.len().min(128)].copy_from_slice(r.path.as_bytes());
            }

            for (rule, prefix) in Into::<Vec<(ebpf_common::_Rule<RuleV4, RuleV6>, u8)>>::into(r) {
                let uid = match rule {
                    ebpf_common::_Rule::V4(rule_v4) => rule_v4.uid,
                    ebpf_common::_Rule::V6(rule_v6) => rule_v6.uid,
                };
                if path_len > 0 {
                    path_keys.push(uid);
                }
                match rule {
                    ebpf_common::_Rule::V4(rule_v4) => {
                        let base_offset = ((core::mem::size_of_val(&rule_v4) - 4) * 8) as u32;
                        let key = Key::new(base_offset + prefix as u32, rule_v4);
                        v4_rules.push((key, value));
                    }
                    ebpf_common::_Rule::V6(rule_v6) => {
                        let base_offset = ((core::mem::size_of_val(&rule_v6) - 16) * 8) as u32;
                        let key = Key::new(base_offset + prefix as u32, rule_v6);
                        v6_rules.push((key, value));
                    }
                }
            }
            let mut v4: aya::maps::LpmTrie<&mut aya::maps::MapData, ebpf_common::RuleV4, LpmValue> =
                aya::maps::LpmTrie::try_from(self.inner.map_mut("V4_RULES").unwrap()).unwrap();
            for (k, v) in &v4_rules {
                v4.insert(k, v, 0).unwrap();
            }
            let mut v6: aya::maps::LpmTrie<&mut aya::maps::MapData, ebpf_common::RuleV6, LpmValue> =
                aya::maps::LpmTrie::try_from(self.inner.map_mut("V6_RULES").unwrap()).unwrap();
            for (k, v) in &v6_rules {
                v6.insert(k, v, 0).unwrap();
            }
            let mut path_map: aya::maps::LpmTrie<
                &mut aya::maps::MapData,
                ebpf_common::PathKey,
                u32,
            > = aya::maps::LpmTrie::try_from(self.inner.map_mut("PATH_RULES").unwrap()).unwrap();
            for pid in path_keys {
                let pk = PathKey {
                    flags: path_flags,
                    pid,
                    path,
                };

                let pkk = Key::new(
                    (size_of_val(&pk) - (128 - path_len as usize)) as u32 * 8,
                    pk,
                );

                path_map.insert(&pkk, rule_id as u32, 0).unwrap();
            }
        }
        // addr_rule_map;
        let mut current_path_pid_map: HashMap<u32, u32> = HashMap::new();
        for p in procfs::process::all_processes().unwrap() {
            let Ok(p) = p else { continue };
            let running_process_path = p.exe().unwrap_or_default();
            let running_process_id = p.pid();
            for (path, rule_id) in addr_rule_map.iter() {
                if running_process_path.starts_with(path) {
                    current_path_pid_map.insert(running_process_id as u32, *rule_id);
                }
            }
        }
        if !current_path_pid_map.is_empty() {
            let mut pid_rule_map: aya::maps::HashMap<&mut aya::maps::MapData, u32, u32> =
                aya::maps::HashMap::try_from(self.inner.map_mut("PID_RULE_MAP").unwrap()).unwrap();
            for (pid, rule_id) in current_path_pid_map.iter() {
                pid_rule_map.insert(pid, rule_id, 0).unwrap();
            }
        }
        // PID_RULE_MAP
    }
    pub fn load_cgroups(&mut self) {
        let program: &mut TracePoint = self
            .inner
            .program_mut("sched_process_exec")
            .unwrap()
            .try_into()
            .unwrap();
        program.load().unwrap();
        program.attach("sched", "sched_process_exec").unwrap();
        let program: &mut TracePoint = self
            .inner
            .program_mut("sched_process_exit")
            .unwrap()
            .try_into()
            .unwrap();
        program.load().unwrap();
        program.attach("sched", "sched_process_exit").unwrap();

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
        // let mut process_map = HashMap::new();
        // if let Ok(process_iter) = procfs::process::all_processes() {
        //     for prc in process_iter {
        //         if let Ok(prc) = prc {
        //             if let Ok(path) = prc.exe() {
        //                 process_map.insert(prc.pid() as u32, path.to_string_lossy().to_string());
        //             }
        //         }
        //     }
        // }

        EbpfMessageStream {
            rules: self.rule_names.clone(),
            network_tuple_stream: AsyncPerfEventArrayStream::<NetworkTuple>::new(
                self.inner.take_map("NETWORK_TUPLE").unwrap(),
            ),
            delay_queue: Default::default(),
            // process_map,
            // queue_map: Default::default(),
        }
    }
}
