use args::Args;
use ebpf::{Ebpf, EbpfMessageAction};
use futures::{StreamExt, future};
use log::warn;
use network::async_forward;
use proxy::Proxy;
use proxy_stream::{ProxyStream, ProxyType};
use std::{
    collections::HashMap,
    env,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};
// use aya_log::EbpfLogger;

use rule::{Action, Path, Rule, Transport};

use serde::{Deserialize, Serialize};
use tokio::{io::AsyncReadExt, net::TcpStream};
mod args;
mod ebpf;
mod error;
mod proxy;
mod rule;
#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    transport: HashMap<String, Transport>,
    path: HashMap<String, Path>,
    rule: HashMap<String, Rule>,
}

impl Config {
    pub async fn load(Args(args): Args) -> Result<Self, error::AegisError> {
        let mut config = Config {
            transport: HashMap::new(),
            path: HashMap::new(),
            rule: HashMap::new(),
        };
        let mut rule = Rule {
            action: Action::Allow,
            ipv4: None,
            ipv6: None,
            port: Vec::new(),
            uid: Vec::new(),
            path: None,
            transport: None,
        };
        match args {
            args::ArgCommands::Forward(forward_args) => {
                rule.action = Action::Forward;
                let mut transport = Transport {
                    ipv4: None,
                    ipv6: None,
                };

                if let Some((ip, prefix, t)) = forward_args.v4 {
                    transport.ipv4 = Some(t);
                    rule.ipv4 = Some((ip, prefix));
                }
                if let Some((ip, prefix, t)) = forward_args.v6 {
                    transport.ipv6 = Some(t);
                    rule.ipv6 = Some((ip, prefix));
                }
                rule.port = forward_args.port;
                rule.uid = forward_args.uid;
                rule.path = forward_args.directory;
                if transport.ipv4.is_some() || transport.ipv6.is_some() {
                    let transport_name = "arg".to_string();
                    config.transport.insert(transport_name.clone(), transport);
                    rule.transport = Some(transport_name);
                }
            }
            args::ArgCommands::Proxy(proxy_args) => {
                rule.action = Action::Proxy;
                let mut transport = Transport {
                    ipv4: None,
                    ipv6: None,
                };

                if let Some((ip, prefix, t)) = proxy_args.v4 {
                    transport.ipv4 = Some(t);
                    rule.ipv4 = Some((ip, prefix));
                }
                if let Some((ip, prefix, t)) = proxy_args.v6 {
                    transport.ipv6 = Some(t);
                    rule.ipv6 = Some((ip, prefix));
                }
                rule.port = proxy_args.port;
                rule.uid = proxy_args.uid;
                rule.path = proxy_args.directory;
                if transport.ipv4.is_some() || transport.ipv6.is_some() {
                    let transport_name = "arg".to_string();
                    config.transport.insert(transport_name.clone(), transport);
                    rule.transport = Some(transport_name);
                }
            }
            args::ArgCommands::Allow(allow_args) => {
                rule.action = Action::Allow;
                if let Some((ip, prefix)) = allow_args.v4 {
                    rule.ipv4 = Some((ip, prefix));
                }
                if let Some((ip, prefix)) = allow_args.v6 {
                    rule.ipv6 = Some((ip, prefix));
                }
                rule.port = allow_args.port;
                rule.uid = allow_args.uid;
                rule.path = allow_args.directory;
            }
            args::ArgCommands::Deny(deny_args) => {
                rule.action = Action::Deny;
                if let Some((ip, prefix)) = deny_args.v4 {
                    rule.ipv4 = Some((ip, prefix));
                }
                if let Some((ip, prefix)) = deny_args.v6 {
                    rule.ipv6 = Some((ip, prefix));
                }
                rule.port = deny_args.port;
                rule.uid = deny_args.uid;
                rule.path = deny_args.directory;
            }
            args::ArgCommands::Import(path) => {
                let mut config_file = tokio::fs::File::open(path).await?;
                let mut rules = String::new();
                config_file.read_to_string(&mut rules).await?;
                return Ok(toml::from_str(&rules)?);
            }
        }
        config.rule.insert("arg".to_string(), rule);
        Ok(config)
    }
}

mod network;

#[tokio::main]
async fn main() -> Result<(), error::AegisError> {
    let config = Config::load(args::Args::parse(env::args())?).await?;
    let mut proxy = Proxy::new(
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0),
    )
    .await?;

    env_logger::init();
    log::info!("starting up");

    let mut ebpf = Ebpf::new()?;
    ebpf.set_proxy_v4_address(proxy.get_local_address_v4()?);
    ebpf.set_proxy_v6_address(proxy.get_local_address_v6()?);
    ebpf.set_transports(config.transport);
    ebpf.set_paths(config.path);
    ebpf.set_rules(config.rule);
    ebpf.load_main_program_info();
    ebpf.load_cgroups();

    let mut event_stream = ebpf.get_event_stream();

    let mut proxy_address_map = HashMap::new();
    let mut socket_address_map: HashMap<SocketAddr, TcpStream> = HashMap::new();
    loop {
        match future::select(event_stream.next(), proxy.next()).await {
            future::Either::Left((Some(msg), _)) => {
                let path = procfs::process::Process::new(msg.tgid as i32)
                    .and_then(|p| p.exe())
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();
                match &msg.action {
                    EbpfMessageAction::Allow(rname) => {
                        log::info!(
                            "Connection Allowed - src={} dst={} uid={} pid={} path={} rule={}",
                            msg.src,
                            msg.actual_dst,
                            msg.uid,
                            msg.pid,
                            path,
                            rname
                        );
                    }
                    EbpfMessageAction::Deny(rname) => {
                        log::info!(
                            "Connection Denined - src={} dst={} uid={} pid={} path={} rule={}",
                            msg.src,
                            msg.actual_dst,
                            msg.uid,
                            msg.pid,
                            path,
                            rname
                        );
                    }
                    EbpfMessageAction::Forward(rname) => {
                        log::info!(
                            "Connection Forwarded - src={} dst={} uid={} pid={} path={} rule={}",
                            msg.src,
                            msg.actual_dst,
                            msg.uid,
                            msg.pid,
                            path,
                            rname
                        );
                    }
                    EbpfMessageAction::Proxy(rname) => {
                        log::info!(
                            "Connection Proxied - src={} dst={} uid={} pid={} path={} rule={}",
                            msg.src,
                            msg.actual_dst,
                            msg.uid,
                            msg.pid,
                            path,
                            rname
                        );
                    }
                    EbpfMessageAction::Interrupted(rname) => {
                        log::info!(
                            "Connection Interrupted - src={} dst={} uid={} pid={} path={} rule={}",
                            msg.src,
                            msg.actual_dst,
                            msg.uid,
                            msg.pid,
                            path,
                            rname
                        );
                    }
                };
                if matches!(msg.action, EbpfMessageAction::Proxy(_)) {
                    if let Some(stream) = socket_address_map.remove(&msg.src) {
                        let proxy_stream = ProxyStream::new(ProxyType::SOCKS5);
                        tokio::spawn(async move {
                            let conn = TcpStream::connect(msg.dst).await;
                            let conn = match conn {
                                Ok(conn) => conn,
                                Err(e) => {
                                    warn!("{}", e);
                                    return;
                                }
                            };
                            let proxy_stream =
                                match proxy_stream.connect(conn, msg.actual_dst).await {
                                    Ok(proxy_stream) => proxy_stream,
                                    Err(e) => {
                                        warn!("{}", e);
                                        return;
                                    }
                                };
                            if let Err(e) = async_forward(proxy_stream, stream).await {
                                warn!("{}", e);
                            }
                        });
                    } else {
                        proxy_address_map.insert(msg.src, (msg.dst, msg.actual_dst));
                    }
                }
            }

            future::Either::Right((Some(Ok((stream, addr))), _)) => {
                if let Some((dst, actual_dst)) = proxy_address_map.remove(&addr) {
                    let proxy_stream = ProxyStream::new(ProxyType::SOCKS5);
                    tokio::spawn(async move {
                        let conn = TcpStream::connect(dst).await;
                        let conn = match conn {
                            Ok(conn) => conn,
                            Err(e) => {
                                warn!("{}", e);
                                return;
                            }
                        };
                        let proxy_stream = match proxy_stream.connect(conn, actual_dst).await {
                            Ok(proxy_stream) => proxy_stream,
                            Err(e) => {
                                warn!("{}", e);
                                return;
                            }
                        };
                        if let Err(e) = async_forward(proxy_stream, stream).await {
                            warn!("{}", e);
                        }
                    });
                } else {
                    socket_address_map.insert(addr, stream);
                }
            }
            _ => {}
        }
    }
}
