use ebpf::{Ebpf, EbpfMessageAction};
use futures::{StreamExt, future};
use log::warn;
use network::async_forward;
use proxy::Proxy;
use proxy_stream::{ProxyStream, ProxyType};
use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};
// use aya_log::EbpfLogger;

use rule::Rule;

use serde::{Deserialize, Serialize};
use tokio::{io::AsyncReadExt, net::TcpStream};
mod ebpf;
mod error;
mod proxy;
mod rule;
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
async fn main() -> Result<(), error::AegisError> {
    let mut proxy = Proxy::new(
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0),
    )
    .await?;

    env_logger::init();
    log::info!("starting up");

    let mut config_file = tokio::fs::File::open("config.toml").await?;
    let mut rules = String::new();
    config_file.read_to_string(&mut rules).await?;
    let config: Config = toml::from_str(&rules)?;

    let mut ebpf = Ebpf::new()?;
    ebpf.set_forward_v4_address(config.forward_address_ipv4);
    ebpf.set_proxy_v4_address(proxy.get_local_address_v4()?);
    ebpf.set_forward_v6_address(config.forward_address_ipv6);
    ebpf.set_proxy_v6_address(proxy.get_local_address_v6()?);
    ebpf.set_rules(config.rules);
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
                            msg.dst,
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
                            msg.dst,
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
                            msg.dst,
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
                            msg.dst,
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
                            msg.dst,
                            msg.uid,
                            msg.pid,
                            path,
                            rname
                        );
                    }
                };
                if let Some(stream) = socket_address_map.remove(&msg.src) {
                    let proxy_stream = ProxyStream::new(ProxyType::SOCKS5);
                    tokio::spawn(async move {
                        let conn = if msg.dst.is_ipv4() {
                            TcpStream::connect(config.proxy_address_ipv4).await
                        } else {
                            TcpStream::connect(config.proxy_address_ipv6).await
                        };
                        let conn = match conn {
                            Ok(conn) => conn,
                            Err(e) => {
                                warn!("{}", e);
                                return ();
                            }
                        };
                        let proxy_stream = match proxy_stream.connect(conn, msg.dst).await {
                            Ok(proxy_stream) => proxy_stream,
                            Err(e) => {
                                warn!("{}", e);
                                return ();
                            }
                        };
                        if let Err(e) = async_forward(proxy_stream, stream).await {
                            warn!("{}", e);
                        }
                    });
                } else {
                    proxy_address_map.insert(msg.src, msg.dst);
                }
            }
            future::Either::Right((Some(Ok((stream, addr))), _)) => {
                if let Some(dst) = proxy_address_map.remove(&addr) {
                    let proxy_stream = ProxyStream::new(ProxyType::SOCKS5);
                    tokio::spawn(async move {
                        let conn = if addr.ip().is_ipv4() {
                            TcpStream::connect(config.proxy_address_ipv4).await
                        } else {
                            TcpStream::connect(config.proxy_address_ipv6).await
                        };
                        let conn = match conn {
                            Ok(conn) => conn,
                            Err(e) => {
                                warn!("{}", e);
                                return ();
                            }
                        };
                        let proxy_stream = match proxy_stream.connect(conn, dst).await {
                            Ok(proxy_stream) => proxy_stream,
                            Err(e) => {
                                warn!("{}", e);
                                return ();
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
