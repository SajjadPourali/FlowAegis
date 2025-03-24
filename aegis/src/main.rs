use ebpf::Ebpf;
use futures::StreamExt;
use network::async_forward;
use proxy_stream::{ProxyStream, ProxyType};
use std::{
    collections::HashMap,
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
};
// use aya_log::EbpfLogger;

use rule::Rule;

use serde::{Deserialize, Serialize};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
    select,
};
mod ebpf;
mod error;
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
    let listener_4 = TcpListener::bind("127.0.0.1:0").await?;
    let listener_6 = TcpListener::bind("[::1]:0").await?;

    let Ok(SocketAddr::V4(proxy_address_ipv4)) = listener_4.local_addr() else {
        return Ok(());
    };
    let Ok(SocketAddr::V6(proxy_address_ipv6)) = listener_6.local_addr() else {
        return Ok(());
    };

    env_logger::init();
    log::info!("starting up");

    let mut config_file = tokio::fs::File::open("rules.toml").await?;
    let mut rules = String::new();
    config_file.read_to_string(&mut rules).await?;
    let config: Config = toml::from_str(&rules)?;
    
    let mut ebpf = Ebpf::new()?;
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
}
