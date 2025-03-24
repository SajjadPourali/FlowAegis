use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

use futures::Stream;
use tokio::net::{TcpListener, TcpStream};

use crate::error::AegisError;

pub struct Proxy {
    listener_4: TcpListener,
    listener_6: TcpListener,
}

impl Proxy {
    pub async fn new(ipv4: SocketAddrV4, ipv6: SocketAddrV6) -> Result<Self, AegisError> {
        let listener_4 = TcpListener::bind(ipv4).await?;
        let listener_6 = TcpListener::bind(ipv6).await?;
        Ok(Self {
            listener_4,
            listener_6,
        })
    }
    pub fn get_local_address_v4(&self) -> Result<SocketAddrV4, std::io::Error> {
        match self.listener_4.local_addr()? {
            SocketAddr::V4(socket_addr_v4) => Ok(socket_addr_v4),
            SocketAddr::V6(_) => Err(std::io::Error::from(std::io::ErrorKind::AddrNotAvailable)),
        }
    }
    pub fn get_local_address_v6(&self) -> Result<SocketAddrV6, std::io::Error> {
        match self.listener_6.local_addr()? {
            SocketAddr::V4(_) => Err(std::io::Error::from(std::io::ErrorKind::AddrNotAvailable)),
            SocketAddr::V6(socket_addr_v6) => Ok(socket_addr_v6),
        }
    }
}

impl Stream for Proxy {
    type Item = Result<(TcpStream, SocketAddr), AegisError>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        if let std::task::Poll::Ready((stream, addr)) = self.listener_4.poll_accept(cx)? {
            return std::task::Poll::Ready(Some(Ok((stream, addr))));
        }
        if let std::task::Poll::Ready((stream, addr)) = self.listener_6.poll_accept(cx)? {
            return std::task::Poll::Ready(Some(Ok((stream, addr))));
        }
        std::task::Poll::Pending
    }
}
