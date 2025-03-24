use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

pub trait AsyncSocket: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T> AsyncSocket for T where T: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
pub async fn async_forward(
    left: impl AsyncSocket,
    right: impl AsyncSocket,
) -> Result<(), ()> {
    let (mut left_rx, mut left_tx) = tokio::io::split(left);
    let (mut right_rx, mut right_tx) = tokio::io::split(right);
    loop {
        tokio::select! {
            res = tokio::io::copy(&mut left_rx, &mut right_tx) => {
                if res.unwrap() == 0 {
                    let _ = left_tx.shutdown().await;
                    let _ = right_tx.shutdown().await;
                    return Ok(())
                }
            },
            res = tokio::io::copy(&mut right_rx, &mut left_tx) => {
                if res.unwrap() == 0 {
                    let _ = left_tx.shutdown().await;
                    let _ = right_tx.shutdown().await;
                    return Ok(())
                }
            },
        }
    }
}