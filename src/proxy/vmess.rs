use crate::common::{
    hash, parse_addr, parse_port,
    KDFSALT_CONST_AEAD_RESP_HEADER_IV, KDFSALT_CONST_AEAD_RESP_HEADER_KEY,
    KDFSALT_CONST_AEAD_RESP_HEADER_LEN_IV, KDFSALT_CONST_AEAD_RESP_HEADER_LEN_KEY,
    KDFSALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV, KDFSALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY,
    KDFSALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV,
    KDFSALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY,
};
use crate::config::Config;
use crate::proxy::dns;

use std::io::Cursor;
use std::pin::Pin;
use std::task::{Context, Poll};

use aes::cipher::KeyInit;
use aes_gcm::{
    aead::{Aead, Payload},
    Aes128Gcm,
};
use bytes::{BufMut, BytesMut};
use futures_util::Stream;
use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use worker::*;

pin_project! {
    pub struct VmessStream<'a> {
        pub config: Config,
        pub ws: &'a WebSocket,
        pub buffer: BytesMut,
        #[pin]
        pub events: EventStream<'a>,
    }
}

impl<'a> VmessStream<'a> {
    pub fn new(config: Config, ws: &'a WebSocket, events: EventStream<'a>) -> Self {
        let buffer = BytesMut::new();
        Self {
            config,
            ws,
            buffer,
            events,
        }
    }

    async fn handle_tcp_outbound(&mut self, addr: String, port: u16) -> Result<()> {
        let mut remote_socket = Socket::builder().connect(&addr, port)
            .map_err(|e| Error::RustError(e.to_string()))?;
        remote_socket.opened().await
            .map_err(|e| Error::RustError(e.to_string()))?;
        tokio::io::copy_bidirectional(self, &mut remote_socket).await
            .map_err(|e| Error::RustError(e.to_string()))?;
        Ok(())
    }

    async fn handle_udp_outbound(&mut self) -> Result<()> {
        let mut buff = vec![0u8; 65535];
        let n = self.read(&mut buff).await?;
        let data = &buff[..n];
        if dns::doh(data).await.is_ok() {
            self.write(data).await?;
        }
        Ok(())
    }

    async fn aead_decrypt(&mut self) -> Result<Vec<u8>> {
        let key = crate::md5!(
            &self.config.uuid.as_bytes(),
            b"c48619fe-8f02-49e0-b9e9-edf763e17e21"
        );

        let mut auth_id = [0u8; 16];
        self.read_exact(&mut auth_id).await?;
        let mut len = [0u8; 18];
        self.read_exact(&mut len).await?;
        let mut nonce = [0u8; 8];
        self.read_exact(&mut nonce).await?;

        let header_length = {
            let header_length_key = &hash::kdf(
                &key,
                &[
                    KDFSALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY,
                    &auth_id,
                    &nonce,
                ],
            )[..16];
            let header_length_nonce = &hash::kdf(
                &key,
                &[
                    KDFSALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV,
                    &auth_id,
                    &nonce,
                ],
            )[..12];

            let payload = Payload {
                msg: &len,
                aad: &auth_id,
            };

            let len = Aes128Gcm::new(header_length_key.into())
                .decrypt(header_length_nonce.into(), payload)
                .map_err(|e| Error::RustError(e.to_string()))?;
            ((len[0] as u16) << 8) | (len[1] as u16)
        };

        let mut cmd = vec![0u8; (header_length + 16) as _];
        self.read_exact(&mut cmd).await?;

        let header_payload = {
            let payload_key = &hash::kdf(
                &key,
                &[
                    KDFSALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY,
                    &auth_id,
                    &nonce,
                ],
            )[..16];
            let payload_nonce = &hash::kdf(
                &key,
                &[KDFSALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV, &auth_id, &nonce],
            )[..12];

            let payload = Payload {
                msg: &cmd,
                aad: &auth_id,
            };

            Aes128Gcm::new(payload_key.into())
                .decrypt(payload_nonce.into(), payload)
                .map_err(|e| Error::RustError(e.to_string()))?
        };
        Ok(header_payload)
    }

    pub async fn process(&mut self) -> Result<()> {
        let mut buf = Cursor::new(self.aead_decrypt().await?);

        let version = buf.read_u8().await?;
        if version != 1 {
            return Err(Error::RustError("invalid version".to_string()));
        }

        let mut iv = [0u8; 16];
        buf.read_exact(&mut iv).await?;
        let mut key = [0u8; 16];
        buf.read_exact(&mut key).await?;

        let mut options = [0u8; 4];
        buf.read_exact(&mut options).await?;

        let cmd = buf.read_u8().await?;
        let is_tcp = cmd == 0x1;

        let remote_port = parse_port(&mut buf).await?;
        let remote_addr = parse_addr(&mut buf).await?;

        let key = &crate::sha256!(&key)[..16];
        let iv = &crate::sha256!(&iv)[..16];

        let length_key = &hash::kdf(&key, &[KDFSALT_CONST_AEAD_RESP_HEADER_LEN_KEY])[..16];
        let length_iv = &hash::kdf(&iv, &[KDFSALT_CONST_AEAD_RESP_HEADER_LEN_IV])[..12];
        let length = Aes128Gcm::new(length_key.into())
            .encrypt(length_iv.into(), &4u16.to_be_bytes()[..])
            .map_err(|e| Error::RustError(e.to_string()))?;
        self.write(&length).await?;

        let payload_key = &hash::kdf(&key, &[KDFSALT_CONST_AEAD_RESP_HEADER_KEY])[..16];
        let payload_iv = &hash::kdf(&iv, &[KDFSALT_CONST_AEAD_RESP_HEADER_IV])[..12];
        let header = {
            let header = [options[0], 0x00, 0x00, 0x00];
            Aes128Gcm::new(payload_key.into())
                .encrypt(payload_iv.into(), &header[..])
                .map_err(|e| Error::RustError(e.to_string()))?
        };
        self.write(&header).await?;

        if is_tcp {
            let addr_pool = [
                (remote_addr.clone(), remote_port),
                (self.config.proxy_addr.clone(), self.config.proxy_port),
            ];
            let mut success = false;
            for (target_addr, target_port) in addr_pool {
                if self.handle_tcp_outbound(target_addr, target_port).await.is_ok() {
                    success = true;
                    break;
                }
            }
            if !success {
                return Err(Error::RustError("No available upstream".to_string()));
            }
        } else {
            self.handle_udp_outbound().await?;
        }
        Ok(())
    }
}

impl<'a> AsyncRead for VmessStream<'a> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<tokio::io::Result<()>> {
        let mut this = self.project();
        loop {
            let size = std::cmp::min(this.buffer.len(), buf.remaining());
            if size > 0 {
                buf.put_slice(&this.buffer.split_to(size));
                return Poll::Ready(Ok(()));
            }
            match this.events.as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(WebsocketEvent::Message(msg)))) => {
                    if let Some(data) = msg.bytes() {
                        this.buffer.put_slice(&data);
                    }
                }
                Poll::Pending => return Poll::Pending,
                _ => return Poll::Ready(Ok(())),
            }
        }
    }
}

impl<'a> AsyncWrite for VmessStream<'a> {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<tokio::io::Result<usize>> {
        Poll::Ready(
            self.ws
                .send_with_bytes(buf)
                .map(|_| buf.len())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string())),
        )
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<tokio::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<tokio::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
