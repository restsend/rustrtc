use crate::transports::dtls::DtlsTransport;
use anyhow::Result;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::sync::{Arc, Mutex, Weak};
use tokio::sync::{Mutex as TokioMutex, mpsc};
use tracing::{trace, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SctpState {
    New,
    Connecting,
    Connected,
    Closed,
}

#[derive(Debug, Clone)]
pub enum DataChannelEvent {
    Open,
    Message(Vec<u8>),
    Close,
}

pub struct DataChannel {
    pub id: u16,
    pub label: String,
    pub state: Mutex<DataChannelState>,
    pub next_ssn: Mutex<u16>,
    tx: Mutex<Option<mpsc::UnboundedSender<DataChannelEvent>>>,
    rx: TokioMutex<mpsc::UnboundedReceiver<DataChannelEvent>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataChannelState {
    Connecting,
    Open,
    Closing,
    Closed,
}

// SCTP Constants
const SCTP_COMMON_HEADER_SIZE: usize = 12;
const CHUNK_HEADER_SIZE: usize = 4;

// Chunk Types
const CT_DATA: u8 = 0;
const CT_INIT: u8 = 1;
const CT_INIT_ACK: u8 = 2;
const CT_SACK: u8 = 3;
const CT_HEARTBEAT: u8 = 4;
const CT_HEARTBEAT_ACK: u8 = 5;
#[allow(unused)]
const CT_ABORT: u8 = 6;
#[allow(unused)]
const CT_SHUTDOWN: u8 = 7;
#[allow(unused)]
const CT_SHUTDOWN_ACK: u8 = 8;
#[allow(unused)]
const CT_ERROR: u8 = 9;
const CT_COOKIE_ECHO: u8 = 10;
const CT_COOKIE_ACK: u8 = 11;

struct SctpInner {
    dtls_transport: Arc<DtlsTransport>,
    state: Arc<Mutex<SctpState>>,
    data_channels: Arc<Mutex<Vec<Weak<DataChannel>>>>,
    local_port: u16,
    remote_port: u16,
    verification_tag: Mutex<u32>,
    remote_verification_tag: Mutex<u32>,
    next_tsn: Mutex<u32>,
}

pub struct SctpTransport {
    inner: Arc<SctpInner>,
    close_tx: Arc<tokio::sync::Notify>,
}

impl SctpTransport {
    pub fn new(
        dtls_transport: Arc<DtlsTransport>,
        data_channels: Arc<Mutex<Vec<Weak<DataChannel>>>>,
        local_port: u16,
        remote_port: u16,
    ) -> (Arc<Self>, impl std::future::Future<Output = ()> + Send + 'static) {
        let inner = Arc::new(SctpInner {
            dtls_transport,
            state: Arc::new(Mutex::new(SctpState::New)),
            data_channels,
            local_port,
            remote_port,
            verification_tag: Mutex::new(0),
            remote_verification_tag: Mutex::new(0),
            next_tsn: Mutex::new(0),
        });

        let close_tx = Arc::new(tokio::sync::Notify::new());
        let close_rx = close_tx.clone();

        let transport = Arc::new(Self {
            inner: inner.clone(),
            close_tx,
        });

        let inner_clone = inner.clone();
        let runner = async move {
            inner_clone.run_loop(close_rx).await;
        };

        (transport, runner)
    }

    pub fn create_data_channel(&self, label: &str, id: u16) -> Arc<DataChannel> {
        let dc = Arc::new(DataChannel::new(id, label.to_string()));
        self.inner
            .data_channels
            .lock()
            .unwrap()
            .push(Arc::downgrade(&dc));
        dc
    }

    pub async fn send_data(&self, channel_id: u16, data: &[u8]) -> Result<()> {
        self.inner.send_data(channel_id, data).await
    }
}

impl Drop for SctpTransport {
    fn drop(&mut self) {
        self.close_tx.notify_waiters();
    }
}

impl SctpInner {
    async fn run_loop(&self, close_rx: Arc<tokio::sync::Notify>) {
        *self.state.lock().unwrap() = SctpState::Connecting;
        loop {
            tokio::select! {
                _ = close_rx.notified() => break,
                res = self.dtls_transport.recv() => {
                    match res {
                        Ok(packet) => {
                            if let Err(e) = self.handle_packet(&packet).await {
                                warn!("SCTP handle packet error: {}", e);
                            }
                        }
                        Err(e) => {
                            warn!("SCTP loop error: {}", e);
                            break;
                        }
                    }
                }
            }
        }

        *self.state.lock().unwrap() = SctpState::Closed;

        let channels = self.data_channels.lock().unwrap();
        for weak_dc in channels.iter() {
            if let Some(dc) = weak_dc.upgrade() {
                let mut state = dc.state.lock().unwrap();
                if *state != DataChannelState::Closed {
                    *state = DataChannelState::Closed;
                    drop(state);
                    dc.send_event(DataChannelEvent::Close);
                    dc.close_channel();
                }
            }
        }
    }

    async fn handle_packet(&self, packet: &[u8]) -> Result<()> {
        if packet.len() < SCTP_COMMON_HEADER_SIZE {
            return Ok(());
        }

        let mut buf = Bytes::copy_from_slice(packet);
        let _src_port = buf.get_u16();
        let _dst_port = buf.get_u16();
        let verification_tag = buf.get_u32();
        let _checksum = buf.get_u32();

        // Verify checksum (TODO)

        while buf.has_remaining() {
            if buf.remaining() < CHUNK_HEADER_SIZE {
                break;
            }
            let chunk_type = buf.get_u8();
            let chunk_flags = buf.get_u8();
            let chunk_length = buf.get_u16() as usize;

            if chunk_length < CHUNK_HEADER_SIZE
                || buf.remaining() < chunk_length - CHUNK_HEADER_SIZE
            {
                break;
            }

            let chunk_value = buf.split_to(chunk_length - CHUNK_HEADER_SIZE);

            // Padding
            let padding = (4 - (chunk_length % 4)) % 4;
            if buf.remaining() >= padding {
                buf.advance(padding);
            }

            match chunk_type {
                CT_INIT => self.handle_init(verification_tag, chunk_value).await?,
                CT_COOKIE_ECHO => self.handle_cookie_echo(chunk_value).await?,
                CT_DATA => self.handle_data(chunk_flags, chunk_value).await?,
                CT_HEARTBEAT => self.handle_heartbeat(chunk_value).await?,
                _ => {
                    trace!("Unhandled SCTP chunk type: {}", chunk_type);
                }
            }
        }
        Ok(())
    }

    async fn handle_init(&self, _remote_tag: u32, chunk: Bytes) -> Result<()> {
        let mut buf = chunk;
        if buf.remaining() < 16 {
            // Fixed params
            return Ok(());
        }
        let initiate_tag = buf.get_u32();
        let _a_rwnd = buf.get_u32();
        let _outbound_streams = buf.get_u16();
        let _inbound_streams = buf.get_u16();
        let _initial_tsn = buf.get_u32();

        *self.remote_verification_tag.lock().unwrap() = initiate_tag;

        // Generate local tag
        let local_tag = 12345; // Fixed for now
        *self.verification_tag.lock().unwrap() = local_tag;

        // Send INIT ACK
        // We need to construct a cookie. For simplicity, we'll just echo back some dummy data.
        let cookie = b"dummy_cookie";

        let mut init_ack_params = BytesMut::new();
        // Initiate Tag
        init_ack_params.put_u32(local_tag);
        // a_rwnd
        init_ack_params.put_u32(1024 * 1024);
        // Outbound streams
        init_ack_params.put_u16(10);
        // Inbound streams
        init_ack_params.put_u16(10);
        // Initial TSN
        init_ack_params.put_u32(0);

        // State Cookie Parameter (Type 7)
        init_ack_params.put_u16(7);
        init_ack_params.put_u16(4 + cookie.len() as u16);
        init_ack_params.put_slice(cookie);
        // Padding for cookie
        let padding = (4 - (cookie.len() % 4)) % 4;
        for _ in 0..padding {
            init_ack_params.put_u8(0);
        }

        self.send_chunk(CT_INIT_ACK, 0, init_ack_params.freeze(), initiate_tag)
            .await?;
        Ok(())
    }

    async fn handle_cookie_echo(&self, _chunk: Bytes) -> Result<()> {
        // Send COOKIE ACK
        let tag = *self.remote_verification_tag.lock().unwrap();
        self.send_chunk(CT_COOKIE_ACK, 0, Bytes::new(), tag).await?;

        *self.state.lock().unwrap() = SctpState::Connected;
        {
            let mut channels = self.data_channels.lock().unwrap();
            channels.retain(|weak_dc| {
                if let Some(dc) = weak_dc.upgrade() {
                    *dc.state.lock().unwrap() = DataChannelState::Open;
                    dc.send_event(DataChannelEvent::Open);
                    true
                } else {
                    false
                }
            });
        }

        Ok(())
    }

    async fn handle_heartbeat(&self, chunk: Bytes) -> Result<()> {
        // Send HEARTBEAT ACK with same info
        // ...

        let tag = *self.remote_verification_tag.lock().unwrap();
        self.send_chunk(CT_HEARTBEAT_ACK, 0, chunk, tag).await?;
        Ok(())
    }

    async fn handle_data(&self, _flags: u8, chunk: Bytes) -> Result<()> {
        let mut buf = chunk;
        if buf.remaining() < 12 {
            return Ok(());
        }
        let tsn = buf.get_u32();
        let stream_id = buf.get_u16();
        let _stream_seq = buf.get_u16();
        let _payload_proto = buf.get_u32();

        let user_data = buf;

        // Send SACK (Simplified: just ack this TSN)
        let mut sack = BytesMut::new();
        sack.put_u32(tsn); // Cumulative TSN Ack
        sack.put_u32(1024 * 1024); // a_rwnd
        sack.put_u16(0); // Number of Gap Ack Blocks
        sack.put_u16(0); // Number of Duplicate TSNs

        let tag = *self.remote_verification_tag.lock().unwrap();
        self.send_chunk(CT_SACK, 0, sack.freeze(), tag).await?;

        let mut channels = self.data_channels.lock().unwrap();
        let mut found_dc = None;
        channels.retain(|weak_dc| {
            if let Some(dc) = weak_dc.upgrade() {
                if dc.id == stream_id {
                    found_dc = Some(dc);
                }
                true
            } else {
                false
            }
        });

        if let Some(dc) = found_dc {
            dc.send_event(DataChannelEvent::Message(user_data.to_vec()));
        }

        Ok(())
    }

    async fn send_chunk(
        &self,
        type_: u8,
        flags: u8,
        value: Bytes,
        verification_tag: u32,
    ) -> Result<()> {
        let mut packet = BytesMut::new();

        // Common Header
        packet.put_u16(self.local_port);
        packet.put_u16(self.remote_port);
        packet.put_u32(verification_tag);
        packet.put_u32(0); // Checksum placeholder

        // Chunk
        packet.put_u8(type_);
        packet.put_u8(flags);
        packet.put_u16((CHUNK_HEADER_SIZE + value.len()) as u16);
        packet.put_slice(&value);

        // Padding
        let padding = (4 - (value.len() % 4)) % 4;
        for _ in 0..padding {
            packet.put_u8(0);
        }

        // Calculate Checksum (CRC32c)
        let checksum = crc32c::crc32c(&packet);

        let mut packet_bytes = packet.to_vec();
        let checksum_bytes = checksum.to_le_bytes();

        packet_bytes[8] = checksum_bytes[0];
        packet_bytes[9] = checksum_bytes[1];
        packet_bytes[10] = checksum_bytes[2];
        packet_bytes[11] = checksum_bytes[3];

        self.dtls_transport.send(&packet_bytes).await
    }

    pub async fn send_data(&self, channel_id: u16, data: &[u8]) -> Result<()> {
        // Wrap in DATA chunk
        let mut payload = BytesMut::new();

        let tsn = {
            let mut tsn_guard = self.next_tsn.lock().unwrap();
            let tsn = *tsn_guard;
            *tsn_guard = tsn.wrapping_add(1);
            tsn
        };

        let ssn = {
            let mut channels = self.data_channels.lock().unwrap();
            let mut found_dc = None;
            channels.retain(|weak_dc| {
                if let Some(dc) = weak_dc.upgrade() {
                    if dc.id == channel_id {
                        found_dc = Some(dc);
                    }
                    true
                } else {
                    false
                }
            });

            if let Some(dc) = found_dc {
                let mut ssn_guard = dc.next_ssn.lock().unwrap();
                let ssn = *ssn_guard;
                *ssn_guard = ssn.wrapping_add(1);
                ssn
            } else {
                0
            }
        };

        payload.put_u32(tsn); // TSN
        payload.put_u16(channel_id); // Stream ID
        payload.put_u16(ssn); // Stream Seq
        payload.put_u32(51); // PPID: WebRTC String (51) or Binary (53)
        payload.put_slice(data);

        let tag = *self.remote_verification_tag.lock().unwrap();
        self.send_chunk(CT_DATA, 0x03, payload.freeze(), tag).await // 0x03 = B(egin) | E(nd)
    }
}

impl DataChannel {
    pub fn new(id: u16, label: String) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self {
            id,
            label,
            state: Mutex::new(DataChannelState::Connecting),
            next_ssn: Mutex::new(0),
            tx: Mutex::new(Some(tx)),
            rx: TokioMutex::new(rx),
        }
    }

    pub async fn recv(&self) -> Option<DataChannelEvent> {
        let mut rx = self.rx.lock().await;
        rx.recv().await
    }

    pub(crate) fn send_event(&self, event: DataChannelEvent) {
        if let Some(tx) = &*self.tx.lock().unwrap() {
            let _ = tx.send(event);
        }
    }

    pub(crate) fn close_channel(&self) {
        *self.tx.lock().unwrap() = None;
    }
}
