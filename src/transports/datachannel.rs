use anyhow::Result;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use parking_lot::Mutex;
use std::sync::atomic::{AtomicU16, AtomicUsize};
use tokio::sync::{Mutex as TokioMutex, mpsc};

// DCEP Constants
pub const DATA_CHANNEL_PPID_DCEP: u32 = 50;
pub const DATA_CHANNEL_PPID_STRING: u32 = 51;
pub const DATA_CHANNEL_PPID_BINARY: u32 = 53;

pub const DCEP_TYPE_OPEN: u8 = 0x03;
pub const DCEP_TYPE_ACK: u8 = 0x02;

#[derive(Debug, Clone)]
pub struct DataChannelOpen {
    pub message_type: u8,
    pub channel_type: u8,
    pub priority: u16,
    pub reliability_parameter: u32,
    pub label: String,
    pub protocol: String,
}

impl DataChannelOpen {
    pub fn marshal(&self) -> Vec<u8> {
        let mut buf = BytesMut::new();
        buf.put_u8(self.message_type);
        buf.put_u8(self.channel_type);
        buf.put_u16(self.priority);
        buf.put_u32(self.reliability_parameter);

        let label_bytes = self.label.as_bytes();
        buf.put_u16(label_bytes.len() as u16);

        let protocol_bytes = self.protocol.as_bytes();
        buf.put_u16(protocol_bytes.len() as u16);

        buf.put_slice(label_bytes);
        buf.put_slice(protocol_bytes);

        buf.to_vec()
    }

    pub fn unmarshal(data: &[u8]) -> Result<Self> {
        let mut buf = Bytes::copy_from_slice(data);
        if buf.remaining() < 12 {
            return Err(anyhow::anyhow!("DCEP Open message too short"));
        }

        let message_type = buf.get_u8();
        if message_type != DCEP_TYPE_OPEN {
            return Err(anyhow::anyhow!("Invalid DCEP message type"));
        }

        let channel_type = buf.get_u8();
        let priority = buf.get_u16();
        let reliability_parameter = buf.get_u32();
        let label_len = buf.get_u16() as usize;
        let protocol_len = buf.get_u16() as usize;

        if buf.remaining() < label_len + protocol_len {
            return Err(anyhow::anyhow!("DCEP Open message too short for payload"));
        }

        let label_bytes = buf.split_to(label_len);
        let protocol_bytes = buf.split_to(protocol_len);

        let label = String::from_utf8(label_bytes.to_vec())?;
        let protocol = String::from_utf8(protocol_bytes.to_vec())?;

        Ok(Self {
            message_type,
            channel_type,
            priority,
            reliability_parameter,
            label,
            protocol,
        })
    }
}

#[derive(Debug, Clone)]
pub struct DataChannelAck {
    pub message_type: u8,
}

impl DataChannelAck {
    pub fn marshal(&self) -> Vec<u8> {
        vec![self.message_type]
    }

    pub fn unmarshal(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(anyhow::anyhow!("DCEP Ack message too short"));
        }
        let message_type = data[0];
        if message_type != DCEP_TYPE_ACK {
            return Err(anyhow::anyhow!("Invalid DCEP message type"));
        }
        Ok(Self { message_type })
    }
}

#[derive(Debug, Clone)]
pub enum DataChannelEvent {
    Open,
    Message(Bytes),
    Close,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum DataChannelState {
    Connecting = 0,
    Open = 1,
    Closing = 2,
    Closed = 3,
}

impl From<usize> for DataChannelState {
    fn from(v: usize) -> Self {
        match v {
            0 => DataChannelState::Connecting,
            1 => DataChannelState::Open,
            2 => DataChannelState::Closing,
            3 => DataChannelState::Closed,
            _ => DataChannelState::Closed,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct DataChannelConfig {
    pub label: String,
    pub protocol: String,
    pub ordered: bool,
    pub max_retransmits: Option<u16>,
    pub max_packet_life_time: Option<u16>,
    pub max_payload_size: Option<usize>,
    pub negotiated: Option<u16>,
}

pub struct DataChannel {
    pub id: u16,
    pub label: String,
    pub protocol: String,
    pub ordered: bool,
    pub max_retransmits: Option<u16>,
    pub max_packet_life_time: Option<u16>,
    pub max_payload_size: usize,
    pub negotiated: bool,
    pub state: AtomicUsize,
    pub next_ssn: AtomicU16,
    tx: Mutex<Option<mpsc::UnboundedSender<DataChannelEvent>>>,
    rx: TokioMutex<mpsc::UnboundedReceiver<DataChannelEvent>>,
    pub(crate) reassembly_buffer: Mutex<BytesMut>,
    pub(crate) send_lock: TokioMutex<()>,
}

impl DataChannel {
    pub fn new(id: u16, config: DataChannelConfig) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self {
            id,
            label: config.label,
            protocol: config.protocol,
            ordered: config.ordered,
            max_retransmits: config.max_retransmits,
            max_packet_life_time: config.max_packet_life_time,
            max_payload_size: config.max_payload_size.unwrap_or(1200),
            negotiated: config.negotiated.is_some(),
            state: AtomicUsize::new(DataChannelState::Connecting as usize),
            next_ssn: AtomicU16::new(0),
            tx: Mutex::new(Some(tx)),
            rx: TokioMutex::new(rx),
            reassembly_buffer: Mutex::new(BytesMut::new()),
            send_lock: TokioMutex::new(()),
        }
    }

    pub async fn recv(&self) -> Option<DataChannelEvent> {
        let mut rx = self.rx.lock().await;
        rx.recv().await
    }

    pub(crate) fn send_event(&self, event: DataChannelEvent) {
        if let Some(tx) = &*self.tx.lock() {
            let _ = tx.send(event);
        }
    }

    pub(crate) fn close_channel(&self) {
        *self.tx.lock() = None;
    }
}
