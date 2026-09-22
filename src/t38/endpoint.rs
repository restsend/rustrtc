use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

use crate::errors::RtcResult;
use crate::t38::ifp::{DataField, IfpPacket, T30Indicator};
#[cfg(test)]
use crate::t38::t30::T30FaxConfig;
use crate::t38::t30::{T30Event, T30Session};
use crate::t38::wire::{WirePacket, decode_wire};
use crate::transports::udptl::{UdtlConfig, UdtlReceiveBuffer, UdtlTransport};
use bytes::Bytes;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReceiveCodec {
    #[default]
    Auto,

    Wire,

    Per,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FaxRxPacket {
    Per(IfpPacket),
    Wire(WirePacket),
}

impl FaxRxPacket {
    pub fn indicators(&self) -> &[T30Indicator] {
        match self {
            Self::Per(IfpPacket::T30Indicator(v)) => v,
            Self::Wire(WirePacket::Indicator(v)) => v,
            _ => &[],
        }
    }

    pub fn is_data(&self) -> bool {
        matches!(
            self,
            Self::Per(IfpPacket::T30Data(_)) | Self::Wire(WirePacket::Data { .. })
        )
    }

    /// The (field_type, payload) pairs of a t30-data packet.
    pub fn data_fields(&self) -> Vec<(u8, Bytes)> {
        match self {
            Self::Wire(WirePacket::Data { fields, .. }) => fields
                .iter()
                .map(|f| (f.field_type as u8, Bytes::clone(&f.data)))
                .collect(),
            Self::Per(IfpPacket::T30Data(fields)) => fields
                .iter()
                .map(|f| (f.field_type as u8, Bytes::clone(&f.data)))
                .collect(),
            _ => Vec::new(),
        }
    }
}

pub struct FaxEndpoint {
    pub transport: Arc<UdtlTransport>,
    pub session: tokio::sync::Mutex<T30Session>,
    recv_buf: tokio::sync::Mutex<UdtlReceiveBuffer>,
    codec: std::sync::Mutex<ReceiveCodec>,
    #[allow(dead_code)]
    config: UdtlConfig,
}

enum T30RxInput {
    Indicators(Vec<T30Indicator>),
    Data {
        data_type: u8,
        fields: Vec<(u8, Bytes)>,
    },
}

impl FaxEndpoint {
    /// Create a new fax endpoint from an existing transport and session.
    pub fn new(transport: Arc<UdtlTransport>, session: T30Session) -> Self {
        Self {
            transport,
            session: tokio::sync::Mutex::new(session),
            recv_buf: tokio::sync::Mutex::new(UdtlReceiveBuffer::new()),
            codec: std::sync::Mutex::new(ReceiveCodec::Auto),
            config: UdtlConfig::default(),
        }
    }

    /// Create a fax endpoint with a bound UDP socket and remote address.
    pub async fn bind(
        local: SocketAddr,
        remote: SocketAddr,
        session: T30Session,
        config: UdtlConfig,
    ) -> RtcResult<Self> {
        let socket = Arc::new(
            UdpSocket::bind(local)
                .await
                .map_err(|e| crate::errors::RtcError::Transport(format!("bind: {e}")))?,
        );
        let transport = Arc::new(UdtlTransport::with_config(socket, remote, config.clone()));
        Ok(Self {
            transport,
            session: tokio::sync::Mutex::new(session),
            recv_buf: tokio::sync::Mutex::new(UdtlReceiveBuffer::new()),
            codec: std::sync::Mutex::new(ReceiveCodec::Auto),
            config,
        })
    }

    /// Create from a pre-bound socket. Useful when the PeerConnection
    /// has already bound the socket during SDP generation.
    pub fn from_socket(
        socket: Arc<UdpSocket>,
        remote_addr: SocketAddr,
        session: T30Session,
    ) -> Self {
        let transport = Arc::new(UdtlTransport::new(socket, remote_addr));
        Self {
            transport,
            session: tokio::sync::Mutex::new(session),
            recv_buf: tokio::sync::Mutex::new(UdtlReceiveBuffer::new()),
            codec: std::sync::Mutex::new(ReceiveCodec::Auto),
            config: UdtlConfig::default(),
        }
    }

    // ── T.30 convenience methods ─────────────────────────────────

    /// Start the fax call as the calling station (sends CNG tone).
    pub async fn start_calling(&self) {
        self.session.lock().await.start_calling();
    }

    /// Answer the fax call as the called station.
    pub async fn start_called(&self) {
        self.session.lock().await.start_called();
    }

    // ── Sending ───────────────────────────────────────────────────

    pub async fn send_indicator(&self, ind: T30Indicator) -> RtcResult<()> {
        let data = match self.codec() {
            ReceiveCodec::Per => IfpPacket::T30Indicator(vec![ind]).encode()?,
            _ => crate::t38::wire::encode_wire_indicator(3, ind as i32).ok_or_else(|| {
                crate::errors::RtcError::Protocol("indicator not encodable".into())
            })?,
        };
        self.transport.send(&data).await
    }

    pub async fn send_data(&self, fields: Vec<DataField>) -> RtcResult<()> {
        self.send_data_typed(crate::t38::t30::T30_DATA_V21, fields)
            .await
    }

    pub async fn send_data_typed(&self, data_type: u8, fields: Vec<DataField>) -> RtcResult<()> {
        let data = match self.codec() {
            ReceiveCodec::Per => IfpPacket::T30Data(fields).encode()?,
            _ => {
                let wire_fields: Vec<crate::t38::wire::WireDataField> = fields
                    .into_iter()
                    .map(|f| crate::t38::wire::WireDataField::new(f.field_type as i32, f.data))
                    .collect();
                crate::t38::wire::encode_wire_data(3, data_type as i32, &wire_fields)
                    .ok_or_else(|| crate::errors::RtcError::Protocol("data not encodable".into()))?
            }
        };
        self.transport.send(&data).await
    }

    // ── Receiving ─────────────────────────────────────────────────

    pub fn set_codec(&self, codec: ReceiveCodec) {
        *self.codec.lock().unwrap_or_else(|p| p.into_inner()) = codec;
    }

    pub fn set_receive_codec(&self, codec: ReceiveCodec) {
        self.set_codec(codec);
    }

    pub fn codec(&self) -> ReceiveCodec {
        *self.codec.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn receive_codec(&self) -> ReceiveCodec {
        self.codec()
    }

    fn decode_rx(&self, raw: &[u8]) -> RtcResult<FaxRxPacket> {
        match self.codec() {
            ReceiveCodec::Wire => decode_wire(raw).map(FaxRxPacket::Wire).map_err(Into::into),
            ReceiveCodec::Per => IfpPacket::decode(raw).map(FaxRxPacket::Per),
            ReceiveCodec::Auto => match decode_wire(raw) {
                Ok(pkt) => Ok(FaxRxPacket::Wire(pkt)),
                Err(wire_err) => match IfpPacket::decode(raw) {
                    Ok(pkt) => Ok(FaxRxPacket::Per(pkt)),
                    Err(_) => Err(crate::errors::RtcError::Protocol(format!(
                        "IFP decode failed (wire: {wire_err})"
                    ))),
                },
            },
        }
    }

    /// Receive the next IFP packet with a timeout.
    /// Returns `None` if no packet arrives within the timeout.
    pub async fn recv_timeout(&self, timeout: std::time::Duration) -> Option<FaxRxPacket> {
        tokio::time::timeout(timeout, self.recv())
            .await
            .ok()
            .flatten()
    }

    /// Receive the next IFP packet. Blocks until data arrives.
    pub async fn recv(&self) -> Option<FaxRxPacket> {
        loop {
            let mut buf = self.recv_buf.lock().await;
            match self.transport.recv(&mut buf).await {
                Ok(Some(raw)) => {
                    drop(buf);
                    match self.decode_rx(&raw) {
                        Ok(pkt) => return Some(pkt),
                        Err(e) => {
                            tracing::warn!("FaxEndpoint: IFP decode error: {e}");
                            continue;
                        }
                    }
                }
                Ok(None) => {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                    continue;
                }
                Err(e) => {
                    tracing::warn!("FaxEndpoint: UDPTL recv error: {e}");
                    return None;
                }
            }
        }
    }

    /// Receive raw IFP bytes.
    pub async fn recv_raw(&self) -> RtcResult<Option<Bytes>> {
        let mut buf = self.recv_buf.lock().await;
        self.transport.recv(&mut buf).await
    }

    // ── Drain events ──────────────────────────────────────────────

    /// Drain T.30 session events.
    pub async fn drain_events(&self) -> Vec<T30Event> {
        let mut session = self.session.lock().await;
        let events: Vec<_> = session.events.drain(..).collect();
        events
    }

    // ── Live session driver ───────────────────────────────────────

    fn to_rx_event(pkt: &FaxRxPacket) -> T30RxInput {
        match pkt {
            FaxRxPacket::Wire(WirePacket::Indicator(list)) => T30RxInput::Indicators(list.clone()),
            FaxRxPacket::Wire(WirePacket::Data { data_type, fields }) => T30RxInput::Data {
                data_type: *data_type,
                fields: fields
                    .iter()
                    .map(|f| (f.field_type as u8, Bytes::clone(&f.data)))
                    .collect(),
            },
            FaxRxPacket::Per(IfpPacket::T30Indicator(list)) => T30RxInput::Indicators(list.clone()),
            FaxRxPacket::Per(IfpPacket::T30Data(fields)) => T30RxInput::Data {
                data_type: crate::t38::t30::T30_DATA_V21,
                fields: fields
                    .iter()
                    .map(|f| (f.field_type as u8, Bytes::clone(&f.data)))
                    .collect(),
            },
        }
    }

    /// Drive a complete T.30 session to completion.
    ///
    /// Sends queued tx units as they become due, feeds received packets into
    /// the session, and returns when the session reaches a terminal state or
    /// `max_ms` elapses. Set the codec to [`ReceiveCodec::Wire`] so that the
    /// modem data type travels with each packet.
    pub async fn run_call(&self, max_ms: u64) -> Vec<T30Event> {
        let start = std::time::Instant::now();
        let mut collected: Vec<T30Event> = Vec::new();
        {
            let mut session = self.session.lock().await;
            if session.state == crate::t38::t30::T30State::Idle {
                session.start_at(0);
            }
        }
        loop {
            let now = start.elapsed().as_millis() as u64;
            {
                let mut session = self.session.lock().await;
                while let Some(unit) = session.pop_tx(now) {
                    let result = match unit.action {
                        crate::t38::t30::TxAction::Indicator(ind) => self.send_indicator(ind).await,
                        crate::t38::t30::TxAction::HdlcFrame(bytes) => {
                            self.send_data_typed(
                                unit.data_type,
                                vec![
                                    DataField {
                                        field_type: crate::t38::ifp::DataFieldType::HdlcData,
                                        data: bytes,
                                    },
                                    DataField {
                                        field_type: crate::t38::ifp::DataFieldType::HdlcFcsOkSigEnd,
                                        data: Bytes::new(),
                                    },
                                ],
                            )
                            .await
                        }
                        crate::t38::t30::TxAction::NonEcmChunk(d) => {
                            self.send_data_typed(
                                unit.data_type,
                                vec![DataField {
                                    field_type: crate::t38::ifp::DataFieldType::T4NonEcm,
                                    data: d,
                                }],
                            )
                            .await
                        }
                        crate::t38::t30::TxAction::NonEcmSigEnd(d) => {
                            self.send_data_typed(
                                unit.data_type,
                                vec![DataField {
                                    field_type: crate::t38::ifp::DataFieldType::T4NonEcmSigEnd,
                                    data: d,
                                }],
                            )
                            .await
                        }
                    };
                    if let Err(e) = result {
                        tracing::warn!("FaxEndpoint: tx failed: {e}");
                    }
                }
                collected.extend(session.drain_events());
                if matches!(
                    session.state,
                    crate::t38::t30::T30State::Complete | crate::t38::t30::T30State::Failed
                ) {
                    return collected;
                }
            }

            if now >= max_ms {
                collected.push(T30Event::Error("run_call budget exhausted".into()));
                return collected;
            }

            if let Some(pkt) = self
                .recv_timeout(std::time::Duration::from_millis(20))
                .await
            {
                let input = Self::to_rx_event(&pkt);
                let mut session = self.session.lock().await;
                match input {
                    T30RxInput::Indicators(list) => {
                        for ind in list {
                            session.on_indicator(ind);
                        }
                    }
                    T30RxInput::Data { data_type, fields } => {
                        for (ft, data) in fields {
                            session.on_data(data_type, ft, &data);
                        }
                    }
                }
                collected.extend(session.drain_events());
                if matches!(
                    session.state,
                    crate::t38::t30::T30State::Complete | crate::t38::t30::T30State::Failed
                ) {
                    return collected;
                }
            }
        }
    }

    // ── Reset ─────────────────────────────────────────────────────

    /// Reset the session and receive buffer.
    pub async fn reset(&self) {
        self.session.lock().await.reset();
        self.recv_buf.lock().await.reset(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::t38::ifp::DataFieldType;

    fn hdlc_field(frame_type: u8, data: &[u8]) -> DataField {
        let mut frame = vec![0xFF, 0xFF, frame_type];
        frame.extend_from_slice(data);
        DataField {
            field_type: DataFieldType::HdlcFcsOk,
            data: Bytes::from(frame),
        }
    }

    #[tokio::test]
    async fn test_fax_endpoint_create_and_send_recv() {
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a_addr = a.local_addr().unwrap();
        let b_addr = b.local_addr().unwrap();

        let ta = Arc::new(a);
        let tb = Arc::new(b);

        let fax_a = FaxEndpoint::from_socket(ta, b_addr, T30Session::new(T30FaxConfig::default()));
        let fax_b = FaxEndpoint::from_socket(tb, a_addr, T30Session::new(T30FaxConfig::default()));
        fax_a.set_codec(ReceiveCodec::Per);
        fax_b.set_codec(ReceiveCodec::Per);

        fax_a.send_indicator(T30Indicator::Cng).await.unwrap();
        fax_a.session.lock().await.start_calling();

        let recv = tokio::time::timeout(std::time::Duration::from_secs(1), fax_b.recv())
            .await
            .unwrap();
        let recv = recv.expect("packet");
        assert_eq!(recv.indicators(), &[T30Indicator::Cng]);
    }

    #[tokio::test]
    async fn test_fax_endpoint_indicator_roundtrip() {
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a_addr = a.local_addr().unwrap();
        let b_addr = b.local_addr().unwrap();

        let fax_a = FaxEndpoint::from_socket(
            Arc::new(a),
            b_addr,
            T30Session::new(T30FaxConfig::default()),
        );
        let fax_b = FaxEndpoint::from_socket(
            Arc::new(b),
            a_addr,
            T30Session::new(T30FaxConfig::default()),
        );
        fax_a.set_codec(ReceiveCodec::Per);
        fax_b.set_codec(ReceiveCodec::Per);

        for ind in &[
            T30Indicator::Cng,
            T30Indicator::Ced,
            T30Indicator::V21Preamble,
        ] {
            fax_a.send_indicator(*ind).await.unwrap();
            let recv = tokio::time::timeout(std::time::Duration::from_millis(500), fax_b.recv())
                .await
                .unwrap();
            let recv = recv.expect("packet");
            assert!(recv.indicators().contains(ind));
        }
    }

    #[tokio::test]
    async fn test_fax_endpoint_data_roundtrip() {
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a_addr = a.local_addr().unwrap();
        let b_addr = b.local_addr().unwrap();

        let fax_a = FaxEndpoint::from_socket(
            Arc::new(a),
            b_addr,
            T30Session::new(T30FaxConfig::default()),
        );
        let fax_b = FaxEndpoint::from_socket(
            Arc::new(b),
            a_addr,
            T30Session::new(T30FaxConfig::default()),
        );
        fax_a.set_codec(ReceiveCodec::Per);
        fax_b.set_codec(ReceiveCodec::Per);

        let data = vec![0xFF, 0x01, 0x02, 0x80, 0x20];
        fax_a
            .send_data(vec![hdlc_field(0x01, &data)])
            .await
            .unwrap();

        let recv = tokio::time::timeout(std::time::Duration::from_secs(1), fax_b.recv())
            .await
            .unwrap();
        let recv = recv.expect("packet");
        assert!(recv.is_data());
    }

    #[tokio::test]
    async fn test_fax_endpoint_recv_timeout() {
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a_addr = a.local_addr().unwrap();

        let fax_b = FaxEndpoint::from_socket(
            Arc::new(b),
            a_addr,
            T30Session::new(T30FaxConfig::default()),
        );

        // No data sent, should timeout
        let result = fax_b
            .recv_timeout(std::time::Duration::from_millis(50))
            .await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_fax_endpoint_bind() {
        let session = T30Session::new(T30FaxConfig::default());
        let remote = "127.0.0.1:9999".parse().unwrap();
        let fax = FaxEndpoint::bind(
            "127.0.0.1:0".parse().unwrap(),
            remote,
            session,
            UdtlConfig::default(),
        )
        .await
        .unwrap();
        assert_eq!(
            fax.transport.local_addr().unwrap().ip().to_string(),
            "127.0.0.1"
        );
    }

    #[tokio::test]
    async fn test_fax_endpoint_wire_interop() {
        use crate::t38::wire::{WireDataField, encode_wire_data, encode_wire_indicator};
        use crate::transports::udptl::UdtlTransport;

        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a_addr = a.local_addr().unwrap();
        let b_addr = b.local_addr().unwrap();

        let fax = FaxEndpoint::from_socket(
            Arc::new(b),
            a_addr,
            T30Session::new(T30FaxConfig::default()),
        );
        fax.set_receive_codec(ReceiveCodec::Wire);
        assert_eq!(fax.receive_codec(), ReceiveCodec::Wire);

        let peer = UdtlTransport::new(Arc::new(a), b_addr);

        peer.send(&encode_wire_indicator(3, 1).unwrap())
            .await
            .unwrap();
        let pkt = tokio::time::timeout(std::time::Duration::from_secs(1), fax.recv())
            .await
            .unwrap()
            .expect("indicator");
        assert!(
            matches!(pkt, FaxRxPacket::Wire(WirePacket::Indicator(ref v)) if v.contains(&T30Indicator::Cng))
        );

        let dis = encode_wire_data(
            3,
            0,
            &[WireDataField::new(2, vec![0xFF, 0xFF, 0x01, 0x00, 0x00])],
        )
        .unwrap();
        peer.send(&dis).await.unwrap();
        let pkt = tokio::time::timeout(std::time::Duration::from_secs(1), fax.recv())
            .await
            .unwrap()
            .expect("data");
        let FaxRxPacket::Wire(WirePacket::Data { data_type, fields }) = pkt else {
            panic!("expected wire data packet");
        };
        assert_eq!(data_type, 0);
        assert_eq!(fields[0].field_type, 2);

        fax.send_indicator(T30Indicator::V3314400Training)
            .await
            .unwrap();
        let mut buf = UdtlReceiveBuffer::new();
        let raw = peer.recv(&mut buf).await.unwrap().unwrap();
        assert_eq!(raw, vec![0x21, 0x80]);
    }
}
