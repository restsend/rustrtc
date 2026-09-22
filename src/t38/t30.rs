use bytes::Bytes;
use std::collections::VecDeque;

use crate::t38::ifp::T30Indicator;

pub const HDLC_ADDRESS: u8 = 0xFF;
pub const HDLC_CONTROL_FINAL: u8 = 0xC8;
pub const HDLC_CONTROL_NON_FINAL: u8 = 0xC0;
pub const FCF_X_BIT: u8 = 0x80;

pub const FCF_DIS: u8 = 0x01;
pub const FCF_CSI: u8 = 0x02;
pub const FCF_NSF: u8 = 0x04;
pub const FCF_DTC: u8 = 0x81;
pub const FCF_CIG: u8 = 0x82;
pub const FCF_DCS: u8 = 0x41;
pub const FCF_TSI: u8 = 0x42;
pub const FCF_NSS: u8 = 0x44;
pub const FCF_SUB: u8 = 0x43;
pub const FCF_CFR: u8 = 0x21;
pub const FCF_FTT: u8 = 0x22;
pub const FCF_CTR: u8 = 0x23;
pub const FCF_EOM: u8 = 0x71;
pub const FCF_MPS: u8 = 0x72;
pub const FCF_EOP: u8 = 0x74;
pub const FCF_MCF: u8 = 0x31;
pub const FCF_RTP: u8 = 0x33;
pub const FCF_RTN: u8 = 0x32;
pub const FCF_PIP: u8 = 0x35;
pub const FCF_PIN: u8 = 0x34;
pub const FCF_DCN: u8 = 0x5F;
pub const FCF_CRP: u8 = 0x58;
pub const FCF_NSC: u8 = 0x24;
pub const FCF_PPS: u8 = 0x7D;
pub const FCF_EOR: u8 = 0x73;
pub const FCF_PPR: u8 = 0x3C;
pub const FCF_RNR: u8 = 0x38;

pub const T30_DATA_V21: u8 = 0;
pub const T30_DATA_V17_14400: u8 = 1;
pub const T30_DATA_V17_12000: u8 = 2;
pub const T30_DATA_V17_9600: u8 = 3;
pub const T30_DATA_V17_7200: u8 = 4;
pub const T30_DATA_V29_9600: u8 = 5;
pub const T30_DATA_V29_7200: u8 = 6;
pub const T30_DATA_V27TER_4800: u8 = 7;
pub const T30_DATA_V27TER_2400: u8 = 8;

pub const FIELD_HDLC_DATA: u8 = 0;
pub const FIELD_HDLC_SIG_END: u8 = 1;
pub const FIELD_HDLC_FCS_OK: u8 = 2;
pub const FIELD_HDLC_FCS_BAD: u8 = 3;
pub const FIELD_HDLC_FCS_OK_SIG_END: u8 = 4;
pub const FIELD_HDLC_FCS_BAD_SIG_END: u8 = 5;
pub const FIELD_T4_NON_ECM: u8 = 6;
pub const FIELD_T4_NON_ECM_SIG_END: u8 = 7;

const DIS_BIT_T38: u16 = 3;
const DIS_BIT_READY_TO_RECEIVE: u16 = 10;
const DIS_BIT_MODEM_V29: u16 = 11;
const DIS_BIT_MODEM_V27TER: u16 = 12;
const DIS_BIT_ECM: u16 = 27;
const DCS_BIT_RECEIVE: u16 = 10;
const DCS_BIT_2D: u16 = 16;
const DCS_BIT_MODEM_CODE_SHIFT: u16 = 11;

pub const TCF_DURATION_MS: u32 = 1500;
pub const TCF_ZERO_BYTES: usize = (TCF_DURATION_MS as usize * 4800) / 8 / 1000;

pub const NON_ECM_CHUNK: usize = 54;
pub const NON_ECM_PACE_MS: u64 = 40;
pub const HDLC_FRAME_PACE_MS: u64 = 75;
pub const DIS_REPEAT_MS: u64 = 3000;
pub const CNG_REPEAT_MS: u64 = 5000;
pub const CED_TO_DIS_MS: u64 = 1900;
pub const DIS_TO_RESPONSE_MS: u64 = 400;
pub const T1_MS: u64 = 35000;
pub const T1_MAX_MS: u64 = 60000;
pub const FCF_FCD: u8 = 0x80;
pub const FCF_RCP: u8 = 0x83;
pub const FCF_RCP_MASKED: u8 = 0x03;
pub const ECM_FRAME_OCTETS: usize = 256;
pub const ECM_MAX_PPR: u8 = 4;
const DCS_BIT_ECM: u16 = 16;
pub const T2_MS: u64 = 6000;
pub const T4_MS: u64 = 3450;
pub const MAX_TRAIN_RETRIES: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum T30Phase {
    Idle,
    CallingToneSent,
    CalledToneReceived,
    Premessage,
    Training,
    ReadyToTransmit,
    TransmittingPage,
    PostPage,
    ReadyToReceive,
    ReceivingPage,
    Disconnecting,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum T30Resolution {
    Standard,
    Fine,
    SuperFine,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum T30Role {
    Caller,
    Callee,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum T30State {
    Idle,
    ToneSending,
    WaitingDis,
    SendingDis,
    WaitingTraining,
    SendingCfr,
    WaitingPage,
    ReceivingPage,
    SendingMcf,
    WaitingDcn,
    SendingDcs,
    WaitingCfr,
    SendingPage,
    WaitingMcf,
    Complete,
    Failed,
}

#[derive(Debug, Clone)]
pub struct T30FaxConfig {
    pub max_bitrate: u32,
    pub resolutions: Vec<T30Resolution>,
    pub ecm_supported: bool,
    pub local_id: String,
}

impl Default for T30FaxConfig {
    fn default() -> Self {
        Self {
            max_bitrate: 14400,
            resolutions: vec![T30Resolution::Standard, T30Resolution::Fine],
            ecm_supported: false,
            local_id: String::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HdlcFrameType {
    Fcd,
    Rcp,
    Dis,
    Csi,
    Nsf,
    Dtc,
    Cig,
    Nsc,
    Dcs,
    Tsi,
    Nss,
    Sub,
    Cfr,
    Ftt,
    Ctr,
    Eom,
    Mps,
    Eop,
    PriEom,
    PriMps,
    PriEop,
    Mcf,
    Rtp,
    Rtn,
    Pip,
    Pin,
    Pps,
    Eor,
    Ppr,
    Rnr,
    Dcn,
    Crp,
    Unknown,
}

impl HdlcFrameType {
    pub fn from_fcf(fcf: u8) -> Self {
        match fcf & !FCF_X_BIT {
            0x00 => Self::Fcd,
            FCF_RCP_MASKED => Self::Rcp,
            FCF_DIS => Self::Dis,
            FCF_CSI => Self::Csi,
            FCF_NSF => Self::Nsf,
            FCF_DTC => Self::Dtc,
            FCF_CIG => Self::Cig,
            FCF_NSC => Self::Nsc,
            FCF_DCS => Self::Dcs,
            FCF_TSI => Self::Tsi,
            FCF_NSS => Self::Nss,
            FCF_SUB => Self::Sub,
            FCF_CFR => Self::Cfr,
            FCF_FTT => Self::Ftt,
            FCF_CTR => Self::Ctr,
            FCF_EOM => Self::Eom,
            FCF_MPS => Self::Mps,
            FCF_EOP => Self::Eop,
            FCF_MCF => Self::Mcf,
            FCF_RTP => Self::Rtp,
            FCF_RTN => Self::Rtn,
            FCF_PIP => Self::Pip,
            FCF_PIN => Self::Pin,
            FCF_PPS => Self::Pps,
            FCF_EOR => Self::Eor,
            FCF_PPR => Self::Ppr,
            FCF_RNR => Self::Rnr,
            FCF_DCN => Self::Dcn,
            FCF_CRP => Self::Crp,
            _ => Self::Unknown,
        }
    }

    pub fn fcf_value(self) -> u8 {
        match self {
            Self::Fcd => FCF_FCD,
            Self::Rcp => FCF_RCP,
            Self::Dis => FCF_DIS,
            Self::Csi => FCF_CSI,
            Self::Nsf => FCF_NSF,
            Self::Dtc => FCF_DTC,
            Self::Cig => FCF_CIG,
            Self::Nsc => FCF_NSC,
            Self::Dcs => FCF_DCS,
            Self::Tsi => FCF_TSI,
            Self::Nss => FCF_NSS,
            Self::Sub => FCF_SUB,
            Self::Cfr => FCF_CFR,
            Self::Ftt => FCF_FTT,
            Self::Ctr => FCF_CTR,
            Self::Eom => FCF_EOM,
            Self::Mps => FCF_MPS,
            Self::Eop => FCF_EOP,
            Self::PriEom => 0x89,
            Self::PriMps => 0x4B,
            Self::PriEop => 0x2B,
            Self::Mcf => FCF_MCF,
            Self::Rtp => FCF_RTP,
            Self::Rtn => FCF_RTN,
            Self::Pip => FCF_PIP,
            Self::Pin => FCF_PIN,
            Self::Pps => FCF_PPS,
            Self::Eor => FCF_EOR,
            Self::Ppr => FCF_PPR,
            Self::Rnr => FCF_RNR,
            Self::Dcn => FCF_DCN,
            Self::Crp => FCF_CRP,
            Self::Unknown => 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HdlcFrame {
    pub control: u8,
    pub fcf: u8,
    pub fif: Vec<u8>,
}

impl HdlcFrame {
    pub fn simple(frame_type: HdlcFrameType, x_bit: bool) -> Self {
        let mut fcf = frame_type.fcf_value();
        if x_bit {
            fcf |= FCF_X_BIT;
        }
        Self {
            control: HDLC_CONTROL_FINAL,
            fcf,
            fif: Vec::new(),
        }
    }

    pub fn with_fif(frame_type: HdlcFrameType, x_bit: bool, fif: Vec<u8>) -> Self {
        let mut fcf = frame_type.fcf_value();
        if x_bit {
            fcf |= FCF_X_BIT;
        }
        Self {
            control: HDLC_CONTROL_FINAL,
            fcf,
            fif,
        }
    }

    pub fn non_final(mut self) -> Self {
        self.control = HDLC_CONTROL_NON_FINAL;
        self
    }

    pub fn frame_type(&self) -> HdlcFrameType {
        HdlcFrameType::from_fcf(self.fcf)
    }

    pub fn is_final(&self) -> bool {
        self.control & 0x08 != 0
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(3 + self.fif.len());
        out.push(HDLC_ADDRESS);
        out.push(self.control);
        out.push(self.fcf);
        out.extend_from_slice(&self.fif);
        out
    }

    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 3 || bytes[0] != HDLC_ADDRESS {
            return None;
        }
        Some(Self {
            control: bytes[1],
            fcf: bytes[2],
            fif: bytes[3..].to_vec(),
        })
    }
}

fn fif_bit(fif: &[u8], bit: u16) -> bool {
    let idx = (bit - 1) as usize;
    let mask = 0x80u8 >> (idx % 8);
    fif.get(idx / 8).map(|b| b & mask != 0).unwrap_or(false)
}

fn set_fif_bit(fif: &mut [u8], bit: u16) {
    let idx = (bit - 1) as usize;
    let byte = idx / 8;
    if byte < fif.len() {
        fif[byte] |= 0x80u8 >> (idx % 8);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectedModem {
    V27Ter4800,
    V27Ter2400,
    V29_7200,
    V29_9600,
    Unsupported,
}

pub fn parse_dis_modem(fif: &[u8]) -> SelectedModem {
    let v29 = fif_bit(fif, DIS_BIT_MODEM_V29);
    let v27 = fif_bit(fif, DIS_BIT_MODEM_V27TER);
    if v27 {
        SelectedModem::V27Ter4800
    } else if v29 {
        SelectedModem::V29_9600
    } else {
        SelectedModem::V27Ter2400
    }
}

pub fn parse_dis_receive_ready(fif: &[u8]) -> bool {
    fif_bit(fif, DIS_BIT_READY_TO_RECEIVE)
}

pub fn build_dis_fif(receive_ready: bool, ecm: bool) -> Vec<u8> {
    let mut fif = vec![0u8; 4];
    set_fif_bit(&mut fif, DIS_BIT_T38);
    if receive_ready {
        set_fif_bit(&mut fif, DIS_BIT_READY_TO_RECEIVE);
    }
    set_fif_bit(&mut fif, DIS_BIT_MODEM_V27TER);
    if ecm {
        set_fif_bit(&mut fif, DIS_BIT_ECM);
    }
    fif
}

pub fn build_dcs_fif(modem: SelectedModem, ecm: bool) -> Vec<u8> {
    let mut fif = vec![0u8; 4];
    set_fif_bit(&mut fif, DCS_BIT_RECEIVE);
    if ecm {
        set_fif_bit(&mut fif, DCS_BIT_ECM);
    }
    let code: u8 = match modem {
        SelectedModem::V27Ter4800 => 4,
        SelectedModem::V27Ter2400 => 0,
        SelectedModem::V29_7200 => 2,
        SelectedModem::V29_9600 => 3,
        SelectedModem::Unsupported => 0,
    };
    let byte = ((DCS_BIT_MODEM_CODE_SHIFT - 1) / 8) as usize;
    if byte < fif.len() {
        fif[byte] |= code << 2;
    }
    fif
}

pub fn parse_dcs_modem(fif: &[u8]) -> SelectedModem {
    let code = (fif.get(1).copied().unwrap_or(0) >> 2) & 0x0F;
    match code {
        0 => SelectedModem::V27Ter2400,
        2 => SelectedModem::V29_7200,
        3 => SelectedModem::V29_9600,
        4 => SelectedModem::V27Ter4800,
        _ => SelectedModem::Unsupported,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxAction {
    Indicator(T30Indicator),
    HdlcFrame(Bytes),
    NonEcmChunk(Bytes),
    NonEcmSigEnd(Bytes),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxUnit {
    pub send_at: u64,
    pub data_type: u8,
    pub action: TxAction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum T30Event {
    PhaseChange(T30Phase, T30Phase),
    RemoteIdentification { id: String },
    LocalIdentification { id: String },
    PageTransferred { page: u32, size: usize },
    PageReceived { page: u32, size: usize },
    DisReceived,
    DcsReceived,
    TrainingOk,
    CfrReceived,
    FttReceived,
    EopReceived,
    McfReceived,
    DcnReceived,
    Disconnected,
    Error(String),
}

pub struct T30Session {
    pub role: T30Role,
    pub state: T30State,
    pub phase: T30Phase,
    pub local_config: T30FaxConfig,
    pub remote_config: Option<T30FaxConfig>,
    pub remote_modem: Option<SelectedModem>,
    pub page_number: u32,
    pub tx_page: Bytes,
    pub page_data: Vec<u8>,
    pub hdlc_buffer: Vec<u8>,
    pub events: VecDeque<T30Event>,
    pub now: u64,
    tx_queue: VecDeque<TxUnit>,
    deadline: Option<u64>,
    tx_cursor: u64,
    x_bit: bool,
    train_retries: u32,
    cng_count: u32,
    dis_count: u32,
    tcf_zeros: usize,
    in_tcf: bool,
    t1_max_ms: u64,
    ecm: bool,
    ecm_block: std::collections::BTreeMap<u8, Vec<u8>>,
    ecm_frames_tx: u8,
    ecm_ppr_retries: u8,
    ecm_await_pps_ack: bool,
    ecm_rcp_seen: bool,
    high_speed_data_type: u8,
    dcs_fif_override: Option<Vec<u8>>,
    two_dim_coding: bool,
}

impl T30Session {
    pub fn new(local_config: T30FaxConfig) -> Self {
        Self {
            role: T30Role::Caller,
            state: T30State::Idle,
            phase: T30Phase::Idle,
            local_config,
            remote_config: None,
            remote_modem: None,
            page_number: 0,
            tx_page: Bytes::new(),
            page_data: Vec::new(),
            hdlc_buffer: Vec::new(),
            events: VecDeque::new(),
            now: 0,
            tx_queue: VecDeque::new(),
            deadline: None,
            tx_cursor: 0,
            x_bit: false,
            train_retries: 0,
            cng_count: 0,
            dis_count: 0,
            tcf_zeros: 0,
            in_tcf: false,
            t1_max_ms: T1_MAX_MS,
            ecm: false,
            ecm_block: std::collections::BTreeMap::new(),
            ecm_frames_tx: 0,
            ecm_ppr_retries: 0,
            ecm_await_pps_ack: false,
            ecm_rcp_seen: false,
            high_speed_data_type: T30_DATA_V27TER_4800,
            dcs_fif_override: None,
            two_dim_coding: false,
        }
    }

    pub fn set_two_dim_coding(&mut self, two_dim: bool) {
        self.two_dim_coding = two_dim;
    }

    pub fn set_t1_max_ms(&mut self, ms: u64) {
        self.t1_max_ms = ms;
    }

    pub fn set_high_speed_data_type(&mut self, data_type: u8) {
        self.high_speed_data_type = data_type;
    }

    pub fn set_dcs_fif(&mut self, fif: Vec<u8>) {
        self.dcs_fif_override = Some(fif);
    }

    pub fn start_calling(&mut self) {
        self.role = T30Role::Caller;
        self.start_at(0);
    }

    pub fn start_called(&mut self) {
        self.role = T30Role::Callee;
        self.start_at(0);
    }

    pub fn start_at(&mut self, now_ms: u64) {
        self.now = now_ms;
        self.tx_queue.clear();
        self.tx_cursor = now_ms;
        self.deadline = None;
        match self.role {
            T30Role::Caller => {
                self.set_state(T30State::ToneSending);
                self.change_phase(T30Phase::CallingToneSent);
                self.queue_at(TxAction::Indicator(T30Indicator::Cng), now_ms);
                self.cng_count = 1;
                self.set_deadline(self.t1_max_ms);
            }
            T30Role::Callee => {
                self.set_state(T30State::ToneSending);
                self.change_phase(T30Phase::CalledToneReceived);
                self.queue_at(TxAction::Indicator(T30Indicator::Ced), now_ms);
                self.queue_dis_burst(now_ms + CED_TO_DIS_MS);
                self.set_deadline(self.t1_max_ms);
            }
        }
    }

    pub fn set_tx_page(&mut self, page: impl Into<Bytes>) {
        self.tx_page = page.into();
    }

    pub fn take_page_data(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.page_data)
    }

    fn set_state(&mut self, s: T30State) {
        self.state = s;
    }

    fn set_deadline(&mut self, in_ms: u64) {
        self.deadline = Some(self.now + in_ms);
    }

    fn clear_deadline(&mut self) {
        self.deadline = None;
    }

    fn next_tx_time(&mut self) -> u64 {
        self.tx_cursor
    }

    fn push_unit(&mut self, delay_ms: u64, data_type: u8, action: TxAction) {
        self.tx_cursor = self.tx_cursor.max(self.now) + delay_ms;
        self.tx_queue.push_back(TxUnit {
            send_at: self.tx_cursor,
            data_type,
            action,
        });
    }

    fn push_unit_at(&mut self, delay_ms: u64, data_type: u8, action: TxAction, at: u64) {
        self.tx_queue.push_back(TxUnit {
            send_at: at + delay_ms,
            data_type,
            action,
        });
    }

    fn queue_at(&mut self, action: TxAction, at: u64) {
        self.tx_cursor = self.tx_cursor.max(at);
        self.tx_queue.push_back(TxUnit {
            send_at: at,
            data_type: T30_DATA_V21,
            action,
        });
    }

    fn queue_dis_burst(&mut self, at: u64) {
        let fif = build_dis_fif(true, self.local_config.ecm_supported);
        let frame = HdlcFrame::with_fif(HdlcFrameType::Dis, self.x_bit, fif).to_bytes();
        self.queue_at(TxAction::Indicator(T30Indicator::V21Preamble), at);
        self.push_unit(
            HDLC_FRAME_PACE_MS,
            T30_DATA_V21,
            TxAction::HdlcFrame(Bytes::from(frame)),
        );
        self.dis_count += 1;
    }

    fn queue_simple_burst(&mut self, frame_type: HdlcFrameType) {
        let at = self.next_tx_time();
        let frame = HdlcFrame::simple(frame_type, self.x_bit).to_bytes();
        self.queue_at(TxAction::Indicator(T30Indicator::V21Preamble), at);
        self.push_unit(
            HDLC_FRAME_PACE_MS,
            T30_DATA_V21,
            TxAction::HdlcFrame(Bytes::from(frame)),
        );
    }

    fn queue_dcs_tcf(&mut self) {
        let modem = self.remote_modem.unwrap_or(SelectedModem::V27Ter4800);
        let t = self.next_tx_time();
        let tsi = HdlcFrame::with_fif(
            HdlcFrameType::Tsi,
            self.x_bit,
            self.local_config
                .local_id
                .as_bytes()
                .iter()
                .take(20)
                .copied()
                .collect(),
        )
        .non_final()
        .to_bytes();
        let mut dcs_fif = match self.dcs_fif_override.clone() {
            Some(fif) => fif,
            None => build_dcs_fif(modem, self.ecm),
        };
        if self.two_dim_coding {
            set_fif_bit(&mut dcs_fif, DCS_BIT_2D);
        }
        let dcs = HdlcFrame::with_fif(HdlcFrameType::Dcs, self.x_bit, dcs_fif).to_bytes();
        self.queue_at(TxAction::Indicator(T30Indicator::V21Preamble), t);
        self.push_unit(
            HDLC_FRAME_PACE_MS,
            T30_DATA_V21,
            TxAction::HdlcFrame(Bytes::from(tsi)),
        );
        self.push_unit(
            HDLC_FRAME_PACE_MS,
            T30_DATA_V21,
            TxAction::HdlcFrame(Bytes::from(dcs)),
        );
        let ind = match modem {
            SelectedModem::V27Ter2400 => T30Indicator::V27Ter2400Preamble,
            SelectedModem::V29_7200 => T30Indicator::V297200Preamble,
            SelectedModem::V29_9600 => T30Indicator::V299600Preamble,
            _ => T30Indicator::V27Ter4800Preamble,
        };
        self.push_unit(150, T30_DATA_V21, TxAction::Indicator(ind));
        let dt = match modem {
            SelectedModem::V27Ter2400 => T30_DATA_V27TER_2400,
            SelectedModem::V29_7200 => T30_DATA_V29_7200,
            SelectedModem::V29_9600 => T30_DATA_V29_9600,
            _ => self.high_speed_data_type,
        };
        let mut remaining = TCF_ZERO_BYTES;
        while remaining > NON_ECM_CHUNK {
            self.push_unit(
                NON_ECM_PACE_MS,
                dt,
                TxAction::NonEcmChunk(Bytes::from(vec![0u8; NON_ECM_CHUNK])),
            );
            remaining -= NON_ECM_CHUNK;
        }
        self.push_unit(
            NON_ECM_PACE_MS,
            dt,
            TxAction::NonEcmSigEnd(Bytes::from(vec![0u8; remaining])),
        );
        self.set_deadline(T4_MS);
    }

    fn queue_page(&mut self) {
        if self.ecm {
            self.queue_page_ecm();
            return;
        }
        let modem = self.remote_modem.unwrap_or(SelectedModem::V27Ter4800);
        let dt = match modem {
            SelectedModem::V27Ter2400 => T30_DATA_V27TER_2400,
            SelectedModem::V29_7200 => T30_DATA_V29_7200,
            SelectedModem::V29_9600 => T30_DATA_V29_9600,
            _ => self.high_speed_data_type,
        };
        let ind = match modem {
            SelectedModem::V27Ter2400 => T30Indicator::V27Ter2400Preamble,
            SelectedModem::V29_7200 => T30Indicator::V297200Preamble,
            SelectedModem::V29_9600 => T30Indicator::V299600Preamble,
            _ => T30Indicator::V27Ter4800Preamble,
        };
        let t = self.next_tx_time();
        self.queue_at(TxAction::Indicator(ind), t);
        let page = self.tx_page.clone();
        let mut last: Option<Bytes> = None;
        for (i, chunk) in page.chunks(NON_ECM_CHUNK).enumerate() {
            if let Some(prev) = last.take() {
                self.push_unit(NON_ECM_PACE_MS, dt, TxAction::NonEcmChunk(prev));
            }
            let slice = page.slice(i * NON_ECM_CHUNK..i * NON_ECM_CHUNK + chunk.len());
            last = Some(slice);
        }
        if let Some(prev) = last.take() {
            self.push_unit(NON_ECM_PACE_MS, dt, TxAction::NonEcmSigEnd(prev));
        } else {
            self.push_unit(NON_ECM_PACE_MS, dt, TxAction::NonEcmSigEnd(Bytes::new()));
        }
        let at = self.next_tx_time();
        self.queue_at(TxAction::Indicator(T30Indicator::V21Preamble), at);
        let eop = HdlcFrame::simple(HdlcFrameType::Eop, self.x_bit).to_bytes();
        self.push_unit(
            HDLC_FRAME_PACE_MS,
            T30_DATA_V21,
            TxAction::HdlcFrame(Bytes::from(eop)),
        );
    }

    fn queue_page_ecm(&mut self) {
        let modem = self.remote_modem.unwrap_or(SelectedModem::V27Ter4800);
        let dt = match modem {
            SelectedModem::V27Ter2400 => T30_DATA_V27TER_2400,
            SelectedModem::V29_7200 => T30_DATA_V29_7200,
            SelectedModem::V29_9600 => T30_DATA_V29_9600,
            _ => T30_DATA_V27TER_4800,
        };
        let ind = match modem {
            SelectedModem::V27Ter2400 => T30Indicator::V27Ter2400Preamble,
            SelectedModem::V29_7200 => T30Indicator::V297200Preamble,
            SelectedModem::V29_9600 => T30Indicator::V299600Preamble,
            _ => T30Indicator::V27Ter4800Preamble,
        };
        let t = self.next_tx_time();
        self.queue_at(TxAction::Indicator(ind), t);
        let page = self.tx_page.clone();
        let frames = page.len().div_ceil(ECM_FRAME_OCTETS);
        self.ecm_frames_tx = frames as u8;
        self.ecm_ppr_retries = 0;
        self.ecm_await_pps_ack = false;
        for (i, chunk) in page.chunks(ECM_FRAME_OCTETS).enumerate() {
            let mut fif = vec![(i + 1) as u8];
            fif.extend_from_slice(chunk);
            let fcd = HdlcFrame::with_fif(HdlcFrameType::Fcd, false, fif).to_bytes();
            self.push_unit(NON_ECM_PACE_MS, dt, TxAction::HdlcFrame(Bytes::from(fcd)));
        }
        let rcp = HdlcFrame::simple(HdlcFrameType::Rcp, false).to_bytes();
        for _ in 0..3 {
            self.push_unit(
                HDLC_FRAME_PACE_MS,
                T30_DATA_V21,
                TxAction::HdlcFrame(Bytes::from(rcp.clone())),
            );
        }
        self.set_state(T30State::SendingPage);
        self.set_deadline(T2_MS * 4);
    }

    fn queue_ecm_retransmit(&mut self, missing: &[u8]) {
        let modem = self.remote_modem.unwrap_or(SelectedModem::V27Ter4800);
        let dt = match modem {
            SelectedModem::V27Ter2400 => T30_DATA_V27TER_2400,
            SelectedModem::V29_7200 => T30_DATA_V29_7200,
            SelectedModem::V29_9600 => T30_DATA_V29_9600,
            _ => T30_DATA_V27TER_4800,
        };
        let page = self.tx_page.clone();
        let mut now = self.next_tx_time();
        for &frame_no in missing {
            let start = (frame_no as usize - 1) * ECM_FRAME_OCTETS;
            let end = (start + ECM_FRAME_OCTETS).min(page.len());
            let mut fif = vec![frame_no];
            fif.extend_from_slice(&page[start..end]);
            let fcd = HdlcFrame::with_fif(HdlcFrameType::Fcd, false, fif).to_bytes();
            self.push_unit_at(
                NON_ECM_PACE_MS,
                dt,
                TxAction::HdlcFrame(Bytes::from(fcd)),
                now,
            );
            now += NON_ECM_PACE_MS;
        }
        let rcp = HdlcFrame::simple(HdlcFrameType::Rcp, false).to_bytes();
        for _ in 0..3 {
            self.push_unit_at(
                HDLC_FRAME_PACE_MS,
                T30_DATA_V21,
                TxAction::HdlcFrame(Bytes::from(rcp.clone())),
                now,
            );
            now += HDLC_FRAME_PACE_MS;
        }
    }

    fn queue_pps_eop(&mut self) {
        let frames = self.ecm_frames_tx as u64;
        let fif = vec![(frames & 0xFF) as u8, (frames >> 8) as u8, 0x12];
        let pps = HdlcFrame::with_fif(HdlcFrameType::Pps, self.x_bit, fif).to_bytes();
        let at = self.next_tx_time();
        self.queue_at(TxAction::Indicator(T30Indicator::V21Preamble), at);
        self.push_unit(
            HDLC_FRAME_PACE_MS,
            T30_DATA_V21,
            TxAction::HdlcFrame(Bytes::from(pps)),
        );
        self.ecm_await_pps_ack = true;
        self.set_deadline(T4_MS);
    }

    fn on_ppr(&mut self, frame: HdlcFrame) {
        if self.role != T30Role::Caller || self.state != T30State::SendingPage || !self.ecm {
            return;
        }
        if self.ecm_ppr_retries >= ECM_MAX_PPR {
            self.fail("ECM PPR retry limit reached".into());
            return;
        }
        self.ecm_ppr_retries += 1;
        self.ecm_await_pps_ack = false;
        let mut missing: Vec<u8> = Vec::new();
        for frame_no in 1..=self.ecm_frames_tx {
            let idx = frame_no as usize - 1;
            let byte = frame.fif.get(idx / 8).copied().unwrap_or(0);
            if byte & (0x80 >> (idx % 8)) != 0 {
                missing.push(frame_no);
            }
        }
        if missing.is_empty() {
            self.queue_pps_eop();
            return;
        }
        self.queue_ecm_retransmit(&missing);
    }

    fn on_rcp(&mut self) {
        if self.role != T30Role::Callee || !self.ecm || self.ecm_rcp_seen {
            return;
        }
        self.ecm_rcp_seen = true;
        let max_seen = match self.ecm_block.keys().max() {
            Some(m) => *m,
            None => return,
        };
        let missing: Vec<u8> = (1..=max_seen)
            .filter(|n| !self.ecm_block.contains_key(n))
            .collect();
        let at = self.next_tx_time();
        self.queue_at(TxAction::Indicator(T30Indicator::V21Preamble), at);
        if missing.is_empty() {
            self.queue_simple_burst(HdlcFrameType::Mcf);
        } else {
            let mut bitmap = vec![0u8; 32];
            for &m in &missing {
                bitmap[(m as usize - 1) / 8] |= 0x80 >> ((m as usize - 1) % 8);
            }
            let ppr = HdlcFrame::with_fif(HdlcFrameType::Ppr, self.x_bit, bitmap).to_bytes();
            self.push_unit(
                HDLC_FRAME_PACE_MS,
                T30_DATA_V21,
                TxAction::HdlcFrame(Bytes::from(ppr)),
            );
        }
    }

    fn on_pps(&mut self, frame: HdlcFrame) {
        if self.role != T30Role::Callee || !self.ecm {
            return;
        }
        let n: usize = u64::from(frame.fif.first().copied().unwrap_or(0))
            .checked_add(256 * u64::from(frame.fif.get(1).copied().unwrap_or(0) & 0x07))
            .unwrap_or(0) as usize;
        if n == 0 || n > 255 {
            return;
        }
        let missing: Vec<usize> = (1..=n)
            .filter(|i| !self.ecm_block.contains_key(&(*i as u8)))
            .collect();
        if !missing.is_empty() {
            let at = self.next_tx_time();
            self.queue_at(TxAction::Indicator(T30Indicator::V21Preamble), at);
            let mut bitmap = vec![0u8; 32];
            for &m in &missing {
                bitmap[(m - 1) / 8] |= 0x80 >> ((m - 1) % 8);
            }
            let ppr = HdlcFrame::with_fif(HdlcFrameType::Ppr, self.x_bit, bitmap).to_bytes();
            self.push_unit(
                HDLC_FRAME_PACE_MS,
                T30_DATA_V21,
                TxAction::HdlcFrame(Bytes::from(ppr)),
            );
            return;
        }
        let mut data = Vec::with_capacity(n * ECM_FRAME_OCTETS);
        for i in 1..=n {
            data.extend_from_slice(&self.ecm_block[&(i as u8)]);
        }
        self.page_data = data;
        self.ecm_block.clear();
        let at = self.next_tx_time();
        self.queue_at(TxAction::Indicator(T30Indicator::V21Preamble), at);
        self.queue_simple_burst(HdlcFrameType::Mcf);
        self.page_complete();
        self.set_state(T30State::WaitingDcn);
        self.set_deadline(4000);
    }

    pub fn pop_tx(&mut self, now: u64) -> Option<TxUnit> {
        self.tick(now);
        if let Some(unit) = self.tx_queue.front()
            && unit.send_at <= self.now
        {
            return self.tx_queue.pop_front();
        }
        None
    }

    pub fn pending_tx(&self) -> bool {
        !self.tx_queue.is_empty()
    }

    pub fn tick(&mut self, now: u64) {
        self.now = self.now.max(now);
        if let Some(dl) = self.deadline
            && self.now >= dl
        {
            self.deadline = None;
            self.on_timeout();
        }
    }

    fn on_timeout(&mut self) {
        match self.state {
            T30State::ToneSending => match self.role {
                T30Role::Caller => {
                    if self.now >= self.t1_max_ms {
                        self.fail("T1 expired waiting for DIS".into());
                    } else if self.cng_count < 3 {
                        let at = self.next_tx_time();
                        self.queue_at(TxAction::Indicator(T30Indicator::Cng), at);
                        self.cng_count += 1;
                        self.set_deadline(CNG_REPEAT_MS);
                    } else {
                        self.set_deadline(CNG_REPEAT_MS);
                    }
                }
                T30Role::Callee => {
                    let at = self.next_tx_time();
                    self.queue_dis_burst(at);
                    self.set_deadline(DIS_REPEAT_MS);
                }
            },
            T30State::SendingDis => {
                let at = self.next_tx_time();
                self.queue_dis_burst(at);
                self.set_deadline(DIS_REPEAT_MS);
            }
            T30State::WaitingDis => {
                if self.role == T30Role::Caller {
                    if self.cng_count < 3 {
                        let at = self.next_tx_time();
                        self.queue_at(TxAction::Indicator(T30Indicator::Cng), at);
                        self.cng_count += 1;
                    }
                    if self.now > self.t1_max_ms {
                        self.fail("T1 expired waiting for DIS".into());
                    } else {
                        self.set_deadline(CNG_REPEAT_MS);
                    }
                } else {
                    let at = self.next_tx_time();
                    self.queue_dis_burst(at);
                    self.set_deadline(DIS_REPEAT_MS);
                }
            }
            T30State::WaitingTraining => {
                self.queue_simple_burst(HdlcFrameType::Ftt);
                self.set_state(T30State::SendingDis);
                self.set_deadline(DIS_REPEAT_MS);
            }
            T30State::WaitingCfr => {
                if self.train_retries < MAX_TRAIN_RETRIES {
                    self.train_retries += 1;
                    self.queue_dcs_tcf();
                    self.set_state(T30State::SendingDcs);
                } else {
                    self.fail("no response to training".into());
                }
            }
            T30State::WaitingPage => {
                self.fail("T2 expired waiting for page data".into());
            }
            T30State::WaitingMcf => {
                self.fail("no response to EOP".into());
            }
            T30State::WaitingDcn => {
                self.complete();
            }
            _ => {}
        }
    }

    fn fail(&mut self, msg: String) {
        self.set_state(T30State::Failed);
        self.clear_deadline();
        self.events.push_back(T30Event::Error(msg));
        self.events.push_back(T30Event::Disconnected);
    }

    fn complete(&mut self) {
        self.set_state(T30State::Complete);
        self.change_phase(T30Phase::Disconnecting);
        self.clear_deadline();
        self.events.push_back(T30Event::Disconnected);
    }

    pub fn on_indicator(&mut self, ind: T30Indicator) {
        match ind {
            T30Indicator::Ced => {
                if self.role == T30Role::Caller && self.state == T30State::ToneSending {
                    self.set_state(T30State::WaitingDis);
                }
            }
            T30Indicator::V27Ter2400Preamble
            | T30Indicator::V27Ter4800Preamble
            | T30Indicator::V297200Preamble
            | T30Indicator::V299600Preamble => {
                if self.state == T30State::WaitingTraining {
                    self.in_tcf = true;
                    self.tcf_zeros = 0;
                    self.set_deadline(T2_MS);
                } else if self.state == T30State::WaitingPage {
                    self.set_deadline(T2_MS);
                }
            }
            _ => {}
        }
    }

    pub fn on_data(&mut self, data_type: u8, field_type: u8, data: &[u8]) {
        match field_type {
            FIELD_HDLC_DATA | FIELD_HDLC_FCS_OK | FIELD_HDLC_FCS_OK_SIG_END => {
                let mut frame_data = self.hdlc_buffer.clone();
                frame_data.extend_from_slice(data);
                if field_type == FIELD_HDLC_DATA {
                    self.hdlc_buffer = frame_data;
                    return;
                }
                self.hdlc_buffer.clear();
                if let Some(frame) = HdlcFrame::parse(&frame_data) {
                    self.on_frame(frame);
                }
            }
            FIELD_T4_NON_ECM => self.on_non_ecm(data_type, data, false),
            FIELD_T4_NON_ECM_SIG_END => self.on_non_ecm(data_type, data, true),
            FIELD_HDLC_SIG_END | FIELD_HDLC_FCS_BAD | FIELD_HDLC_FCS_BAD_SIG_END => {
                self.hdlc_buffer.clear();
            }
            _ => {}
        }
    }

    fn on_non_ecm(&mut self, data_type: u8, data: &[u8], sig_end: bool) {
        let is_high_speed = data_type == T30_DATA_V27TER_4800
            || data_type == T30_DATA_V27TER_2400
            || matches!(data_type, 1..=6);
        match self.state {
            T30State::WaitingTraining => {
                if is_high_speed {
                    self.tcf_zeros += data.iter().filter(|&&b| b == 0).count();
                    self.set_deadline(T2_MS);
                    if sig_end {
                        self.training_ok();
                    }
                }
            }
            T30State::WaitingPage | T30State::ReceivingPage if is_high_speed => {
                self.page_data.extend_from_slice(data);
                self.set_state(T30State::ReceivingPage);
                self.change_phase(T30Phase::ReceivingPage);
                self.set_deadline(T2_MS);
                if sig_end {
                    self.page_complete();
                }
            }
            _ => {}
        }
    }

    fn training_ok(&mut self) {
        self.in_tcf = false;
        self.tcf_zeros = 0;
        self.events.push_back(T30Event::TrainingOk);
        self.change_phase(T30Phase::ReadyToReceive);
        self.queue_simple_burst(HdlcFrameType::Cfr);
        self.set_state(T30State::WaitingPage);
        self.set_deadline(T2_MS);
    }

    fn page_complete(&mut self) {
        self.page_number += 1;
        let size = self.page_data.len();
        self.events.push_back(T30Event::PageReceived {
            page: self.page_number,
            size,
        });
        self.set_state(T30State::WaitingPage);
        self.set_deadline(T2_MS);
    }

    fn on_frame(&mut self, frame: HdlcFrame) {
        let ftype = frame.frame_type();
        match ftype {
            HdlcFrameType::Dis => self.on_dis(frame),
            HdlcFrameType::Dcs => self.on_dcs(frame),
            HdlcFrameType::Tsi | HdlcFrameType::Cig => {
                let id: String = frame
                    .fif
                    .iter()
                    .map(|&b| b as char)
                    .filter(|c| c.is_ascii_graphic() || *c == ' ')
                    .collect();
                if !id.is_empty() {
                    self.events.push_back(T30Event::RemoteIdentification { id });
                }
            }
            HdlcFrameType::Cfr => self.on_cfr(),
            HdlcFrameType::Ftt => self.on_ftt(),
            HdlcFrameType::Mcf => {
                if self.role == T30Role::Caller && self.state == T30State::SendingPage && self.ecm {
                    self.on_mcf_ecm();
                } else {
                    self.on_mcf();
                }
            }
            HdlcFrameType::Rcp => self.on_rcp(),
            HdlcFrameType::Pps => self.on_pps(frame),
            HdlcFrameType::Ppr => self.on_ppr(frame),
            HdlcFrameType::Fcd => {
                if frame.fif.len() >= 2 {
                    let frame_no = frame.fif[0];
                    self.ecm_block.insert(frame_no, frame.fif[1..].to_vec());
                    self.ecm_rcp_seen = false;
                }
            }
            HdlcFrameType::Rtp | HdlcFrameType::Rtn => self.on_ftt(),
            HdlcFrameType::Eop | HdlcFrameType::PriEop => self.on_eop(),
            HdlcFrameType::Mps | HdlcFrameType::PriMps => self.on_mps(),
            HdlcFrameType::Eom | HdlcFrameType::PriEom => self.on_eom(),
            HdlcFrameType::Dcn => {
                self.events.push_back(T30Event::DcnReceived);
                if self.state == T30State::WaitingDcn {
                    self.complete();
                } else {
                    self.fail("unexpected DCN".into());
                }
            }
            _ => {}
        }
    }

    fn on_dis(&mut self, frame: HdlcFrame) {
        if self.role != T30Role::Caller {
            return;
        }
        match self.state {
            T30State::ToneSending | T30State::WaitingDis => {
                let modem = parse_dis_modem(&frame.fif);
                if modem == SelectedModem::Unsupported {
                    self.fail("remote has no compatible modem".into());
                    return;
                }
                self.remote_modem = Some(modem);
                let remote_ecm = fif_bit(&frame.fif, DIS_BIT_ECM);
                self.ecm = self.local_config.ecm_supported && remote_ecm;
                self.remote_config = Some(T30FaxConfig {
                    max_bitrate: 4800,
                    resolutions: vec![T30Resolution::Standard],
                    ecm_supported: remote_ecm,
                    local_id: String::new(),
                });
                self.x_bit = true;
                self.events.push_back(T30Event::DisReceived);
                self.change_phase(T30Phase::Premessage);
                self.cng_count = 99;
                self.tx_cursor = self.now + DIS_TO_RESPONSE_MS;
                self.queue_dcs_tcf();
                self.set_state(T30State::SendingDcs);
                self.change_phase(T30Phase::Training);
                self.set_deadline(T4_MS + 4000);
            }
            _ => {}
        }
    }

    fn on_dcs(&mut self, frame: HdlcFrame) {
        if self.role != T30Role::Callee {
            return;
        }
        if self.state == T30State::ToneSending
            || self.state == T30State::SendingDis
            || self.state == T30State::WaitingTraining
        {
            let modem = parse_dcs_modem(&frame.fif);
            if modem == SelectedModem::Unsupported {
                self.queue_simple_burst(HdlcFrameType::Ftt);
                self.set_state(T30State::SendingDis);
                self.set_deadline(DIS_REPEAT_MS);
                return;
            }
            self.remote_modem = Some(modem);
            self.ecm = fif_bit(&frame.fif, DCS_BIT_ECM);
            self.remote_config = Some(T30FaxConfig {
                max_bitrate: 4800,
                resolutions: vec![T30Resolution::Standard],
                ecm_supported: self.ecm,
                local_id: String::new(),
            });
            self.events.push_back(T30Event::DcsReceived);
            self.change_phase(T30Phase::Training);
            self.set_state(T30State::WaitingTraining);
            self.in_tcf = false;
            self.tcf_zeros = 0;
            self.set_deadline(T2_MS);
        }
    }

    fn on_cfr(&mut self) {
        if self.role == T30Role::Caller && self.state == T30State::SendingDcs {
            self.events.push_back(T30Event::CfrReceived);
            self.clear_deadline();
            self.change_phase(T30Phase::ReadyToTransmit);
            self.queue_page();
            self.set_state(T30State::SendingPage);
            self.change_phase(T30Phase::TransmittingPage);
        }
    }

    fn on_ftt(&mut self) {
        if self.role == T30Role::Caller
            && (self.state == T30State::SendingDcs || self.state == T30State::WaitingCfr)
        {
            self.events.push_back(T30Event::FttReceived);
            if self.train_retries < MAX_TRAIN_RETRIES {
                self.train_retries += 1;
                self.queue_dcs_tcf();
                self.set_state(T30State::SendingDcs);
            } else {
                self.queue_simple_burst(HdlcFrameType::Dcn);
                self.fail("training failed after retries".into());
            }
        }
    }

    fn on_mcf_ecm(&mut self) {
        if !self.ecm_await_pps_ack {
            self.queue_pps_eop();
            return;
        }
        self.events.push_back(T30Event::McfReceived);
        self.page_number += 1;
        let size = self.tx_page.len();
        self.events.push_back(T30Event::PageTransferred {
            page: self.page_number,
            size,
        });
        self.clear_deadline();
        let at = self.next_tx_time();
        self.queue_at(TxAction::Indicator(T30Indicator::V21Preamble), at);
        let dcn = HdlcFrame::simple(HdlcFrameType::Dcn, self.x_bit).to_bytes();
        self.push_unit(
            HDLC_FRAME_PACE_MS,
            T30_DATA_V21,
            TxAction::HdlcFrame(Bytes::from(dcn)),
        );
        self.set_state(T30State::WaitingDcn);
        self.set_deadline(4000);
    }

    fn on_mcf(&mut self) {
        if self.role == T30Role::Caller && self.state == T30State::SendingPage {
            self.events.push_back(T30Event::McfReceived);
            self.page_number += 1;
            let size = self.tx_page.len();
            self.events.push_back(T30Event::PageTransferred {
                page: self.page_number,
                size,
            });
            self.clear_deadline();
            let at = self.next_tx_time();
            self.queue_at(TxAction::Indicator(T30Indicator::V21Preamble), at);
            let dcn = HdlcFrame::simple(HdlcFrameType::Dcn, self.x_bit).to_bytes();
            self.push_unit(
                HDLC_FRAME_PACE_MS,
                T30_DATA_V21,
                TxAction::HdlcFrame(Bytes::from(dcn)),
            );
            self.set_state(T30State::WaitingDcn);
            self.set_deadline(4000);
        }
    }

    fn on_eop(&mut self) {
        if self.role == T30Role::Callee && self.state == T30State::WaitingPage {
            self.events.push_back(T30Event::EopReceived);
            self.change_phase(T30Phase::PostPage);
            self.queue_simple_burst(HdlcFrameType::Mcf);
            self.set_state(T30State::WaitingDcn);
            self.set_deadline(T2_MS);
        }
    }

    fn on_mps(&mut self) {
        if self.role == T30Role::Callee && self.state == T30State::WaitingPage {
            self.events.push_back(T30Event::EopReceived);
            self.queue_simple_burst(HdlcFrameType::Mcf);
            self.set_state(T30State::WaitingPage);
            self.set_deadline(T2_MS);
        }
    }

    fn on_eom(&mut self) {
        if self.role == T30Role::Callee && self.state == T30State::WaitingPage {
            self.events.push_back(T30Event::EopReceived);
            self.queue_simple_burst(HdlcFrameType::Mcf);
            self.set_state(T30State::WaitingTraining);
            self.set_deadline(T2_MS);
        }
    }

    pub fn drain_events(&mut self) -> Vec<T30Event> {
        self.events.drain(..).collect()
    }

    pub fn reset(&mut self) {
        self.state = T30State::Idle;
        self.phase = T30Phase::Idle;
        self.remote_config = None;
        self.remote_modem = None;
        self.remote_modem = None;
        self.page_number = 0;
        self.page_data.clear();
        self.tx_page.clear();
        self.hdlc_buffer.clear();
        self.tx_queue.clear();
        self.deadline = None;
        self.x_bit = false;
        self.train_retries = 0;
        self.cng_count = 0;
        self.dis_count = 0;
        self.tcf_zeros = 0;
        self.in_tcf = false;
        self.high_speed_data_type = T30_DATA_V27TER_4800;
        self.dcs_fif_override = None;
        self.two_dim_coding = false;
    }

    fn change_phase(&mut self, new_phase: T30Phase) {
        if self.phase != new_phase {
            let old = self.phase;
            self.phase = new_phase;
            self.events.push_back(T30Event::PhaseChange(old, new_phase));
        }
    }
}

impl std::fmt::Debug for T30Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("T30Session")
            .field("role", &self.role)
            .field("state", &self.state)
            .field("phase", &self.phase)
            .field("page_number", &self.page_number)
            .finish()
    }
}

#[cfg(test)]

mod ecm_tests {
    use super::*;
    use crate::t38::t30::{FIELD_HDLC_FCS_OK_SIG_END, T30_DATA_V21};

    #[derive(Clone)]
    enum Side {
        A,
        B,
    }

    struct Loop {
        a: T30Session,
        b: T30Session,
        now: u64,
        drop_next_fcd2: bool,
    }

    impl Loop {
        fn new() -> Self {
            let cfg = T30FaxConfig {
                ecm_supported: true,
                ..T30FaxConfig::default()
            };
            let mut a = T30Session::new(cfg.clone());
            a.role = T30Role::Caller;
            let mut b = T30Session::new(cfg);
            b.role = T30Role::Callee;
            a.start_calling();
            a.start_at(0);
            b.start_called();
            b.start_at(0);
            Self {
                a,
                b,
                now: 0,
                drop_next_fcd2: false,
            }
        }

        fn feed(_side: Side, session: &mut T30Session, bytes: &[u8]) {
            session.on_data(T30_DATA_V21, FIELD_HDLC_FCS_OK_SIG_END, bytes);
        }

        fn step(&mut self) {
            self.now += 20;
            self.a.tick(self.now);
            self.b.tick(self.now);
            let mut wire: Vec<(Side, Bytes)> = Vec::new();
            while let Some(unit) = self.a.pop_tx(self.now) {
                match unit.action {
                    TxAction::Indicator(ind) => self.b.on_indicator(ind),
                    TxAction::HdlcFrame(bytes) => {
                        let drop = self.drop_next_fcd2
                            && bytes.len() > 3
                            && bytes[2] == FCF_FCD
                            && bytes[3] == 2;
                        if drop {
                            self.drop_next_fcd2 = false;
                        } else {
                            wire.push((Side::B, bytes));
                        }
                    }
                    TxAction::NonEcmChunk(d) => {
                        self.b.on_data(unit.data_type, FIELD_T4_NON_ECM, &d);
                    }
                    TxAction::NonEcmSigEnd(d) => {
                        self.b.on_data(unit.data_type, FIELD_T4_NON_ECM_SIG_END, &d);
                    }
                }
            }
            while let Some(unit) = self.b.pop_tx(self.now) {
                match unit.action {
                    TxAction::Indicator(ind) => self.a.on_indicator(ind),
                    TxAction::HdlcFrame(bytes) => wire.push((Side::A, bytes)),
                    _ => {}
                }
            }
            for (side, bytes) in wire {
                match side {
                    Side::B => Self::feed(Side::B, &mut self.b, &bytes),
                    Side::A => Self::feed(Side::A, &mut self.a, &bytes),
                }
            }
        }
    }

    #[test]
    fn ecm_page_transfers_clean() {
        let mut lp = Loop::new();
        let page: Vec<u8> = (0..500u32).map(|i| (i * 7 % 251) as u8).collect();
        lp.a.set_tx_page(page.clone());
        lp.a.set_two_dim_coding(true);

        for _ in 0..3000 {
            lp.step();
            if lp.a.state == T30State::Complete && lp.b.state == T30State::Complete {
                break;
            }
        }

        let a_events = lp.a.drain_events();
        let b_events = lp.b.drain_events();
        assert_eq!(lp.a.state, T30State::Complete, "a: {a_events:?}");
        assert_eq!(lp.b.state, T30State::Complete, "b: {b_events:?}");
        assert_eq!(lp.b.take_page_data(), page);
    }

    #[test]
    fn ecm_ppr_recovers_lost_frame() {
        let mut lp = Loop::new();
        lp.drop_next_fcd2 = true;
        let page: Vec<u8> = (0..500u32).map(|i| (i * 11 % 249) as u8).collect();
        lp.a.set_tx_page(page.clone());

        for _ in 0..4000 {
            lp.step();
            if lp.a.state == T30State::Complete && lp.b.state == T30State::Complete {
                break;
            }
        }

        let a_events = lp.a.drain_events();
        let b_events = lp.b.drain_events();
        assert_eq!(lp.a.state, T30State::Complete, "a: {a_events:?}");
        assert_eq!(lp.b.state, T30State::Complete, "b: {b_events:?}");
        assert_eq!(lp.b.take_page_data(), page);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caller() -> T30Session {
        let mut s = T30Session::new(T30FaxConfig::default());
        s.role = T30Role::Caller;
        s
    }

    fn callee() -> T30Session {
        let mut s = T30Session::new(T30FaxConfig::default());
        s.role = T30Role::Callee;
        s
    }

    #[test]
    fn fcf_classification() {
        assert_eq!(HdlcFrameType::from_fcf(0x01), HdlcFrameType::Dis);
        assert_eq!(HdlcFrameType::from_fcf(0x81), HdlcFrameType::Dis);
        assert_eq!(HdlcFrameType::from_fcf(0x41), HdlcFrameType::Dcs);
        assert_eq!(HdlcFrameType::from_fcf(0xC1), HdlcFrameType::Dcs);
        assert_eq!(HdlcFrameType::from_fcf(0x42), HdlcFrameType::Tsi);
        assert_eq!(HdlcFrameType::from_fcf(0xC2), HdlcFrameType::Tsi);
        assert_eq!(HdlcFrameType::from_fcf(0x21), HdlcFrameType::Cfr);
        assert_eq!(HdlcFrameType::from_fcf(0x31), HdlcFrameType::Mcf);
        assert_eq!(HdlcFrameType::from_fcf(0x74), HdlcFrameType::Eop);
        assert_eq!(HdlcFrameType::from_fcf(0xF4), HdlcFrameType::Eop);
        assert_eq!(HdlcFrameType::from_fcf(0x5F), HdlcFrameType::Dcn);
        assert_eq!(HdlcFrameType::from_fcf(0xDF), HdlcFrameType::Dcn);
        assert_eq!(HdlcFrameType::from_fcf(0x22), HdlcFrameType::Ftt);
    }

    #[test]
    fn frame_roundtrip() {
        let f = HdlcFrame::with_fif(HdlcFrameType::Dis, false, build_dis_fif(true, false));
        let bytes = f.to_bytes();
        assert_eq!(bytes[0], HDLC_ADDRESS);
        assert_eq!(bytes[1], HDLC_CONTROL_FINAL);
        let parsed = HdlcFrame::parse(&bytes).unwrap();
        assert_eq!(parsed.frame_type(), HdlcFrameType::Dis);
        assert_eq!(parsed.fif, f.fif);
    }

    #[test]
    fn dis_fif_has_v27ter_and_receive() {
        let fif = build_dis_fif(true, true);
        assert!(parse_dis_receive_ready(&fif));
        assert_eq!(parse_dis_modem(&fif), SelectedModem::V27Ter4800);
    }

    #[test]
    fn dcs_fif_codes_v27ter_4800() {
        let fif = build_dcs_fif(SelectedModem::V27Ter4800, false);
        assert_eq!((fif[1] >> 2) & 0x0F, 4);
        let fif0 = build_dcs_fif(SelectedModem::V27Ter2400, false);
        assert_eq!((fif0[1] >> 2) & 0x0F, 0);
    }

    #[test]
    fn callee_flow_dis_and_dcs() {
        let mut c = callee();
        c.start_at(0);
        let units: Vec<TxUnit> = {
            let mut out = Vec::new();
            for t in (0..=4000u64).step_by(50) {
                while let Some(u) = c.pop_tx(t) {
                    out.push(u);
                    if out.len() > 40 {
                        break;
                    }
                }
            }
            out
        };
        assert!(
            units
                .iter()
                .any(|u| matches!(u.action, TxAction::Indicator(T30Indicator::Ced)))
        );
        let dis_unit = units
            .iter()
            .find(|u| matches!(u.action, TxAction::HdlcFrame(_)))
            .expect("DIS frame queued");
        let frame = match &dis_unit.action {
            TxAction::HdlcFrame(b) => HdlcFrame::parse(b).unwrap(),
            _ => unreachable!(),
        };
        assert_eq!(frame.frame_type(), HdlcFrameType::Dis);

        let mut x = caller();
        x.start_at(0);
        x.on_frame(HdlcFrame::parse(&frame.to_bytes()).unwrap());
        assert_eq!(x.state, T30State::SendingDcs);
        assert!(x.remote_modem.is_some());

        let dcs_bytes = {
            let mut found = None;
            for t in (0..=4000u64).step_by(50) {
                while let Some(u) = x.pop_tx(t) {
                    if let TxAction::HdlcFrame(b) = &u.action {
                        let f = HdlcFrame::parse(b).unwrap();
                        if f.frame_type() == HdlcFrameType::Dcs {
                            found = Some(b.clone());
                        }
                    }
                }
                if found.is_some() {
                    break;
                }
            }
            found.expect("DCS frame in tx queue")
        };

        let mut y = callee();
        y.start_at(0);
        y.tick(100);
        y.on_data(T30_DATA_V21, FIELD_HDLC_FCS_OK, &dcs_bytes);
        assert_eq!(y.state, T30State::WaitingTraining);
        assert_eq!(y.remote_modem, Some(SelectedModem::V27Ter4800));
    }

    #[test]
    fn tcf_detection_and_cfr() {
        let mut c = callee();
        c.start_at(0);
        let dcs = HdlcFrame::with_fif(
            HdlcFrameType::Dcs,
            true,
            build_dcs_fif(SelectedModem::V27Ter4800, false),
        )
        .to_bytes();
        c.on_data(T30_DATA_V21, FIELD_HDLC_FCS_OK, &dcs);
        assert_eq!(c.state, T30State::WaitingTraining);

        let zeros = vec![0u8; NON_ECM_CHUNK];
        for _ in 0..(TCF_ZERO_BYTES / zeros.len()) {
            c.on_data(T30_DATA_V27TER_4800, FIELD_T4_NON_ECM, &zeros);
        }
        c.on_data(T30_DATA_V27TER_4800, FIELD_T4_NON_ECM_SIG_END, &zeros);
        assert_eq!(c.state, T30State::WaitingPage);
        assert!(c.events.iter().any(|e| matches!(e, T30Event::TrainingOk)));
    }

    #[test]
    fn page_reception_and_eop() {
        let mut c = callee();
        c.start_at(0);
        let dcs = HdlcFrame::with_fif(
            HdlcFrameType::Dcs,
            true,
            build_dcs_fif(SelectedModem::V27Ter4800, false),
        )
        .to_bytes();
        c.on_data(T30_DATA_V21, FIELD_HDLC_FCS_OK, &dcs);
        c.on_indicator(T30Indicator::V27Ter4800Preamble);
        let zeros = vec![0u8; NON_ECM_CHUNK];
        for _ in 0..(TCF_ZERO_BYTES / zeros.len()) {
            c.on_data(T30_DATA_V27TER_4800, FIELD_T4_NON_ECM, &zeros);
        }
        c.on_data(T30_DATA_V27TER_4800, FIELD_T4_NON_ECM_SIG_END, &zeros);
        assert_eq!(c.state, T30State::WaitingPage);
        let page = vec![0xABu8; 100];
        c.on_data(T30_DATA_V27TER_4800, FIELD_T4_NON_ECM, &page);
        c.on_data(T30_DATA_V27TER_4800, FIELD_T4_NON_ECM_SIG_END, &[]);
        assert_eq!(c.page_number, 1);
        assert!(
            c.events
                .iter()
                .any(|e| matches!(e, T30Event::PageReceived { page: 1, size: 100 }))
        );

        c.on_data(T30_DATA_V21, FIELD_HDLC_FCS_OK, &[0xFF, 0xC8, 0xF4]);
        assert_eq!(c.state, T30State::WaitingDcn);
        assert!(c.pending_tx());

        c.on_data(T30_DATA_V21, FIELD_HDLC_FCS_OK, &[0xFF, 0xC8, 0xDF]);
        assert_eq!(c.state, T30State::Complete);
    }

    #[test]
    fn caller_full_flow() {
        let mut x = caller();
        x.set_tx_page(vec![0x5A; 200]);
        x.start_at(0);

        x.on_data(
            T30_DATA_V21,
            FIELD_HDLC_FCS_OK,
            &HdlcFrame::with_fif(HdlcFrameType::Dis, false, build_dis_fif(true, false)).to_bytes(),
        );
        assert_eq!(x.state, T30State::SendingDcs);

        let mut got_tcf_end = false;
        let mut t_final = 0u64;
        for t in (0..=6000u64).step_by(50) {
            while let Some(u) = x.pop_tx(t) {
                t_final = t;
                if let TxAction::NonEcmSigEnd(d) = u.action {
                    assert!(!d.is_empty() || TCF_ZERO_BYTES % NON_ECM_CHUNK == 0);
                    got_tcf_end = true;
                }
            }
            if got_tcf_end {
                break;
            }
        }
        assert!(got_tcf_end, "TCF chunks queued");

        x.tick(t_final);
        x.on_data(
            T30_DATA_V21,
            FIELD_HDLC_FCS_OK,
            &HdlcFrame::simple(HdlcFrameType::Cfr, false).to_bytes(),
        );
        assert_eq!(x.state, T30State::SendingPage);

        let mut page_bytes = 0usize;
        let mut sig_end = false;
        for t in (x.now..=(x.now + 6000)).step_by(50) {
            while let Some(u) = x.pop_tx(t) {
                match u.action {
                    TxAction::NonEcmChunk(d) => page_bytes += d.len(),
                    TxAction::NonEcmSigEnd(d) => {
                        page_bytes += d.len();
                        sig_end = true;
                    }
                    _ => {}
                }
            }
        }
        assert!(sig_end);
        assert_eq!(page_bytes, 200);

        x.on_data(
            T30_DATA_V21,
            FIELD_HDLC_FCS_OK,
            &HdlcFrame::simple(HdlcFrameType::Mcf, false).to_bytes(),
        );
        assert_eq!(x.state, T30State::WaitingDcn);
        assert!(
            x.events
                .iter()
                .any(|e| matches!(e, T30Event::PageTransferred { page: 1, size: 200 }))
        );
    }

    #[test]
    fn t1_timeout_fails_caller() {
        let mut x = caller();
        x.start_at(0);
        x.tick(T1_MAX_MS + 100);
        assert_eq!(x.state, T30State::Failed);
    }

    #[test]
    fn tx_units_respect_send_at() {
        let mut x = caller();
        x.start_at(1000);
        match x.pop_tx(1000) {
            Some(u) => assert!(u.send_at <= 1000),
            None => panic!("first unit should be ready"),
        }
        assert!(
            x.pop_tx(1000).is_none() || {
                let u = x.pop_tx(1000).unwrap();
                u.send_at > 1000
            }
        );
    }
}
