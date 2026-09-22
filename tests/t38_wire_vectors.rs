#![cfg(feature = "t38")]

use bytes::Bytes;
use rustrtc::t38::wire::{
    T38CoreRx, WireDataField, WireRxEvent, encode_wire_data, encode_wire_indicator,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    #[allow(dead_code)]
    generated_by: String,
    scenarios: Vec<Scenario>,
}

#[derive(Deserialize)]
struct Scenario {
    name: String,
    version: u8,
    ops: Vec<Op>,
    results: Vec<OpResult>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Op {
    TxIndicator {
        indicator: i32,
    },
    TxData {
        data_type: i32,
        fields: Vec<FixtureField>,
    },
    RxPacket {
        hex: String,
        seq: u16,
    },
}

#[derive(Deserialize)]
struct FixtureField {
    field_type: i32,
    len: usize,
    pattern: u8,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum OpResult {
    Tx { hex: Option<String> },
    Rx { ret: i32, events: Vec<FixtureEvent> },
}

#[derive(Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum FixtureEvent {
    Indicator {
        indicator: i32,
    },
    Data {
        data_type: i32,
        field_type: i32,
        hex: String,
    },
    Missing {
        expected: i32,
        actual: i32,
    },
}

impl FixtureEvent {
    fn into_event(self) -> WireRxEvent {
        match self {
            FixtureEvent::Indicator { indicator } => WireRxEvent::Indicator(indicator),
            FixtureEvent::Data {
                data_type,
                field_type,
                hex,
            } => WireRxEvent::Data {
                data_type,
                field_type,
                payload: Bytes::from(from_hex(&hex)),
            },
            FixtureEvent::Missing { expected, actual } => WireRxEvent::Missing { expected, actual },
        }
    }
}

fn from_hex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn payload(spec: &FixtureField) -> Vec<u8> {
    vec![spec.pattern; spec.len]
}

fn replay_scenario(s: &Scenario) -> Result<(), String> {
    let mut rx_state: Option<T38CoreRx> = None;
    for (i, (op, expected)) in s.ops.iter().zip(&s.results).enumerate() {
        let ctx = || format!("{} [op {i}]", s.name);
        match (op, expected) {
            (Op::TxIndicator { indicator }, OpResult::Tx { hex }) => {
                let got = encode_wire_indicator(s.version, *indicator);
                match hex {
                    None => assert!(got.is_none(), "{}: expected rejection", ctx()),
                    Some(hex) => assert_eq!(
                        got.as_deref(),
                        Some(from_hex(hex).as_slice()),
                        "{}: byte mismatch",
                        ctx()
                    ),
                }
            }
            (Op::TxData { data_type, fields }, OpResult::Tx { hex }) => {
                let wire_fields: Vec<_> = fields
                    .iter()
                    .map(|f| WireDataField::new(f.field_type, payload(f)))
                    .collect();
                let got = encode_wire_data(s.version, *data_type, &wire_fields);
                match hex {
                    None => assert!(got.is_none(), "{}: expected rejection", ctx()),
                    Some(hex) => assert_eq!(
                        got.as_deref(),
                        Some(from_hex(hex).as_slice()),
                        "{}: byte mismatch",
                        ctx()
                    ),
                }
            }
            (Op::RxPacket { hex, seq }, OpResult::Rx { ret, events }) => {
                let state = rx_state.get_or_insert_with(|| T38CoreRx::new(s.version));
                let got = state.feed(*seq, &from_hex(hex));
                if *ret < 0 {
                    assert!(got.is_err(), "{}: expected Err, got {:?}", ctx(), got);
                } else {
                    let want: Vec<WireRxEvent> =
                        events.clone().into_iter().map(|e| e.into_event()).collect();
                    assert_eq!(got.as_ref(), Ok(&want), "{}: event mismatch", ctx());
                }
            }
            _ => unreachable!("op/result kind mismatch in fixture"),
        }
    }
    Ok(())
}

#[test]
fn wire_codec_matches_reference_bit_exact() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/t38_wire_vectors.json"
    );
    let raw = std::fs::read_to_string(path).expect("fixture missing");
    let fixture: Fixture = serde_json::from_str(&raw).expect("fixture parse");

    let mut failures = Vec::new();
    for scenario in &fixture.scenarios {
        if let Err(e) = replay_scenario(scenario) {
            failures.push(e);
        }
    }

    assert!(
        failures.is_empty(),
        "{}/{} scenarios diverged from reference:\n{}",
        failures.len(),
        fixture.scenarios.len(),
        failures.join("\n")
    );
}
