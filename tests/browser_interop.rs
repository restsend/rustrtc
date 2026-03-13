use std::ffi::OsStr;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use headless_chrome::{Browser, LaunchOptionsBuilder, Tab};
use rustrtc::config::{ApplicationCapability, MediaCapabilities};
use rustrtc::transports::datachannel::{DataChannel, DataChannelEvent};
use rustrtc::{
    AudioCapability, MediaSection, PeerConnection, PeerConnectionEvent, RtcConfiguration,
    RtcConfigurationBuilder, SdpType, SessionDescription,
};
use serial_test::serial;
use tokio::time::timeout;

const BROWSER_TIMEOUT: Duration = Duration::from_secs(15);
const CHANNEL_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, serde::Deserialize)]
struct BrowserDescription {
    #[serde(rename = "type")]
    kind: String,
    sdp: String,
    #[serde(rename = "signalingState")]
    signaling_state: String,
}

#[derive(Debug, serde::Deserialize)]
struct BrowserPeerState {
    #[serde(rename = "signalingState")]
    signaling_state: String,
    #[serde(rename = "connectionState")]
    connection_state: String,
}

struct BrowserPeer {
    _browser: Browser,
    tab: Arc<Tab>,
}

impl BrowserPeer {
    fn launch() -> Result<Option<Self>> {
        let Some(path) = find_browser_binary() else {
            eprintln!("Skipping browser interop test: no Chrome/Chromium binary found");
            return Ok(None);
        };

        let options = LaunchOptionsBuilder::default()
            .path(Some(path))
            .port(Some(allocate_debug_port()?))
            .headless(true)
            .sandbox(false)
            .enable_gpu(false)
            .idle_browser_timeout(Duration::from_secs(120))
            .args(vec![
                OsStr::new("--disable-features=WebRtcHideLocalIpsWithMdns"),
                OsStr::new("--use-fake-ui-for-media-stream"),
                OsStr::new("--use-fake-device-for-media-stream"),
                OsStr::new("--no-first-run"),
                OsStr::new("--no-default-browser-check"),
            ])
            .build()
            .map_err(|err| anyhow!("failed to build Chrome launch options: {err}"))?;
        let browser = Browser::new(options).context("failed to launch Chrome")?;
        let tab = browser.new_tab().context("failed to create browser tab")?;
        tab.navigate_to("about:blank")
            .context("failed to open blank page")?;
        tab.wait_until_navigated()
            .context("failed to finish browser navigation")?;

        Ok(Some(Self {
            _browser: browser,
            tab,
        }))
    }

    fn setup_peer(&self, add_audio: bool, add_data_channel: bool) -> Result<()> {
        let audio_setup = if add_audio {
            "pc.addTransceiver('audio', { direction: 'sendrecv' });"
        } else {
            ""
        };
        let data_channel_setup = if add_data_channel {
            r#"
            const dc = pc.createDataChannel("browser-channel");
            state.dc = dc;
            dc.onmessage = (event) => state.messages.push(String(event.data));
            "#
        } else {
            ""
        };

        self.eval_json::<bool>(&format!(
            r#"(async () => {{
                const pc = new RTCPeerConnection();
                const state = {{
                    pc,
                    dc: null,
                    messages: [],
                }};
                pc.onconnectionstatechange = () => {{
                    state.lastConnectionState = pc.connectionState;
                }};
                pc.onsignalingstatechange = () => {{
                    state.lastSignalingState = pc.signalingState;
                }};
                {audio_setup}
                {data_channel_setup}
                window.__rustrtc = state;
                return true;
            }})()"#
        ))?;
        Ok(())
    }

    fn create_offer(&self) -> Result<SessionDescription> {
        let desc: BrowserDescription = self.eval_json(
            r#"(async () => {
                const pc = window.__rustrtc.pc;
                const offer = await pc.createOffer();
                await pc.setLocalDescription(offer);
                if (pc.iceGatheringState !== "complete") {
                    await new Promise((resolve) => {
                        const onState = () => {
                            if (pc.iceGatheringState === "complete") {
                                pc.removeEventListener("icegatheringstatechange", onState);
                                resolve();
                            }
                        };
                        pc.addEventListener("icegatheringstatechange", onState);
                        setTimeout(() => {
                            pc.removeEventListener("icegatheringstatechange", onState);
                            resolve();
                        }, 5000);
                    });
                }
                return {
                    type: pc.localDescription.type,
                    sdp: pc.localDescription.sdp,
                    signalingState: pc.signalingState,
                };
            })()"#,
        )?;
        if desc.kind != "offer" {
            bail!("expected browser offer, got {}", desc.kind);
        }
        assert_eq!(desc.signaling_state, "have-local-offer");
        SessionDescription::parse(SdpType::Offer, &desc.sdp)
            .context("failed to parse browser offer SDP")
    }

    fn set_remote_description(&self, desc: &SessionDescription) -> Result<BrowserPeerState> {
        let kind = sdp_type_string(desc.sdp_type);
        let sdp = desc.to_sdp_string();
        self.eval_json(&format!(
            r#"(async () => {{
                const pc = window.__rustrtc.pc;
                await pc.setRemoteDescription({{
                    type: {kind},
                    sdp: {sdp},
                }});
                return {{
                    signalingState: pc.signalingState,
                    connectionState: pc.connectionState,
                }};
            }})()"#,
            kind = serde_json::to_string(kind)?,
            sdp = serde_json::to_string(&sdp)?,
        ))
    }

    fn signaling_state(&self) -> Result<String> {
        self.eval_json(r#"(async () => window.__rustrtc.pc.signalingState)()"#)
    }

    fn wait_connected(&self) -> Result<()> {
        self.wait_for_js_condition(
            r#"(async () => ({
                connectionState: window.__rustrtc.pc.connectionState,
                signalingState: window.__rustrtc.pc.signalingState,
            }))()"#,
            |state: &BrowserPeerState| match state.connection_state.as_str() {
                "connected" => Ok(true),
                "failed" | "closed" => bail!(
                    "browser peer reached terminal state {}",
                    state.connection_state
                ),
                _ => Ok(false),
            },
        )
    }

    fn wait_data_channel_open(&self) -> Result<()> {
        self.wait_for_js_condition(
            r#"(async () => ({
                readyState: window.__rustrtc.dc ? window.__rustrtc.dc.readyState : null
            }))()"#,
            |value: &serde_json::Value| {
                let state = value
                    .get("readyState")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default();
                match state {
                    "open" => Ok(true),
                    "closing" | "closed" => bail!("browser data channel is {state}"),
                    _ => Ok(false),
                }
            },
        )
    }

    fn send_data_channel_text(&self, text: &str) -> Result<()> {
        self.eval_json::<bool>(&format!(
            r#"(async () => {{
                window.__rustrtc.dc.send({text});
                return true;
            }})()"#,
            text = serde_json::to_string(text)?,
        ))?;
        Ok(())
    }

    fn wait_for_message(&self, expected: &str) -> Result<()> {
        let expected = expected.to_string();
        self.wait_for_js_condition(
            r#"(async () => window.__rustrtc.messages)()"#,
            move |messages: &Vec<String>| Ok(messages.iter().any(|msg| msg == &expected)),
        )
    }

    fn close(&self) -> Result<()> {
        self.eval_json::<bool>(
            r#"(async () => {
                if (window.__rustrtc?.dc) {
                    window.__rustrtc.dc.close();
                }
                if (window.__rustrtc?.pc) {
                    window.__rustrtc.pc.close();
                }
                return true;
            })()"#,
        )?;
        Ok(())
    }

    fn eval_json<T: serde::de::DeserializeOwned>(&self, expression: &str) -> Result<T> {
        // The CDP evaluate API returns objects by reference, so stringify in-page and decode
        // in Rust to keep the helper stable for nested JS results like SDP payloads.
        let script = format!(
            r#"(async () => {{
                const value = await ({expression});
                return JSON.stringify(value);
            }})()"#
        );
        let remote = self
            .tab
            .evaluate(&script, true)
            .context("failed to evaluate browser script")?;
        let value = remote
            .value
            .context("browser script returned no serializable value")?;
        let json_text = value
            .as_str()
            .context("browser script did not return a JSON string")?;
        serde_json::from_str(json_text).context("failed to decode browser JSON result")
    }

    fn wait_for_js_condition<T, F>(&self, expression: &str, mut predicate: F) -> Result<()>
    where
        T: serde::de::DeserializeOwned,
        F: FnMut(&T) -> Result<bool>,
    {
        let started = std::time::Instant::now();
        loop {
            let value: T = self.eval_json(expression)?;
            if predicate(&value)? {
                return Ok(());
            }
            if started.elapsed() > BROWSER_TIMEOUT {
                bail!("timed out waiting for browser condition");
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

fn find_browser_binary() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("CHROME_BIN") {
        let path = PathBuf::from(path);
        if path.exists() {
            return Some(path);
        }
    }

    for candidate in [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        "/usr/bin/google-chrome",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/snap/bin/chromium",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    ] {
        let path = PathBuf::from(candidate);
        if path.exists() {
            return Some(path);
        }
    }

    find_on_path(["google-chrome", "chromium", "chromium-browser", "chrome"])
}

fn allocate_debug_port() -> Result<u16> {
    // Prefer an OS-assigned loopback port so grouped regression runs don't depend on
    // headless_chrome's built-in 8000-9000 scan window.
    let listener =
        TcpListener::bind(("127.0.0.1", 0)).context("failed to reserve Chrome debug port")?;
    let port = listener
        .local_addr()
        .context("failed to inspect Chrome debug port")?
        .port();
    drop(listener);
    Ok(port)
}

fn find_on_path<const N: usize>(names: [&str; N]) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        for name in names {
            let candidate = dir.join(name);
            if candidate.exists() {
                return Some(candidate);
            }
            #[cfg(windows)]
            {
                let candidate = dir.join(format!("{name}.exe"));
                if candidate.exists() {
                    return Some(candidate);
                }
            }
        }
    }
    None
}

fn sdp_type_string(sdp_type: SdpType) -> &'static str {
    match sdp_type {
        SdpType::Offer => "offer",
        SdpType::Pranswer => "pranswer",
        SdpType::Answer => "answer",
        SdpType::Rollback => "rollback",
    }
}

fn find_attr_values<'a>(section: &'a MediaSection, key: &str) -> Vec<&'a str> {
    section
        .attributes
        .iter()
        .filter(|attr| attr.key == key)
        .filter_map(|attr| attr.value.as_deref())
        .collect()
}

fn find_codec_payload_type(section: &MediaSection, codec_name: &str) -> Option<u8> {
    let codec_name = codec_name.to_ascii_lowercase();
    section
        .attributes
        .iter()
        .filter(|attr| attr.key == "rtpmap")
        .filter_map(|attr| attr.value.as_deref())
        .find_map(|value| {
            let (payload_type, codec) = value.split_once(' ')?;
            let codec = codec.to_ascii_lowercase();
            if codec.starts_with(&format!("{codec_name}/")) {
                payload_type.parse().ok()
            } else {
                None
            }
        })
}

async fn wait_for_incoming_data_channel(pc: &PeerConnection) -> Result<Arc<DataChannel>> {
    loop {
        let event = timeout(CHANNEL_TIMEOUT, pc.recv())
            .await
            .context("timed out waiting for incoming peer event")?
            .ok_or_else(|| anyhow!("peer connection event channel closed"))?;
        match event {
            PeerConnectionEvent::DataChannel(dc) => return Ok(dc),
            PeerConnectionEvent::Track(_) => {}
        }
    }
}

async fn wait_for_rust_data_channel_open(dc: &Arc<DataChannel>) -> Result<()> {
    loop {
        let event = timeout(CHANNEL_TIMEOUT, dc.recv())
            .await
            .context("timed out waiting for Rust data channel event")?
            .ok_or_else(|| anyhow!("Rust data channel event channel closed"))?;
        match event {
            DataChannelEvent::Open => return Ok(()),
            DataChannelEvent::Close => bail!("Rust data channel closed before opening"),
            DataChannelEvent::Message(_) => {}
        }
    }
}

async fn wait_for_rust_data_channel_message(dc: &Arc<DataChannel>, expected: &str) -> Result<()> {
    loop {
        let event = timeout(CHANNEL_TIMEOUT, dc.recv())
            .await
            .context("timed out waiting for Rust data channel message")?
            .ok_or_else(|| anyhow!("Rust data channel event channel closed"))?;
        match event {
            DataChannelEvent::Message(data) => {
                let text = String::from_utf8(data.to_vec())
                    .context("Rust data channel received non-UTF8 payload")?;
                if text == expected {
                    return Ok(());
                }
            }
            DataChannelEvent::Close => bail!("Rust data channel closed before message arrived"),
            DataChannelEvent::Open => {}
        }
    }
}

fn init_browser_test_runtime() {
    rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider()).ok();
    let _ = env_logger::builder().is_test(true).try_init();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn browser_pranswer_then_answer_connects() -> Result<()> {
    init_browser_test_runtime();
    let Some(browser) = BrowserPeer::launch()? else {
        return Ok(());
    };
    browser.setup_peer(true, false)?;

    let offer = browser.create_offer()?;
    let pc = PeerConnection::new(RtcConfiguration::default());
    pc.set_remote_description(offer).await?;

    let mut pranswer = pc.create_answer().await?;
    pranswer.sdp_type = SdpType::Pranswer;
    pc.set_local_description(pranswer)?;
    pc.wait_for_gathering_complete().await;
    let pranswer = pc
        .local_description()
        .context("missing local pranswer after gathering")?;

    let browser_state = browser.set_remote_description(&pranswer)?;
    assert_eq!(browser_state.signaling_state, "have-remote-pranswer");
    assert_eq!(browser.signaling_state()?, "have-remote-pranswer");

    let answer = pc.create_answer().await?;
    pc.set_local_description(answer)?;
    let answer = pc
        .local_description()
        .context("missing final local answer")?;

    let browser_state = browser.set_remote_description(&answer)?;
    assert_eq!(browser_state.signaling_state, "stable");

    pc.wait_for_connected().await?;
    browser
        .wait_connected()
        .context("waiting for browser peer to reach connected")?;

    browser.close()?;
    pc.close();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn browser_offer_preserves_opus_fmtp_in_answer() -> Result<()> {
    init_browser_test_runtime();
    let Some(browser) = BrowserPeer::launch()? else {
        return Ok(());
    };
    browser.setup_peer(true, false)?;

    let offer = browser.create_offer()?;
    let opus_payload_type = find_codec_payload_type(&offer.media_sections[0], "opus")
        .context("browser offer did not advertise opus")?;

    let config = RtcConfigurationBuilder::new()
        .media_capabilities(MediaCapabilities {
            audio: vec![AudioCapability::opus()],
            video: vec![],
            application: Some(ApplicationCapability::default()),
        })
        .build();
    let pc = PeerConnection::new(config);
    pc.set_remote_description(offer).await?;

    let answer = pc.create_answer().await?;
    pc.set_local_description(answer)?;
    pc.wait_for_gathering_complete().await;
    let answer = pc
        .local_description()
        .context("missing local answer after gathering")?;

    let fmtp_values = find_attr_values(&answer.media_sections[0], "fmtp");
    let expected_fmtp = format!("{opus_payload_type} minptime=10;useinbandfec=1");
    assert!(fmtp_values.iter().any(|value| *value == expected_fmtp));
    assert_eq!(
        pc.get_transceivers()[0].get_payload_map()[&opus_payload_type]
            .fmtp
            .as_deref(),
        Some("minptime=10;useinbandfec=1")
    );

    let browser_state = browser.set_remote_description(&answer)?;
    assert_eq!(browser_state.signaling_state, "stable");

    browser.close()?;
    pc.close();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn browser_datachannel_message_roundtrip() -> Result<()> {
    init_browser_test_runtime();
    let Some(browser) = BrowserPeer::launch()? else {
        return Ok(());
    };
    browser.setup_peer(false, true)?;

    let offer = browser.create_offer()?;
    let pc = PeerConnection::new(RtcConfiguration::default());
    pc.set_remote_description(offer).await?;

    let answer = pc.create_answer().await?;
    pc.set_local_description(answer)?;
    pc.wait_for_gathering_complete().await;
    let answer = pc
        .local_description()
        .context("missing local answer after gathering")?;
    browser.set_remote_description(&answer)?;

    pc.wait_for_connected().await?;
    browser
        .wait_connected()
        .context("waiting for browser peer to reach connected")?;

    let data_channel = wait_for_incoming_data_channel(&pc).await?;
    wait_for_rust_data_channel_open(&data_channel).await?;
    browser
        .wait_data_channel_open()
        .context("waiting for browser data channel to open")?;

    pc.send_text(data_channel.id, "hello from rust").await?;
    browser
        .wait_for_message("hello from rust")
        .context("waiting for browser to receive Rust data channel message")?;

    browser.send_data_channel_text("hello from chrome")?;
    wait_for_rust_data_channel_message(&data_channel, "hello from chrome").await?;

    browser.close()?;
    pc.close();
    Ok(())
}
