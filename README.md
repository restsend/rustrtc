# rustrtc

A pure Rust implementation of WebRTC. 

## Features

- **PeerConnection**: The main entry point for WebRTC connections.
- **Data Channels**: Support for reliable and unreliable data channels.
- **Media Support**: RTP/SRTP handling for audio and video.
- **ICE/STUN**: Interactive Connectivity Establishment and STUN protocol support.
- **DTLS**: Datagram Transport Layer Security for secure communication.
- **SDP**: Session Description Protocol parsing and generation.

## Usage

Here is a simple example of how to create a `PeerConnection` and handle an offer:

```rust
use rustrtc::{PeerConnection, RtcConfiguration, SessionDescription, SdpType};

#[tokio::main]
async fn main() {
    let config = RtcConfiguration::default();
    let pc = PeerConnection::new(config);

    // Create a Data Channel
    let dc = pc.create_data_channel("data").unwrap();

    // Handle received messages
    let dc_clone = dc.clone();
    tokio::spawn(async move {
        while let Some(event) = dc_clone.recv().await {
            if let rustrtc::transports::sctp::DataChannelEvent::Message(data) = event {
                println!("Received: {:?}", String::from_utf8_lossy(&data));
            }
        }
    });

    // ... Handle SDP offer/answer exchange ...
}
```

## Examples

You can run the examples provided in the repository.

### Echo Server

The echo server example demonstrates how to accept a WebRTC connection, receive data on a data channel, and echo it back. It also supports video playback if an IVF file is provided.

1. Run the server:
    ```bash
    cargo run --example echo_server
    ```

2. Open your browser and navigate to `http://127.0.0.1:3000`.

### RTP Example

The RTP example demonstrates how to create a PeerConnection, add an audio track, and send dummy audio frames.

1. Run the example:
    ```bash
    cargo run --example rtp_example
    ```

## License

This project is licensed under the MIT License.
