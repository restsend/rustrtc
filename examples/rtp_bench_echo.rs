use std::io::Result;
use std::net::UdpSocket;

fn main() -> Result<()> {
    let addr = "0.0.0.0:6000";
    let socket = UdpSocket::bind(addr)?;
    println!("RTP Echo Server listening on {}", addr);

    let mut buf = [0u8; 2048];
    loop {
        let (size, src) = socket.recv_from(&mut buf)?;
        socket.send_to(&buf[..size], src)?;
    }
}
