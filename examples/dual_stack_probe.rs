//! Probe: does a dual-stack `::` UDP socket (IPV6_V6ONLY=off, set pre-bind
//! via transports::bind_udp) receive packets sent from 127.0.0.1 to
//! 127.0.0.1:<port> on this platform?

#[cfg(feature = "std")]
#[tokio::main]
async fn main() {
    use std::sync::Arc;
    let sock = rustrtc::transports::bind_udp("[::]:0".parse().unwrap()).unwrap();
    let sock = Arc::new(sock);
    let port = sock.local_addr().unwrap().port();
    println!("dual-stack socket bound, port = {port}");

    // v4 sender: 127.0.0.1 -> 127.0.0.1:port
    let v4 = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let s = sock.clone();
    let rx = tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        let (n, from) = s.recv_from(&mut buf).await.unwrap();
        (n, from)
    });
    v4.send_to(b"v4-probe", format!("127.0.0.1:{port}")).await.unwrap();
    let rx = tokio::time::timeout(std::time::Duration::from_secs(2), rx).await;
    match rx {
        Ok(Ok((n, from))) => println!("v4 -> dual-stack: OK, {n} bytes from {from}"),
        _ => println!("v4 -> dual-stack: NO PACKET RECEIVED (timeout)"),
    }

    // v6 sender: ::1 -> [::1]:port
    let v6 = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
    let s = sock.clone();
    let rx = tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        let (n, from) = s.recv_from(&mut buf).await.unwrap();
        (n, from)
    });
    v6.send_to(b"v6-probe", format!("[::1]:{port}")).await.unwrap();
    let rx = tokio::time::timeout(std::time::Duration::from_secs(2), rx).await;
    match rx {
        Ok(Ok((n, from))) => println!("v6 -> dual-stack: OK, {n} bytes from {from}"),
        _ => println!("v6 -> dual-stack: NO PACKET RECEIVED (timeout)"),
    }

    // Cross-family reply: dual-stack socket -> 127.0.0.1 sender
    let (n, from) = match tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            let mut buf = [0u8; 1500];
            let (n, from) = sock.recv_from(&mut buf).await.unwrap();
            if &buf[..4] == b"v4-p" {
                sock.send_to(b"reply", from).await.unwrap();
                break (n, from);
            }
        }
    })
    .await
    {
        Ok(x) => x,
        _ => {
            println!("no v4 packet to reply to");
            return;
        }
    };
    let mut buf = [0u8; 64];
    let r = tokio::time::timeout(std::time::Duration::from_secs(2), v4.recv_from(&mut buf)).await;
    println!(
        "reply dual-stack -> 127.0.0.1 (from {from}, {n}B): {}",
        r.map(|o| format!("OK {:?}", o)).unwrap_or_else(|_| "NO REPLY".into())
    );
}
