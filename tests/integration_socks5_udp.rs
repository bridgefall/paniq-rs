//! Integration test for SOCKS5 UDP ASSOCIATE.
//!
//! Validates that UDP data can be transferred over SOCKS5 proxy,
//! which is essential for WebRTC calls.

#![cfg(feature = "socks5")]
#![cfg(feature = "kcp")]

mod support;

use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use support::StackHarness;

const TEST_PAYLOAD: &[u8] = b"hello udp world";

/// Simple UDP echo server
async fn start_udp_echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&buf[..n], peer).await;
        }
    });

    (addr, handle)
}

#[tokio::test]
async fn integration_socks5_udp_associate() {
    // Start UDP echo server
    let (echo_addr, echo_handle) = start_udp_echo_server().await;
    println!("UDP Echo server listening on: {}", echo_addr);

    // Spawn production proxy and SOCKS5 servers using the test harness
    let harness = StackHarness::spawn(
        "127.0.0.1:0".parse().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .await
    .expect("Failed to spawn test harness");

    let socks_addr = harness.socks_addr();
    println!("SOCKS5 server listening on: {}", socks_addr);

    // Connect as SOCKS5 client for the control connection
    let mut socks_conn = tokio::net::TcpStream::connect(socks_addr).await.unwrap();

    // SOCKS5 handshake
    socks_conn.write_all(&[0x05, 0x01, 0x02]).await.unwrap(); // ver, nmethods, userpass
    let mut resp = [0u8; 2];
    socks_conn.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [0x05, 0x02]);

    // Auth
    let mut auth_msg = vec![0x01];
    auth_msg.push(4u8);
    auth_msg.extend_from_slice(b"user");
    auth_msg.push(4u8);
    auth_msg.extend_from_slice(b"pass");
    socks_conn.write_all(&auth_msg).await.unwrap();
    socks_conn.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [0x01, 0x00]);

    // UDP ASSOCIATE request
    // Client sends the address it intends to use for UDP.
    let associate_req = vec![0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    socks_conn.write_all(&associate_req).await.unwrap();

    // Read reply
    let mut reply = [0u8; 10];
    socks_conn.read_exact(&mut reply).await.unwrap();

    if reply[1] != 0x00 {
        panic!(
            "UDP ASSOCIATE failed with error code 0x{:02x}. 0x07 is Command Not Supported.",
            reply[1]
        );
    }

    // The reply contains the BND.ADDR and BND.PORT which is the UDP relay address
    let mut bnd_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
        reply[4], reply[5], reply[6], reply[7],
    ));
    if bnd_ip.is_unspecified() {
        bnd_ip = socks_addr.ip();
    }
    let bnd_port = u16::from_be_bytes([reply[8], reply[9]]);
    let relay_addr = SocketAddr::new(bnd_ip, bnd_port);
    println!("SOCKS5 UDP relay address: {}", relay_addr);

    // Now send UDP data to the relay address
    let udp_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // Construct SOCKS5 UDP header
    let mut packet = vec![0x00, 0x00, 0x00]; // RSV, RSV, FRAG
    match echo_addr {
        SocketAddr::V4(v4) => {
            packet.push(0x01); // ATYP IPv4
            packet.extend_from_slice(&v4.ip().octets());
            packet.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            packet.push(0x04); // ATYP IPv6
            packet.extend_from_slice(&v6.ip().octets());
            packet.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    packet.extend_from_slice(TEST_PAYLOAD);

    println!("Sending UDP packet to relay...");
    udp_socket.send_to(&packet, relay_addr).await.unwrap();

    // Receive echo
    let mut recv_buf = [0u8; 4096];
    let (n, peer) = timeout(Duration::from_secs(5), udp_socket.recv_from(&mut recv_buf))
        .await
        .expect("Timeout waiting for UDP echo")
        .unwrap();

    println!("Received UDP packet from: {}", peer);
    assert_eq!(peer, relay_addr);

    // Check header and data
    // Header size for IPv4: 3 (RSV, FRAG) + 1 (ATYP) + 4 (IP) + 2 (Port) = 10
    assert!(n > 10, "Received packet too short: {}", n);
    assert_eq!(
        &recv_buf[n - TEST_PAYLOAD.len()..n],
        TEST_PAYLOAD,
        "Payload mismatch"
    );

    println!("UDP ASSOCIATE test passed!");

    // Cleanup
    echo_handle.abort();
}
