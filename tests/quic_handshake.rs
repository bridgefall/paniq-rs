#![cfg(feature = "quic")]

use std::net::UdpSocket;
use std::thread;

use paniq::envelope::client::{client_handshake, UdpPacketConn};
use paniq::envelope::replay::ReplayCache;
use paniq::envelope::server::ServerConn;
use paniq::obf::{Config, Framer, MessageType, SharedRng};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use std::time::Duration;

#[test]
fn udp_packet_conn_handshake_round_trip() {
    let cfg = Config {
        jc: 0,
        jmin: 0,
        jmax: 0,
        s1: 0,
        s2: 0,
        s3: 0,
        s4: 0,
        h1: "10".into(),
        h2: "20".into(),
        h3: "30".into(),
        h4: "40".into(),
        i1: "<b 0x01><d>".into(),
        i2: String::new(),
        i3: String::new(),
        i4: String::new(),
        i5: String::new(),
    };

    let rng = SharedRng::from_seed(9);
    let client_framer = Framer::new_with_rng(cfg.clone(), rng.clone()).unwrap();
    let server_framer = Framer::new_with_rng(cfg, rng.clone()).unwrap();

    let client_addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server_addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let client_sock = UdpSocket::bind(client_addr).unwrap();
    let server_sock = UdpSocket::bind(server_addr).unwrap();
    let client_addr = client_sock.local_addr().unwrap();
    let server_addr = server_sock.local_addr().unwrap();

    let mut client_conn =
        UdpPacketConn::new(client_sock.try_clone().unwrap(), server_addr).unwrap();
    let server_conn = UdpPacketConn::new(server_sock.try_clone().unwrap(), client_addr).unwrap();
    let mut server = ServerConn::new(
        server_conn,
        server_framer,
        ReplayCache::new(Duration::from_secs(60), 256),
        rng.clone(),
    );

    let server_thread = thread::spawn(move || {
        let result = server.handle_preamble().unwrap();
        server
            .send_response(MessageType::Response, b"ok")
            .unwrap();
        result
    });

    let mut rng = ChaCha8Rng::seed_from_u64(42);
    client_handshake(&mut client_conn, &client_framer, b"init", &mut rng).unwrap();

    let (msg, payload) = server_thread.join().unwrap();
    assert_eq!(msg, MessageType::Initiation);
    assert!(payload.starts_with(b"init"));
}
