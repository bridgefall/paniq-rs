#![cfg(feature = "kcp")]

use paniq::kcp::client::connect_after_handshake;
use paniq::kcp::server::listen_on_socket;
use paniq::obf::{Config, Framer, SharedRng};
use tokio::sync::oneshot;

fn base_config() -> Config {
    Config {
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
    }
}

fn make_framer(cfg: &Config, seed: u64) -> Framer {
    Framer::new_with_rng(cfg.clone(), SharedRng::from_seed(seed)).unwrap()
}

#[tokio::test]
async fn quic_round_trip_over_obfuscating_socket() {
    let cfg = base_config();
    let client_framer = make_framer(&cfg, 123);
    let server_config = ();
    let client_config = ();

    let client_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let server_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let server_addr = server_sock.local_addr().unwrap();

    let server_quic_framer = make_framer(&cfg, 456);
    let (ready_tx, ready_rx) = oneshot::channel();
    let server_task = tokio::spawn(async move {
        let server_ep = listen_on_socket(server_sock, server_quic_framer, server_config)
            .await
            .unwrap();
        let _ = ready_tx.send(());
        if let Some(incoming) = server_ep.accept().await {
            let connection = incoming.await.unwrap();
            let (mut send, mut recv) = connection.accept_bi().await.unwrap();
            let mut buf = vec![0u8; 64];
            let n = recv.read(&mut buf).await.unwrap().unwrap();
            send.write_all(&buf[..n]).await.unwrap();
            send.finish().await.unwrap();
        }
    });

    ready_rx.await.unwrap();

    let (endpoint, conn) = connect_after_handshake(
        client_sock,
        server_addr,
        client_framer,
        client_config,
        "localhost",
    )
    .await
    .unwrap();

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(b"hello-obf-quic").await.unwrap();
    send.finish().await.unwrap();

    let echoed = recv.read_to_end(usize::MAX).await.unwrap();
    assert_eq!(echoed, b"hello-obf-quic");

    conn.close(0u32.into(), b"done");
    server_task.await.unwrap();
    drop(conn);
    drop(endpoint);
}
