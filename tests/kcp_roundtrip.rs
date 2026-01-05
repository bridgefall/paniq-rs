#![cfg(feature = "kcp")]

use paniq::kcp::server::listen;
use paniq::kcp::KcpClient;
use paniq::obf::{Config, Framer, SharedRng};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
async fn kcp_round_trip_over_obfuscating_socket() {
    let cfg = base_config();
    let client_framer = make_framer(&cfg, 123);
    let server_framer = make_framer(&cfg, 456);

    let server_config = paniq::kcp::server::ServerConfigWrapper {
        max_packet_size: 1350,
        max_payload: 1200,
        transport_replay: false,
        idle_timeout_secs: 120,
        handshake_timeout_secs: 5,
        handshake_attempts: 3,
        preamble_delay_ms: 5,
    };

    let client_config = paniq::kcp::ClientConfig {
        max_packet_size: 1350,
        max_payload: 1200,
        transport_replay: false,
        padding_policy: paniq::envelope::padding::PaddingPolicy {
            enabled: false,
            min: 0,
            max: 0,
            burst_min: 0,
            burst_max: 0,
            burst_prob: 0.0,
        },
        handshake_timeout: std::time::Duration::from_secs(5),
        handshake_attempts: 3,
        preamble_delay: std::time::Duration::from_millis(5),
    };

    // Use a known port
    let known_addr: std::net::SocketAddr = "127.0.0.1:12987".parse().unwrap();

    // Start server
    let server_task = tokio::spawn(async move {
        let server_ep = listen(known_addr, server_framer, server_config)
            .await
            .unwrap();
        tracing::info!(listen_addr = %server_ep.local_addr(), "Server listening");
        if let Some(incoming) = server_ep.accept().await {
            tracing::info!("Server accepted connection");
            let mut connection = incoming.await_connection().await.unwrap();
            let (mut send, mut recv) = connection.accept_bi().await.unwrap();
            let mut buf = vec![0u8; 64];
            let n = recv.read(&mut buf).await.unwrap();
            tracing::debug!(bytes = n, data = ?&buf[..n], "Server read");
            send.write_all(&buf[..n]).await.unwrap();
            send.shutdown().await.unwrap();
            tracing::debug!("Server echoed data");
        }
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Connect client using KcpClient::connect (which creates its own socket)
    let client = KcpClient::connect(known_addr, client_framer, client_config)
        .await
        .unwrap();

    let stream = client.open_stream().await.unwrap();
    let (mut reader, mut writer) = tokio::io::split(stream);
    writer.write_all(b"hello-obf-kcp").await.unwrap();

    // Give time for data to transit through KCP/UDP
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    writer.shutdown().await.unwrap();

    let echoed = {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();
        buf
    };
    assert_eq!(echoed, b"hello-obf-kcp");

    // No close method on KcpClient currently
    server_task.await.unwrap();
}
