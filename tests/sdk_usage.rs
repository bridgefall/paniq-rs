//! Integration test for direct SDK usage.

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use paniq::client::PaniqClient;
use paniq::kcp::client::ClientConfigWrapper;
use paniq::profile::Profile;
use paniq::runtime::{ProxyConfig, ProxyHandle};

#[tokio::test]
async fn sdk_direct_usage_roundtrip() {
    // 1. Setup - Start a proxy server using the test runtime
    let profile = Profile::test_profile();
    // Configure a simple, predictable obfuscation for the test
    let proxy_config = ProxyConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        profile: profile.clone(),
    };
    let proxy = ProxyHandle::spawn(proxy_config)
        .await
        .expect("Failed to spawn proxy");
    let server_addr = proxy.addr;

    // 2. Client Setup - Use PaniqClient directly
    let obf_config = profile.obf_config();
    let client_config = ClientConfigWrapper {
        max_packet_size: profile.effective_kcp_max_packet_size(),
        max_payload: profile.effective_kcp_max_payload(),
        ..Default::default()
    };

    let client = PaniqClient::new(server_addr, obf_config, client_config);

    // 3. Open Stream & Verify
    // Since we are talking to proxy-server, it expects the proxy protocol handshake.
    // However, for this SDK test, we just want to see if we can open a stream
    // and if it reacts (even if it rejects the version).

    let mut stream = client.open_stream().await.expect("Failed to open stream");

    // Write something that isn't a valid version to see if proxy reacts
    stream
        .write_all(&[0xFF])
        .await
        .expect("Failed to write to stream");

    // Proxy should close the stream or return an error because 0xFF is not a valid version.
    // In our case, handle_stream returns Error and the task ends, which closes KCP stream.

    let mut buf = [0u8; 10];
    let read_result = timeout(Duration::from_secs(2), stream.read(&mut buf)).await;

    // We expect either 0 bytes (EOF) or an error, but not a timeout hang.
    match read_result {
        Ok(Ok(0)) => {
            // Success: EOF received as expected after invalid handshake
        }
        Ok(Ok(n)) => {
            tracing::info!("Read {} bytes: {:?}", n, &buf[..n]);
        }
        Ok(Err(e)) => {
            tracing::info!("Read error as expected: {}", e);
        }
        Err(_) => {
            panic!("SDK stream read timed out - potential hang in session management");
        }
    }

    proxy.shutdown();
}

#[tokio::test]
async fn sdk_client_reconnection() {
    let profile = Profile::test_profile();
    let proxy_config = ProxyConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        profile: profile.clone(),
    };

    let proxy = ProxyHandle::spawn(proxy_config.clone())
        .await
        .expect("Failed to spawn proxy");
    let server_addr = proxy.addr;

    let client = PaniqClient::new(
        server_addr,
        profile.obf_config(),
        ClientConfigWrapper::default(),
    );

    // 1. First stream
    {
        let _stream = client
            .open_stream()
            .await
            .expect("Failed to open first stream");
    }

    // 2. Kill proxy
    client.close().await;
    proxy.shutdown();
    proxy
        .wait()
        .await
        .expect("Failed to wait for proxy shutdown");
    tokio::time::sleep(Duration::from_millis(500)).await;

    // 3. Restart proxy on SAME port
    let mut restart_config = proxy_config.clone();
    restart_config.listen_addr = server_addr;

    let mut proxy = None;
    for _ in 0..5 {
        match ProxyHandle::spawn(restart_config.clone()).await {
            Ok(p) => {
                proxy = Some(p);
                break;
            }
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
    let proxy = proxy.expect("Failed to restart proxy after retries");
    assert_eq!(proxy.addr, server_addr);

    // 4. Second stream - should trigger reconnection
    let stream_result = timeout(Duration::from_secs(5), client.open_stream()).await;
    match stream_result {
        Ok(Ok(_)) => {
            // Success: Reconnected and opened stream
        }
        Ok(Err(e)) => {
            panic!("Failed to open second stream after proxy restart: {}", e);
        }
        Err(_) => {
            panic!("Timed out opening second stream after proxy restart");
        }
    }

    proxy.shutdown();
}
