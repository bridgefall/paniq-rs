use std::net::SocketAddr;
use std::path::PathBuf;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use paniq::kcp::server::listen_on_socket;
use paniq::profile::Profile;
use paniq::{kcp, obf::Framer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = parse_args()?;
    let profile = Profile::from_file(&args.profile)?;
    let framer = Framer::new(profile.obf_config())?;

    let udp_sock = std::net::UdpSocket::bind(&args.listen)?;
    let endpoint = listen_on_socket(udp_sock, framer, ()).await?;
    eprintln!("proxy-server listening on {}", endpoint.local_addr());

    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            if let Ok(conn) = incoming.await_connection().await {
                handle_connection(conn).await;
            }
        });
    }

    Ok(())
}

struct Args {
    listen: SocketAddr,
    profile: PathBuf,
}

fn parse_args() -> Result<Args, pico_args::Error> {
    let mut pargs = pico_args::Arguments::from_env();
    let listen = pargs.value_from_str(["-l", "--listen"])?;
    let profile: PathBuf = pargs.value_from_str(["-p", "--profile"])?;

    Ok(Args { listen, profile })
}

async fn handle_connection(conn: kcp::client::Connection) {
    loop {
        match conn.accept_bi().await {
            Ok((send, recv)) => {
                tokio::spawn(async move {
                    if let Err(err) = handle_stream(send, recv).await {
                        eprintln!("stream closed with error: {}", err);
                    }
                });
            }
            Err(err) => {
                eprintln!("connection closed: {}", err);
                break;
            }
        }
    }
}

async fn handle_stream(
    mut send: kcp::client::SendStream,
    mut recv: kcp::client::RecvStream,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let target = read_target(&mut recv).await?;
    let mut target = TcpStream::connect(&target).await?;
    target.set_nodelay(true)?;

    let (mut target_reader, mut target_writer) = target.split();

    let client_to_target = async {
        tokio::io::copy(&mut recv, &mut target_writer).await?;
        target_writer.shutdown().await?;
        Ok::<(), std::io::Error>(())
    };

    let target_to_client = async {
        tokio::io::copy(&mut target_reader, &mut send).await?;
        send.shutdown().await?;
        Ok::<(), std::io::Error>(())
    };

    let _ = tokio::try_join!(client_to_target, target_to_client)?;

    Ok(())
}

async fn read_target(
    recv: &mut kcp::client::RecvStream,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let mut header = [0u8; 2];
    recv.read_exact(&mut header).await?;
    let version = header[0];
    let addr_type = header[1];

    if version != 0x01 {
        return Err(format!("unsupported protocol version: {}", version).into());
    }

    let target = match addr_type {
        0x01 => {
            let mut buf = [0u8; 4];
            recv.read_exact(&mut buf).await?;
            let mut port_buf = [0u8; 2];
            recv.read_exact(&mut port_buf).await?;
            let ip = std::net::Ipv4Addr::from(buf);
            format!("{}:{}", ip, u16::from_be_bytes(port_buf))
        }
        0x04 => {
            let mut buf = [0u8; 16];
            recv.read_exact(&mut buf).await?;
            let mut port_buf = [0u8; 2];
            recv.read_exact(&mut port_buf).await?;
            let ip = std::net::Ipv6Addr::from(buf);
            format!("{}:{}", ip, u16::from_be_bytes(port_buf))
        }
        0x03 => {
            let mut len_buf = [0u8; 1];
            recv.read_exact(&mut len_buf).await?;
            let len = len_buf[0] as usize;
            let mut host = vec![0u8; len];
            recv.read_exact(&mut host).await?;
            let mut port_buf = [0u8; 2];
            recv.read_exact(&mut port_buf).await?;
            let host = String::from_utf8(host)?;
            format!("{}:{}", host, u16::from_be_bytes(port_buf))
        }
        other => return Err(format!("unsupported address type: {}", other).into()),
    };

    Ok(target)
}
