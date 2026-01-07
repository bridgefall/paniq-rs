use clap::{Parser, Subcommand};
use paniq::control::{ControlRequest, ControlResponse};
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    match args.command {
        Commands::Ping => {
            let response = send_command(args.socket, ControlRequest::Ping).await?;
            match response {
                ControlResponse::Pong => {
                    println!("Pong");
                }
                ControlResponse::Error(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
                _ => {
                    eprintln!("Unexpected response");
                    std::process::exit(1);
                }
            }
        }
        Commands::Stats => {
            let response = send_command(args.socket, ControlRequest::GetStats).await?;
            match response {
                ControlResponse::Stats(stats) => {
                    println!("{}", serde_json::to_string_pretty(&stats)?);
                }
                ControlResponse::Error(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
                _ => {
                    eprintln!("Unexpected response");
                    std::process::exit(1);
                }
            }
        }
    }

    Ok(())
}

async fn send_command(
    socket_path: PathBuf,
    request: ControlRequest,
) -> Result<ControlResponse, Box<dyn std::error::Error>> {
    let mut stream = UnixStream::connect(&socket_path).await?;
    let bytes = serde_json::to_vec(&request)?;
    stream.write_all(&bytes).await?;
    stream.shutdown().await?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    let response: ControlResponse = serde_json::from_slice(&buf)?;

    match &response {
        ControlResponse::Error(e) => Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Server error: {}", e),
        )) as Box<dyn std::error::Error>),
        _ => Ok(response),
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about = "Paniq control tool", long_about = None)]
struct Args {
    #[arg(short, long, help = "Path to control Unix domain socket")]
    socket: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    #[command(about = "Ping the daemon")]
    Ping,
    #[command(about = "Get daemon statistics")]
    Stats,
}
