use bytes::Bytes;
use clap::Parser;
use quinn::congestion::{BbrConfig, ControllerFactory, CubicConfig, NewRenoConfig};
use quinn::{ClientConfig, Endpoint, ServerConfig, TransportConfig};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::time::interval;

const BUFFER_SIZE: usize = 4 * 1024 * 1024; // 4MB

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Running mode: client or server
    #[arg(short, long)]
    mode: String,

    /// Listen or connect address (ip:port)
    #[arg(short, long)]
    addr: String,

    /// Test scenario: stream or dgram
    #[arg(short = 's', long)]
    scene: String,

    /// Packet size in bytes
    #[arg(short = 'p', long)]
    packet_size: usize,

    /// CA certificate path (client mode)
    #[arg(long, default_value = "./ca.crt")]
    ca: String,

    /// Server certificate path
    #[arg(long, default_value = "./server.crt")]
    cert: String,

    /// Server private key path
    #[arg(long, default_value = "./server.key")]
    key: String,

    /// QUIC congestion control algorithm (cubic, bbr, newreno)
    #[arg(long = "cc", default_value = "cubic", value_parser = ["cubic", "bbr", "newreno"])]
    pub congestion_algorithm: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    println!("=== Command Line Arguments ===");
    println!("Mode: {}", args.mode);
    println!("Addr: {}", args.addr);
    println!("Scene: {}", args.scene);
    println!("Packet Size: {}", args.packet_size);
    println!("CA: {:?}", args.ca);
    println!("Cert: {:?}", args.cert);
    println!("Key: {:?}", args.key);
    println!("============================");

    // 根据模式和场景调用对应的逻辑
    match args.mode.as_str() {
        "server" => {
            if args.scene.as_str() == "dgram" {
                run_dgram_server(args).await?;
            } else {
                return Err(format!("Unsupported scene for server: {}", args.scene).into());
            }
        }
        "client" => {
            if args.scene.as_str() == "dgram" {
                run_dgram_client(args).await?;
            } else {
                return Err(format!("Unsupported scene for client: {}", args.scene).into());
            }
        }
        _ => {
            return Err(format!("Unsupported mode: {}", args.mode).into());
        }
    }

    Ok(())
}

/// Create congestion controller factory based on algorithm name
fn create_congestion_controller(algorithm: &str) -> Arc<dyn ControllerFactory + Send + Sync> {
    match algorithm {
        "bbr" => Arc::new(BbrConfig::default()) as Arc<dyn ControllerFactory + Send + Sync>,
        "newreno" => Arc::new(NewRenoConfig::default()) as Arc<dyn ControllerFactory + Send + Sync>,
        _ => Arc::new(CubicConfig::default()) as Arc<dyn ControllerFactory + Send + Sync>,
    }
}

/// Create transport config with specified congestion control algorithm
fn create_transport_config(congestion_algorithm: &str) -> TransportConfig {
    let mut config = TransportConfig::default();
    let congestion_controller = create_congestion_controller(congestion_algorithm);
    config.congestion_controller_factory(congestion_controller);
    config.max_idle_timeout(None);
    config
}

/// Load server configuration from certificate files with congestion control
fn load_server_config(
    cert_path: &str,
    key_path: &str,
    congestion_algorithm: &str,
) -> Result<quinn::ServerConfig, Box<dyn std::error::Error>> {
    // 从文件加载服务器配置
    let cert = CertificateDer::from_pem_file(cert_path)?;
    let key = PrivatePkcs8KeyDer::from_pem_file(key_path)?;

    let mut server_config = ServerConfig::with_single_cert(vec![cert], key.into())?;

    // 设置传输配置包括拥塞控制算法
    let mut transport_config = create_transport_config(congestion_algorithm);
    transport_config
        .initial_mtu(1500)
        .datagram_receive_buffer_size(Some(65536))
        .datagram_send_buffer_size(65536);
    server_config.transport_config(Arc::new(transport_config));

    Ok(server_config)
}

/// Load client configuration with certificate verification enabled and congestion control
fn load_client_config(
    ca_cert_path: &str,
    congestion_algorithm: &str,
) -> Result<quinn::ClientConfig, Box<dyn std::error::Error>> {
    // 加载 CA 证书文件用于验证服务端
    let cert = CertificateDer::from_pem_file(ca_cert_path)?;
    let mut certs = rustls::RootCertStore::empty();
    certs.add(cert)?;

    let mut client_config = ClientConfig::with_root_certificates(Arc::new(certs))?;

    // 设置传输配置包括拥塞控制算法
    let mut transport_config = create_transport_config(congestion_algorithm);
    transport_config
        .initial_mtu(1500)
        .datagram_receive_buffer_size(Some(65536))
        .datagram_send_buffer_size(65536);
    client_config.transport_config(Arc::new(transport_config));

    Ok(client_config)
}

/// Run dgram server: receive packets and discard them
async fn run_dgram_server(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting dgram server on {}...", args.addr);

    let cert_path = args.cert;
    let key_path = args.key;

    let server_config = load_server_config(&cert_path, &key_path, &args.congestion_algorithm)?;

    // 使用 socket2 创建 UDP socket 并设置缓冲区大小
    let addr: SocketAddr = args.addr.parse().unwrap();
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_recv_buffer_size(BUFFER_SIZE).map_err(|e| {
        eprintln!("Failed to set receive buffer size: {}", e);
        e
    })?;
    socket.set_send_buffer_size(BUFFER_SIZE).map_err(|e| {
        eprintln!("Failed to set send buffer size: {}", e);
        e
    })?;
    socket.bind(&addr.into())?;

    let std_socket = std::net::UdpSocket::from(socket);
    let endpoint = Endpoint::new(
        Default::default(),
        Some(server_config),
        std_socket,
        Arc::new(quinn::TokioRuntime),
    )?;

    let total_bytes = Arc::new(AtomicU64::new(0));

    // 统计任务：每秒输出统计信息
    let total_bytes_clone = total_bytes.clone();
    tokio::spawn(async move {
        let mut last_bytes = 0u64;
        let mut ticker = interval(Duration::from_secs(1));

        loop {
            ticker.tick().await;
            let current_bytes = total_bytes_clone.load(Ordering::Relaxed);
            let delta_bytes = current_bytes - last_bytes;
            let bandwidth_bps = delta_bytes; // bytes per second

            let total_mb = current_bytes as f64 / 1024.0 / 1024.0;
            let bandwidth_mbps = bandwidth_bps as f64 * 8.0 / 1000.0 / 1000.0;

            println!(
                "[STATS] Total received: {:.2} MB, Last second bandwidth: {:.2} Mbps",
                total_mb, bandwidth_mbps
            );
            last_bytes = current_bytes;
        }
    });

    // 接收连接
    while let Some(conn) = endpoint.accept().await {
        let conn = conn.await?;
        let total_bytes_clone = total_bytes.clone();

        println!("New connection from: {}", conn.remote_address());

        // 为每个连接启动接收任务
        tokio::spawn(async move {
            loop {
                match conn.read_datagram().await {
                    Ok(datagram) => {
                        let bytes = datagram.len() as u64;
                        total_bytes_clone.fetch_add(bytes, Ordering::Relaxed);
                    }
                    Err(e) => {
                        eprintln!("Error receiving datagram: {}", e);
                        break;
                    }
                }
            }
        });
    }

    Ok(())
}

/// Run dgram client: send packets like crazy
async fn run_dgram_client(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting dgram client connecting to {}...", args.addr);

    let ca_path = args.ca;
    let client_config = load_client_config(&ca_path, &args.congestion_algorithm)?;

    // 使用 socket2 创建 UDP socket 并设置缓冲区大小
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_recv_buffer_size(BUFFER_SIZE).map_err(|e| {
        eprintln!("Failed to set receive buffer size: {}", e);
        e
    })?;
    socket.set_send_buffer_size(BUFFER_SIZE).map_err(|e| {
        eprintln!("Failed to set send buffer size: {}", e);
        e
    })?;
    socket.bind(&"0.0.0.0:0".parse::<SocketAddr>().unwrap().into())?;

    let std_socket = std::net::UdpSocket::from(socket);
    let endpoint = Endpoint::new(
        Default::default(),
        None,
        std_socket,
        Arc::new(quinn::TokioRuntime),
    )?;

    let addr: SocketAddr = args.addr.parse().unwrap();
    let connection = endpoint
        .connect_with(client_config, addr, "localhost")?
        .await?;
    println!("Connected to server: {}", connection.remote_address());

    // 创建测试数据包
    let packet_data = Bytes::copy_from_slice(&vec![0u8; args.packet_size]);

    println!("Sending packets of {} bytes each...", args.packet_size);

    // 疯狂发送数据包
    loop {
        match connection.send_datagram(packet_data.clone()) {
            Ok(_) => {}
            Err(e) => {
                // 发送失败，可能是缓冲区满，继续尝试
                eprintln!("Send error: {}", e);
            }
        }
    }
}
