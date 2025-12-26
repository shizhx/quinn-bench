use bytes::Bytes;
use clap::{Parser, ValueEnum};
use quinn::congestion::{BbrConfig, ControllerFactory, CubicConfig, NewRenoConfig};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{Endpoint, TransportConfig};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::time::interval;

const BUFFER_SIZE: usize = 4 * 1024 * 1024; // 4MB

#[derive(Copy, Clone, Debug, ValueEnum)]
enum Mode {
    #[value(name = "client")]
    Client,
    #[value(name = "server")]
    Server,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum Scene {
    #[value(name = "stream")]
    Stream,
    #[value(name = "dgram")]
    Dgram,
}

#[derive(Parser, Debug)]
#[command(name = "s2n-bench")]
#[command(about = "Network throughput testing tool", long_about = None)]
struct Args {
    /// Running mode: client or server
    #[arg(short, long)]
    mode: Mode,

    /// Listen or connect address (ip:port)
    #[arg(value_enum, short, long)]
    addr: String,

    /// Test scenario: stream or dgram
    #[arg(value_enum, short = 's', long)]
    scene: Scene,

    /// Packet size in bytes
    #[arg(short = 'p', long, default_value = "1350")]
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
    println!("Mode: {:?}", args.mode);
    println!("Addr: {}", args.addr);
    println!("Scene: {:?}", args.scene);
    println!("Packet Size: {}", args.packet_size);
    println!("CA: {:?}", args.ca);
    println!("Cert: {:?}", args.cert);
    println!("Key: {:?}", args.key);
    println!("Congestion Algorithm: {:?}", args.congestion_algorithm);
    println!("============================");

    // 根据模式和场景调用对应的逻辑
    match (args.mode, args.scene) {
        (Mode::Server, Scene::Dgram) => run_quic_server(args).await?,
        (Mode::Client, Scene::Dgram) => run_quic_client(args).await?,
        (Mode::Server, Scene::Stream) => run_quic_server(args).await?,
        (Mode::Client, Scene::Stream) => run_quic_client(args).await?,
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

    let provider = rustls::crypto::ring::default_provider();
    let mut server_config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key.into())
        .unwrap();

    server_config.alpn_protocols = vec![b"h3".to_vec()];

    let server_crypto = QuicServerConfig::try_from(server_config)?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));

    // 设置传输配置包括拥塞控制算法
    let mut transport_config = create_transport_config(congestion_algorithm);
    transport_config
        .initial_mtu(1500)
        .datagram_receive_buffer_size(Some(262144))
        .datagram_send_buffer_size(262144);
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

    // 创建 key logger（从 SSLKEYLOGFILE 环境变量读取）
    // 如果未设置环境变量，则不会记录密钥材料
    let key_log = Arc::new(rustls::KeyLogFile::new());

    // 检查并打印 key log 状态
    if std::env::var("SSLKEYLOGFILE").is_ok() {
        println!("Key logging enabled via SSLKEYLOGFILE environment variable");
    }

    // 设置密码学密钥提供器
    let provider = rustls::crypto::ring::default_provider();
    let verifier =
        WebPkiServerVerifier::builder_with_provider(Arc::new(certs), Arc::new(provider)).build()?;

    let provider = rustls::crypto::ring::default_provider();
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap() // The default providers support TLS 1.3
        .with_webpki_verifier(verifier)
        .with_no_client_auth();

    config.enable_early_data = true;
    config.key_log = key_log;
    config.alpn_protocols = vec![b"h3".to_vec()];

    let client_crypto = QuicClientConfig::try_from(config)?;

    // 创建 quinn ClientConfig
    let mut client_config = quinn::ClientConfig::new(Arc::new(client_crypto));

    // 设置传输配置包括拥塞控制算法
    let mut transport_config = create_transport_config(congestion_algorithm);
    transport_config
        .initial_mtu(1500)
        .datagram_receive_buffer_size(Some(262144))
        .datagram_send_buffer_size(262144);
    client_config.transport_config(Arc::new(transport_config));

    Ok(client_config)
}

/// 启动统计任务，定时打印吞吐量信息
async fn start_stats_task(
    bytes_counter: Arc<AtomicU64>,
    stats_type: &str,
) -> tokio::task::JoinHandle<()> {
    let stats_type = stats_type.to_string();
    tokio::spawn(async move {
        let mut interval = interval(Duration::from_secs(1));
        let mut last_bytes = 0u64;

        loop {
            interval.tick().await;
            let current_bytes = bytes_counter.load(Ordering::Relaxed);
            let bytes_per_sec = current_bytes - last_bytes;
            let total_mb = current_bytes as f64 / (1024.0 * 1024.0);
            let mb_per_sec = bytes_per_sec as f64 / (1000.0 * 1000.0) * 8.0;

            println!(
                "Total {}: {:.2} MB, Speed: {:.2} Mbps",
                stats_type, total_mb, mb_per_sec
            );
            last_bytes = current_bytes;
        }
    })
}

/// Run quic server: receive packets and discard them
async fn run_quic_server(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting QUIC server on {}...", args.addr);

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

    let bytes_received = Arc::new(AtomicU64::new(0));
    // 启动统计任务
    let _stats_handle = start_stats_task(Arc::clone(&bytes_received), "received").await;

    // 接收连接
    while let Some(conn) = endpoint.accept().await {
        let conn = conn.await?;
        let total_bytes_clone = bytes_received.clone();

        println!("New connection from: {}", conn.remote_address());

        // 为每个连接启动接收任务
        tokio::spawn(async move {
            match args.scene {
                Scene::Stream => {
                    let (_, mut recv_stream) = conn.accept_bi().await.unwrap();
                    println!("Accepted new stream: {}", recv_stream.id());
                    let mut buf = vec![0u8; args.packet_size];
                    loop {
                        match recv_stream.read(&mut buf).await {
                            Ok(size) => {
                                if let Some(bytes_received) = size {
                                    total_bytes_clone
                                        .fetch_add(bytes_received as u64, Ordering::Relaxed);
                                }
                            }
                            Err(e) => {
                                eprintln!("Error receiving stream: {}", e);
                                break;
                            }
                        }
                    }
                }
                Scene::Dgram => loop {
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
                },
            }
        });
    }

    Ok(())
}

/// Run quic client: send packets like crazy
async fn run_quic_client(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting QUIC client connecting to {}...", args.addr);

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
    let packet_data = vec![0u8; args.packet_size];
    let packet_bytes = Bytes::copy_from_slice(&vec![0u8; args.packet_size]);

    let bytes_sent = Arc::new(AtomicU64::new(0));
    // 启动统计任务
    let _stats_handle = start_stats_task(Arc::clone(&bytes_sent), "sent").await;

    println!("Sending packets of {} bytes each...", args.packet_size);

    // 疯狂发送数据包
    match args.scene {
        Scene::Stream => {
            // 打开流
            let (mut send_stream, _) = connection.open_bi().await.unwrap();
            println!("Opened stream: {}", send_stream.id());
            loop {
                match send_stream.write_all(&packet_data).await {
                    Ok(_) => {
                        bytes_sent.fetch_add(args.packet_size as u64, Ordering::Relaxed);
                    }
                    Err(e) => {
                        eprintln!("Failed to write stream: {:?}", e);
                    }
                }
            }
        }
        Scene::Dgram => {
            loop {
                match connection.send_datagram_wait(packet_bytes.clone()).await {
                    Ok(_) => {
                        bytes_sent.fetch_add(args.packet_size as u64, Ordering::Relaxed);
                    }
                    Err(e) => {
                        // 发送失败，可能是缓冲区满，继续尝试
                        eprintln!("Send error: {}", e);
                    }
                }
            }
        }
    }
}
