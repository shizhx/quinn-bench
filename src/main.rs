use bytes::Bytes;
use clap::{Parser, ValueEnum};
use log::{error, info};
use quinn::congestion::{BbrConfig, ControllerFactory, CubicConfig, NewRenoConfig};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{Endpoint, TransportConfig, VarInt};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{self, AsyncBufReadExt, BufReader};
use tokio::time::interval;
use tokio_util::sync::CancellationToken;

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
    congestion_algorithm: String,

    /// Parallel QUIC connection count
    #[arg(long = "conn", default_value = "1")]
    max_conn: usize,

    /// Parallel QUIC stream count
    #[arg(long = "stream", default_value = "1")]
    max_stream: usize,

    /// Download mode
    #[arg(short, long)]
    download: bool,

    /// Interactive wait some step
    #[arg(short, long)]
    interactive: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
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
    println!("Max connection: {:?}", args.max_conn);
    println!("Max stream: {:?}", args.max_stream);
    println!("Download: {:?}", args.download);
    println!("Interactive: {:?}", args.interactive);
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
    config
        .max_idle_timeout(None)
        .initial_mtu(1500)
        .receive_window(VarInt::from_u32(1024 * 1024 * 2))
        .stream_receive_window(VarInt::from_u32(1024 * 1024))
        .max_concurrent_bidi_streams(VarInt::from_u32(5000))
        .datagram_receive_buffer_size(Some(1024 * 1024))
        .datagram_send_buffer_size(1024 * 1024);
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
    let transport_config = create_transport_config(congestion_algorithm);
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
        info!("Key logging enabled via SSLKEYLOGFILE environment variable");
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
    let transport_config = create_transport_config(congestion_algorithm);
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
        let mut speed_history: VecDeque<f64> = VecDeque::new();

        loop {
            interval.tick().await;
            let current_bytes = bytes_counter.load(Ordering::Relaxed);
            let bytes_per_sec = current_bytes - last_bytes;
            let total_mb = current_bytes as f64 / (1024.0 * 1024.0);
            let mb_per_sec = bytes_per_sec as f64 / (1000.0 * 1000.0) * 8.0;

            // 将当前速度添加到历史记录中
            speed_history.push_back(mb_per_sec);
            // 保持最多10个记录（10秒的历史）
            if speed_history.len() > 10 {
                speed_history.pop_front();
            }

            // 计算最近1秒、5秒、10秒的平均速度
            let speed_1s = mb_per_sec; // 当前1秒的速度
            let speed_5s: f64 = speed_history.iter().rev().take(5).sum::<f64>()
                / (speed_history.len().min(5) as f64);
            let speed_10s: f64 = speed_history.iter().sum::<f64>() / (speed_history.len() as f64);

            info!(
                "Total {}: {:.2} MB, Speed (1s): {:.2} Mbps, Speed (5s): {:.2} Mbps, Speed (10s): {:.2} Mbps",
                stats_type, total_mb, speed_1s, speed_5s, speed_10s
            );
            last_bytes = current_bytes;
        }
    })
}

/// Run quic server: receive packets and discard them
async fn run_quic_server(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting QUIC server on {}...", args.addr);

    let cert_path = args.cert;
    let key_path = args.key;

    let server_config = load_server_config(&cert_path, &key_path, &args.congestion_algorithm)?;

    // 使用 socket2 创建 UDP socket 并设置缓冲区大小
    let addr: SocketAddr = args.addr.parse().unwrap();
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_recv_buffer_size(BUFFER_SIZE).map_err(|e| {
        error!("Failed to set receive buffer size: {}", e);
        e
    })?;
    socket.set_send_buffer_size(BUFFER_SIZE).map_err(|e| {
        error!("Failed to set send buffer size: {}", e);
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
    let stat_type = match args.download {
        true => "sent",
        false => "received",
    };
    // 启动统计任务
    let _stats_handle = start_stats_task(Arc::clone(&bytes_received), stat_type).await;

    // 待发送数据
    let packet_size = args.packet_size as u64;
    let packet = vec![0xABu8; args.packet_size];
    let packet = Bytes::copy_from_slice(&packet);

    // 接收连接
    while let Some(conn) = endpoint.accept().await {
        let conn = conn.await?;
        let total_bytes_clone = bytes_received.clone();

        info!("Accepted connection from {}", conn.remote_address());

        // 为每个连接启动接收任务
        let packet = packet.clone();
        tokio::spawn(async move {
            match args.scene {
                Scene::Stream => loop {
                    let (mut send_stream, mut recv_stream) = conn.accept_bi().await.unwrap();
                    info!(
                        "Accepted new stream from {}: {}",
                        conn.remote_address(),
                        recv_stream.id()
                    );
                    let total_bytes = total_bytes_clone.clone();
                    let packet = packet.clone();
                    if args.download {
                        tokio::spawn(async move {
                            loop {
                                match stream_write_all(&mut send_stream, &packet).await {
                                    Ok(_) => {
                                        total_bytes.fetch_add(packet_size, Ordering::Relaxed);
                                    }
                                    Err(e) => {
                                        error!("Failed to write download stream: {e:?}");
                                    }
                                }
                            }
                        });
                    } else {
                        tokio::spawn(async move {
                            // 每个流一个缓冲区
                            let mut buf = vec![0u8; args.packet_size];
                            loop {
                                match recv_stream.read(&mut buf).await {
                                    Ok(size) => {
                                        if let Some(bytes_received) = size {
                                            total_bytes.fetch_add(
                                                bytes_received as u64,
                                                Ordering::Relaxed,
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        error!("Error receiving stream: {}", e);
                                        break;
                                    }
                                }
                            }
                        });
                    }
                },
                Scene::Dgram => loop {
                    if args.download {
                        match conn.send_datagram_wait(packet.clone()).await {
                            Ok(_) => {
                                total_bytes_clone.fetch_add(packet_size, Ordering::Relaxed);
                            }
                            Err(e) => {
                                error!("Failed to send download datagram: {e:?}");
                            }
                        }
                    } else {
                        match conn.read_datagram().await {
                            Ok(datagram) => {
                                let bytes = datagram.len() as u64;
                                total_bytes_clone.fetch_add(bytes, Ordering::Relaxed);
                            }
                            Err(e) => {
                                error!("Error receiving datagram: {}", e);
                                break;
                            }
                        }
                    }
                },
            }
        });
    }

    Ok(())
}

async fn stream_write_all(
    stream: &mut quinn::SendStream,
    buf: &[u8],
) -> Result<(), quinn::WriteError> {
    let mut buf = buf;
    while !buf.is_empty() {
        let written = stream.write(buf).await?;
        buf = &buf[written..];
    }
    Ok(())
}

/// Run quic client: send packets like crazy
async fn run_quic_client(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting QUIC client connecting to {}...", args.addr);

    let ca_path = args.ca.clone();
    let client_config = load_client_config(&ca_path, &args.congestion_algorithm)?;

    // 使用 socket2 创建 UDP socket 并设置缓冲区大小
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_recv_buffer_size(BUFFER_SIZE).map_err(|e| {
        error!("Failed to set receive buffer size: {}", e);
        e
    })?;
    socket.set_send_buffer_size(BUFFER_SIZE).map_err(|e| {
        error!("Failed to set send buffer size: {}", e);
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

    // 创建测试数据包
    let packet = Bytes::copy_from_slice(&vec![0u8; args.packet_size]);
    let total_bytes = Arc::new(AtomicU64::new(0));
    let args = Arc::new(args);

    // 启动统计任务
    let stat_type = match args.download {
        false => "sent",
        true => "received",
    };
    let _stats_handle = start_stats_task(Arc::clone(&total_bytes), stat_type).await;
    let waiting_signal = CancellationToken::new();

    for _ in 0..args.max_conn {
        let conn = endpoint
            .connect_with(client_config.clone(), addr, "localhost")?
            .await?;

        let packet = packet.clone();
        let total_bytes = total_bytes.clone();
        let args = Arc::clone(&args);
        // 启动任务并等待所有的流都打开
        start_quic_client_conn_task(conn, args, packet, total_bytes, waiting_signal.clone()).await;
    }

    info!(
        "Open {} connections and {} streams to {}",
        args.max_conn, args.max_stream, args.addr
    );

    if args.interactive {
        info!("Press ENTER to continue...");
        let mut stdin = BufReader::new(io::stdin());
        let mut line = String::new();
        stdin.read_line(&mut line).await?;
    }

    info!("Start QUIC client transfer tasks");
    waiting_signal.cancel();

    std::future::pending::<()>().await;
    Ok(())
}

async fn start_quic_client_conn_task(
    conn: quinn::Connection,
    args: Arc<Args>,
    packet: Bytes,
    total_bytes: Arc<AtomicU64>,
    waiting_signal: CancellationToken,
) {
    // 疯狂发送数据包
    let packet_size = args.packet_size;
    let download = args.download;
    match args.scene {
        Scene::Stream => {
            // 打开流
            for _ in 0..args.max_stream {
                let total_bytes = total_bytes.clone();
                let buf = packet.clone();

                let (mut send_stream, mut recv_stream) = conn.open_bi().await.unwrap();
                // 发送数据真正打开流
                let _ = stream_write_all(&mut send_stream, b"HELLO").await;

                let waiting_signal = waiting_signal.clone();
                if download {
                    tokio::spawn(async move {
                        // 等待开始信号
                        waiting_signal.cancelled().await;
                        // 每个流一个缓冲区
                        let mut buf = vec![0u8; packet_size];
                        loop {
                            match recv_stream.read(&mut buf).await {
                                Ok(size) => {
                                    if let Some(bytes_received) = size {
                                        total_bytes
                                            .fetch_add(bytes_received as u64, Ordering::Relaxed);
                                    }
                                }
                                Err(e) => {
                                    error!("Error receiving stream: {}", e);
                                    break;
                                }
                            }
                        }
                    });
                } else {
                    tokio::spawn(async move {
                        // 等待开始信号
                        waiting_signal.cancelled().await;
                        loop {
                            match stream_write_all(&mut send_stream, &buf).await {
                                Ok(_) => {
                                    total_bytes.fetch_add(packet_size as u64, Ordering::Relaxed);
                                }
                                Err(e) => {
                                    error!("Failed to write stream: {:?}", e);
                                }
                            }
                        }
                    });
                }
            }
        }
        Scene::Dgram => {
            tokio::spawn(async move {
                if download {
                    loop {
                        match conn.read_datagram().await {
                            Ok(datagram) => {
                                let bytes = datagram.len() as u64;
                                total_bytes.fetch_add(bytes, Ordering::Relaxed);
                            }
                            Err(e) => {
                                error!("Error receiving datagram: {}", e);
                                break;
                            }
                        }
                    }
                } else {
                    loop {
                        match conn.send_datagram_wait(packet.clone()).await {
                            Ok(_) => {
                                total_bytes.fetch_add(args.packet_size as u64, Ordering::Relaxed);
                            }
                            Err(e) => {
                                // 发送失败，可能是缓冲区满，继续尝试
                                error!("Send error: {}", e);
                            }
                        }
                    }
                }
            });
        }
    }
}
