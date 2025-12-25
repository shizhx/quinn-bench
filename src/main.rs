use clap::Parser;
use quinn::congestion::{BbrConfig, ControllerFactory, CubicConfig, NewRenoConfig};
use quinn::{ClientConfig, ServerConfig, TransportConfig};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use std::sync::Arc;

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
    #[arg(long)]
    ca: Option<String>,

    /// Server certificate path
    #[arg(long)]
    cert: Option<String>,

    /// Server private key path
    #[arg(long)]
    key: Option<String>,

    /// QUIC congestion control algorithm (cubic, bbr, newreno)
    #[arg(long = "cc", default_value = "cubic", value_parser = ["cubic", "bbr", "newreno"])]
    pub congestion_algorithm: String,
}

fn main() {
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

    let mut client_config = ClientConfig::with_root_certificates(Arc::new(certs))?;

    // 设置传输配置包括拥塞控制算法
    let transport_config = create_transport_config(congestion_algorithm);
    client_config.transport_config(Arc::new(transport_config));

    Ok(client_config)
}
