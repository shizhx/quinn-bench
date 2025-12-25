use clap::Parser;

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
    #[arg(short = 'n', long)]
    scene: String,

    /// Packet size in bytes
    #[arg(short = 's', long)]
    packet_size: usize,

    /// CA certificate path (client mode)
    #[arg(short, long)]
    ca: Option<String>,

    /// Server certificate path
    #[arg(short = 'e', long)]
    cert: Option<String>,

    /// Server private key path
    #[arg(short, long)]
    key: Option<String>,
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
