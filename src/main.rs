use clap::Parser;
use toy_dns_server::serve_udp;

#[derive(Parser)]
struct Cli {
    #[arg(long, default_value = "[::]:53")]
    listen: String,
}

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    let Cli { listen } = Cli::parse();
    eprintln!("Toy DNS server will now attempt to listen on {listen}");
    serve_udp(&listen).await?;
    Ok(())
}
