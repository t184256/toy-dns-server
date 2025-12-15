use clap::Parser;
use toy_dns_server::{ZoneConfig, serve};

#[derive(Parser)]
struct Cli {
    #[arg(long, default_value = "[::]:53")]
    listen: String,
    #[arg(long, default_value = "tests/example_zone.yaml")]
    config: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let Cli { listen, config } = Cli::parse();

    let yaml = std::fs::read_to_string(&config)?;
    let zone_config: ZoneConfig = serde_yaml::from_str(&yaml)?;

    eprintln!("Toy DNS server will now attempt to listen on {listen}");
    serve(&zone_config, &listen).await?;
    Ok(())
}
