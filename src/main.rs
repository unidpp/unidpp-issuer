//! Entrypoint: environment-driven configuration, then serve forever.

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let (config, warning) = unidpp_issuer::Config::from_env();
    if let Some(w) = warning {
        eprintln!("unidpp-issuer: WARNING — {w}");
    }
    unidpp_issuer::run(config).await
}
