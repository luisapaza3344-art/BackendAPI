use anyhow::Result;
use security_service::{
    app::SecurityApp,
    config::SecurityConfig,
    logging::init_fips_logger,
};
use std::net::SocketAddr;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize FIPS 140-3 Level 3 compliant logging
    init_fips_logger()?;
    
    info!("🔐 Starting FIPS 140-3 Level 3 Security Service with immutable audit trail");
    
    // Load configuration
    let config = SecurityConfig::from_env()?;
    info!("📋 Security configuration loaded");
    
    // Initialize the security application
    let app = SecurityApp::new(config.clone()).await?;
    info!("🚀 Security service initialized successfully");
    
    // Create the router
    let router = app.create_router().await?;
    
    // Start the server with proper configuration
    let addr = SocketAddr::from(([0, 0, 0, 0], config.server.port));
    info!("🌐 Security service listening on {} (TLS: {})", addr, config.server.tls_enabled);
    
    let listener = tokio::net::TcpListener::bind(addr).await?;
    
    if config.server.tls_enabled {
        info!("⚠️  TLS enabled but not implemented - running in HTTP mode for development");
        // TODO: Implement TLS with proper certificates
        // For production, implement TLS termination or use reverse proxy
    }
    
    axum::serve(listener, router)
        .await
        .map_err(|e| anyhow::anyhow!("Server error: {}", e))?;

    Ok(())
}