use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub redis: RedisConfig,
    pub qldb: QLDBConfig,
    pub ipfs: IPFSConfig,
    pub bitcoin: BitcoinConfig,
    pub hsm: HSMConfig,
    pub fips: FIPSConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub tls_enabled: bool,
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub fips_mode: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisConfig {
    pub url: String,
    pub pool_size: u32,
    pub fips_mode: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QLDBConfig {
    pub ledger_name: String,
    pub region: String,
    pub table_name: String,
    pub fips_endpoints: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IPFSConfig {
    pub gateway_url: String,
    pub api_url: String,
    pub pin_service_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinConfig {
    pub rpc_url: String,
    pub rpc_user: String,
    pub rpc_password: String,
    pub network: String, // mainnet, testnet, regtest
    pub anchor_interval_blocks: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HSMConfig {
    pub provider: String,
    pub key_id: String,
    pub fips_mode: bool,
    pub attestation_key_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FIPSConfig {
    pub enabled: bool,
    pub level: String, // "140-3_Level_3"
    pub compliance_mode: bool,
    pub audit_all_operations: bool,
}

impl SecurityConfig {
    pub fn from_env() -> Result<Self> {
        Ok(SecurityConfig {
            server: ServerConfig {
                host: env::var("SECURITY_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
                port: env::var("SECURITY_PORT")
                    .unwrap_or_else(|_| "8000".to_string())
                    .parse()?,
                tls_enabled: env::var("TLS_ENABLED")
                    .unwrap_or_else(|_| "true".to_string())
                    .parse()?,
                cert_path: env::var("TLS_CERT_PATH")
                    .unwrap_or_else(|_| "certs/security.crt".to_string()),
                key_path: env::var("TLS_KEY_PATH")
                    .unwrap_or_else(|_| "certs/security.key".to_string()),
            },
            database: DatabaseConfig {
                url: env::var("DATABASE_URL")?,
                max_connections: env::var("DB_MAX_CONNECTIONS")
                    .unwrap_or_else(|_| "25".to_string())
                    .parse()?,
                fips_mode: env::var("DB_FIPS_MODE")
                    .unwrap_or_else(|_| "true".to_string())
                    .parse()?,
            },
            redis: RedisConfig {
                url: env::var("REDIS_URL")
                    .unwrap_or_else(|_| "redis://localhost:6379".to_string()),
                pool_size: env::var("REDIS_POOL_SIZE")
                    .unwrap_or_else(|_| "10".to_string())
                    .parse()?,
                fips_mode: env::var("REDIS_FIPS_MODE")
                    .unwrap_or_else(|_| "true".to_string())
                    .parse()?,
            },
            qldb: QLDBConfig {
                ledger_name: env::var("QLDB_LEDGER_NAME")
                    .unwrap_or_else(|_| "security-audit-ledger".to_string()),
                region: env::var("AWS_REGION")
                    .unwrap_or_else(|_| "us-east-1".to_string()),
                table_name: env::var("QLDB_TABLE_NAME")
                    .unwrap_or_else(|_| "audit_records".to_string()),
                fips_endpoints: env::var("QLDB_FIPS_ENDPOINTS")
                    .unwrap_or_else(|_| "true".to_string())
                    .parse()?,
            },
            ipfs: IPFSConfig {
                gateway_url: env::var("IPFS_GATEWAY_URL")
                    .unwrap_or_else(|_| "https://ipfs.io".to_string()),
                api_url: env::var("IPFS_API_URL")
                    .unwrap_or_else(|_| "http://localhost:5001".to_string()),
                pin_service_key: env::var("IPFS_PIN_SERVICE_KEY").ok(),
            },
            bitcoin: BitcoinConfig {
                rpc_url: env::var("BITCOIN_RPC_URL")
                    .unwrap_or_else(|_| "http://localhost:8332".to_string()),
                rpc_user: env::var("BITCOIN_RPC_USER")
                    .unwrap_or_else(|_| "bitcoinrpc".to_string()),
                rpc_password: env::var("BITCOIN_RPC_PASSWORD")
                    .unwrap_or_else(|_| "".to_string()),
                network: env::var("BITCOIN_NETWORK")
                    .unwrap_or_else(|_| "testnet".to_string()),
                anchor_interval_blocks: env::var("BITCOIN_ANCHOR_INTERVAL")
                    .unwrap_or_else(|_| "6".to_string())
                    .parse()?,
            },
            hsm: HSMConfig {
                provider: env::var("HSM_PROVIDER")
                    .unwrap_or_else(|_| "aws-cloudhsm".to_string()),
                key_id: env::var("HSM_KEY_ID")
                    .unwrap_or_else(|_| "security-attestation-key".to_string()),
                fips_mode: env::var("HSM_FIPS_MODE")
                    .unwrap_or_else(|_| "true".to_string())
                    .parse()?,
                attestation_key_id: env::var("HSM_ATTESTATION_KEY_ID")
                    .unwrap_or_else(|_| "attestation-signing-key".to_string()),
            },
            fips: FIPSConfig {
                enabled: env::var("FIPS_ENABLED")
                    .unwrap_or_else(|_| "true".to_string())
                    .parse()?,
                level: env::var("FIPS_LEVEL")
                    .unwrap_or_else(|_| "140-3_Level_3".to_string()),
                compliance_mode: env::var("FIPS_COMPLIANCE_MODE")
                    .unwrap_or_else(|_| "true".to_string())
                    .parse()?,
                audit_all_operations: env::var("FIPS_AUDIT_ALL")
                    .unwrap_or_else(|_| "true".to_string())
                    .parse()?,
            },
        })
    }
}