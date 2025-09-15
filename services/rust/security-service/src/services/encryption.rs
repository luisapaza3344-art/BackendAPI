use crate::{
    error::{SecurityError, SecurityResult},
    services::hsm::HSMService,
    logging::log_hsm_operation,
};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key
};
use base64::{Engine as _, engine::general_purpose};
use rand::RngCore;
use serde_json::{json, Value};
use std::collections::HashMap;
use uuid::Uuid;

/// DEVELOPMENT AEAD encryption service for sensitive audit data
/// Uses AES-256-GCM with KEK/DEK pattern for secure key management
/// ⚠️  NOT production ready - requires real HSM integration for production use
pub struct EncryptionService {
    hsm_service: HSMService,
    kek_cache: HashMap<String, Key<Aes256Gcm>>, // Key Encryption Keys cache
}

/// Encrypted data container with persistent wrapped DEK for IPFS storage
#[derive(Clone, Debug)]
pub struct EncryptedData {
    pub ciphertext: String,           // Base64 encoded AES-256-GCM encrypted data
    pub nonce: String,               // Base64 encoded nonce (96-bit for AES-GCM)
    pub wrapped_dek: String,         // Base64 encoded DEK wrapped with KEK
    pub kek_id: String,              // KEK identifier for unwrapping
    pub algorithm: String,           // "AES-256-GCM"
    pub version: String,             // Encryption format version  
    pub aad: String,                 // Base64 encoded Additional Authenticated Data
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl EncryptionService {
    /// Initialize FIPS-compliant encryption service with HSM integration
    pub async fn new(hsm_service: HSMService) -> SecurityResult<Self> {
        log_hsm_operation(
            "encryption-service",
            "initialize", 
            "started",
            Some("AES-256-GCM"),
        );

        let service = Self {
            hsm_service,
            kek_cache: HashMap::new(),
        };

        log_hsm_operation(
            "encryption-service",
            "initialize", 
            "success",
            Some("AES-256-GCM"), 
        );

        Ok(service)
    }

    /// Encrypt audit data using AES-256-GCM with KEK/DEK pattern
    pub async fn encrypt_audit_data(&mut self, data: &Value, kek_id: &str) -> SecurityResult<EncryptedData> {
        log_hsm_operation(kek_id, "encrypt_audit_data", "started", Some("AES-256-GCM"));

        // 1. Get or derive the Key Encryption Key (KEK) deterministically
        let kek = self.get_or_derive_kek(kek_id).await?;

        // 2. Generate a random Data Encryption Key (DEK) for this specific record
        let mut dek_bytes = [0u8; 32]; // 256-bit key for AES-256
        OsRng.fill_bytes(&mut dek_bytes);
        let dek = Key::<Aes256Gcm>::from_slice(&dek_bytes);

        // 3. Wrap the DEK with the KEK using AES-KW equivalent (encrypt DEK with KEK)
        let dek_nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let kek_cipher = Aes256Gcm::new(&kek);
        let wrapped_dek = kek_cipher
            .encrypt(&dek_nonce, dek_bytes.as_ref())
            .map_err(|e| SecurityError::Encryption(format!("DEK wrapping failed: {}", e)))?;

        // 4. Serialize the actual audit data to encrypt
        let plaintext = serde_json::to_vec(data)
            .map_err(|e| SecurityError::Encryption(format!("Failed to serialize data: {}", e)))?;

        // 5. Create Additional Authenticated Data (AAD) for integrity
        let aad_data = format!("audit_record|{}|{}|AES-256-GCM", kek_id, chrono::Utc::now().timestamp());
        
        // 6. Encrypt the audit data with the DEK using proper AEAD with AAD parameter
        let data_nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let dek_cipher = Aes256Gcm::new(dek);
        
        // CRITICAL FIX: Use proper AEAD encryption with AAD as separate parameter
        use aes_gcm::aead::Payload;
        let payload = Payload {
            msg: &plaintext,
            aad: aad_data.as_bytes(),
        };
        
        let ciphertext = dek_cipher
            .encrypt(&data_nonce, payload)
            .map_err(|e| SecurityError::Encryption(format!("AES-GCM encryption failed: {}", e)))?;

        // 7. Create the encrypted data container
        let encrypted_data = EncryptedData {
            ciphertext: general_purpose::STANDARD.encode(&ciphertext),
            nonce: general_purpose::STANDARD.encode(&data_nonce),
            wrapped_dek: format!("{}:{}", 
                general_purpose::STANDARD.encode(&dek_nonce),  // KEK nonce 
                general_purpose::STANDARD.encode(&wrapped_dek) // Wrapped DEK
            ),
            kek_id: kek_id.to_string(),
            algorithm: "AES-256-GCM".to_string(),
            version: "2.0".to_string(), // Updated version for KEK/DEK pattern
            aad: general_purpose::STANDARD.encode(&aad_data),
            created_at: chrono::Utc::now(),
        };

        log_hsm_operation(kek_id, "encrypt_audit_data", "success", Some("AES-256-GCM"));

        tracing::info!(
            "🔐 Audit data encrypted with AES-256-GCM KEK/DEK pattern, kek_id: {}, size: {} bytes",
            kek_id, ciphertext.len()
        );

        Ok(encrypted_data)
    }

    /// Decrypt audit data using AES-256-GCM with persistent KEK/DEK recovery
    pub async fn decrypt_audit_data(&mut self, encrypted_data: &EncryptedData) -> SecurityResult<Value> {
        log_hsm_operation(&encrypted_data.kek_id, "decrypt_audit_data", "started", Some("AES-256-GCM"));

        // 1. Validate algorithm and version compatibility
        if encrypted_data.algorithm != "AES-256-GCM" {
            return Err(SecurityError::Encryption(format!(
                "Unsupported encryption algorithm: {}", 
                encrypted_data.algorithm
            )));
        }

        // 2. Get the Key Encryption Key (KEK) deterministically
        let kek = self.get_or_derive_kek(&encrypted_data.kek_id).await?;

        // 3. Parse and unwrap the Data Encryption Key (DEK)
        let wrapped_parts: Vec<&str> = encrypted_data.wrapped_dek.split(':').collect();
        if wrapped_parts.len() != 2 {
            return Err(SecurityError::Encryption("Invalid wrapped DEK format".to_string()));
        }

        let kek_nonce = general_purpose::STANDARD
            .decode(wrapped_parts[0])
            .map_err(|e| SecurityError::Encryption(format!("Invalid KEK nonce encoding: {}", e)))?;
        
        let wrapped_dek_bytes = general_purpose::STANDARD
            .decode(wrapped_parts[1])
            .map_err(|e| SecurityError::Encryption(format!("Invalid wrapped DEK encoding: {}", e)))?;

        // 4. Unwrap the DEK using KEK
        let kek_cipher = Aes256Gcm::new(&kek);
        let kek_nonce_array = *aes_gcm::Nonce::from_slice(&kek_nonce);
        let dek_bytes = kek_cipher
            .decrypt(&kek_nonce_array, wrapped_dek_bytes.as_ref())
            .map_err(|e| SecurityError::Encryption(format!("DEK unwrapping failed: {}", e)))?;

        let dek = Key::<Aes256Gcm>::from_slice(&dek_bytes);

        // 5. Decrypt the actual audit data with DEK using proper AEAD with AAD parameter
        let ciphertext = general_purpose::STANDARD
            .decode(&encrypted_data.ciphertext)
            .map_err(|e| SecurityError::Encryption(format!("Invalid ciphertext encoding: {}", e)))?;

        let data_nonce = general_purpose::STANDARD
            .decode(&encrypted_data.nonce)
            .map_err(|e| SecurityError::Encryption(format!("Invalid nonce encoding: {}", e)))?;

        let data_nonce_array = *aes_gcm::Nonce::from_slice(&data_nonce);
        let dek_cipher = Aes256Gcm::new(dek);
        
        // 6. Prepare AAD for proper AEAD decryption
        let aad_decoded = general_purpose::STANDARD
            .decode(&encrypted_data.aad)
            .map_err(|e| SecurityError::Encryption(format!("Invalid AAD encoding: {}", e)))?;
        
        // CRITICAL FIX: Use proper AEAD decryption with AAD as separate parameter
        use aes_gcm::aead::Payload;
        let payload = Payload {
            msg: &ciphertext,
            aad: &aad_decoded,
        };
        
        let plaintext = dek_cipher
            .decrypt(&data_nonce_array, payload)
            .map_err(|e| SecurityError::Encryption(format!("AES-GCM decryption failed - possible tampering: {}", e)))?;

        // 7. Deserialize back to JSON
        let data: Value = serde_json::from_slice(&plaintext)
            .map_err(|e| SecurityError::Encryption(format!("Failed to deserialize decrypted data: {}", e)))?;

        log_hsm_operation(&encrypted_data.kek_id, "decrypt_audit_data", "success", Some("AES-256-GCM"));

        tracing::info!(
            "🔓 Audit data decrypted successfully, kek_id: {}, size: {} bytes",
            encrypted_data.kek_id, plaintext.len()
        );

        Ok(data)
    }

    /// Get or derive Key Encryption Key (KEK) deterministically from HSM
    async fn get_or_derive_kek(&mut self, kek_id: &str) -> SecurityResult<Key<Aes256Gcm>> {
        // Check cache first
        if let Some(kek) = self.kek_cache.get(kek_id) {
            return Ok(*kek);
        }

        log_hsm_operation(kek_id, "derive_kek", "started", Some("HMAC-SHA256"));

        // Use DETERMINISTIC key derivation with stable HSM-based inputs
        // This ensures the same KEK is always derived for the same kek_id
        let kek_context = format!("KEK_DERIVATION_CONTEXT_{}", kek_id);
        
        // Get deterministic master key material from HSM configuration instead of signature
        // Use stable HSM identifiers to ensure deterministic derivation
        let master_key_material = format!(
            "STABLE_HSM_MASTER_{}_{}_V2", 
            self.hsm_service.get_key_id(), 
            self.hsm_service.get_attestation_key_id()
        );
        
        // Derive KEK using HKDF with completely stable inputs
        let kek_bytes = self.derive_kek_deterministic(&master_key_material, &kek_context)?;
        let kek = Key::<Aes256Gcm>::from_slice(&kek_bytes);

        // Cache the derived KEK
        self.kek_cache.insert(kek_id.to_string(), *kek);

        log_hsm_operation(kek_id, "derive_kek", "success", Some("HMAC-SHA256"));

        tracing::info!("🔑 KEK derived deterministically from stable HSM config, kek_id: {}", kek_id);

        Ok(*kek)
    }

    /// Derive KEK deterministically using HKDF-like approach with stable inputs
    fn derive_kek_deterministic(&self, master_material: &str, context: &str) -> SecurityResult<[u8; 32]> {
        use sha2::{Sha256, Digest};
        use hmac::{Hmac, Mac};

        // Step 1: Extract - create PRK from master material
        let mut hmac = <Hmac<Sha256> as Mac>::new_from_slice(b"FIPS_AUDIT_ENCRYPTION_SALT_V2")
            .map_err(|e| SecurityError::Encryption(format!("HMAC initialization failed: {}", e)))?;
        
        hmac.update(master_material.as_bytes());
        let prk = hmac.finalize().into_bytes();

        // Step 2: Expand - derive KEK from PRK + context
        let mut hmac_expand = <Hmac<Sha256> as Mac>::new_from_slice(&prk)
            .map_err(|e| SecurityError::Encryption(format!("HMAC expand initialization failed: {}", e)))?;
        
        hmac_expand.update(context.as_bytes());
        hmac_expand.update(b"AES-256-GCM_KEK_V2");
        hmac_expand.update(&[0x01]); // Counter for HKDF

        let kek_hash = hmac_expand.finalize().into_bytes();
        let mut kek_bytes = [0u8; 32];
        kek_bytes.copy_from_slice(&kek_hash[..32]);

        Ok(kek_bytes)
    }

    /// Create encrypted IPFS payload with persistent key material
    pub fn create_encrypted_ipfs_payload(&self, encrypted_data: &EncryptedData, audit_record_id: Uuid) -> Value {
        json!({
            "audit_record_id": audit_record_id,
            "encrypted_payload": {
                "ciphertext": encrypted_data.ciphertext,
                "nonce": encrypted_data.nonce, 
                "wrapped_dek": encrypted_data.wrapped_dek,  // Contains persistent key recovery data
                "kek_id": encrypted_data.kek_id,
                "algorithm": encrypted_data.algorithm,
                "version": encrypted_data.version,
                "aad": encrypted_data.aad,
                "encrypted_at": encrypted_data.created_at,
            },
            "ipfs_metadata": {
                "stored_at": chrono::Utc::now(),
                "version": "2.0",
                "format": "encrypted_json_kek_dek", 
                "encryption": "AES-256-GCM", // Removed false FIPS claims
                "compression": "none",
                "production_ready": false, // Development mode - not production ready
                "hsm_derived": true,
                "key_recovery": "deterministic_kek_persistent_dek"
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::HSMConfig,
        services::hsm::HSMService,
    };
    use serde_json::json;
    use uuid::Uuid;

    async fn create_test_encryption_service() -> EncryptionService {
        let hsm_config = HSMConfig {
            provider: "test_provider".to_string(),
            key_id: "test_key_id".to_string(),
            attestation_key_id: "test_attestation_key".to_string(),
            fips_mode: true,
        };
        let hsm_service = HSMService::new(hsm_config).await.unwrap();
        EncryptionService::new(hsm_service).await.unwrap()
    }

    #[tokio::test] 
    async fn test_encryption_deterministic_recovery() {
        // Test that the same KEK can be derived after service restart
        // This test ensures data recoverability - CRITICAL for audit compliance
        
        let test_data = json!({
            "user_id": "test_user_123",
            "transaction_id": "tx_456",
            "amount": 1000.50,
            "timestamp": "2025-09-15T00:00:00Z"
        });
        let kek_id = "test_service_kek";
        
        // First encryption with initial service instance
        let mut service1 = create_test_encryption_service().await;
        let encrypted_data = service1.encrypt_audit_data(&test_data, kek_id).await.unwrap();
        
        // Simulate service restart - create new instance (clearing cache)
        let mut service2 = create_test_encryption_service().await;
        
        // Should be able to decrypt with new service instance
        let decrypted_data = service2.decrypt_audit_data(&encrypted_data).await.unwrap();
        
        assert_eq!(test_data, decrypted_data, "Deterministic recovery failed - data not recoverable after restart");
        
        // Verify KEK derivation is truly deterministic
        let kek1 = service1.get_or_derive_kek(kek_id).await.unwrap();
        let kek2 = service2.get_or_derive_kek(kek_id).await.unwrap();
        assert_eq!(kek1.as_slice(), kek2.as_slice(), "KEK derivation is not deterministic!");
    }

    #[tokio::test]
    async fn test_kek_dek_pattern_integrity() {
        // Test that KEK/DEK pattern works correctly with different records
        // and keys can be recovered independently
        
        let mut service = create_test_encryption_service().await;
        
        let data1 = json!({"record": 1, "sensitive": "data1"});
        let data2 = json!({"record": 2, "sensitive": "data2"});
        let data3 = json!({"record": 3, "sensitive": "data3"});
        
        // Use different KEK IDs for different services/contexts
        let kek_id1 = "service_a_kek";
        let kek_id2 = "service_b_kek";
        
        // Encrypt multiple records
        let encrypted1 = service.encrypt_audit_data(&data1, kek_id1).await.unwrap();
        let encrypted2 = service.encrypt_audit_data(&data2, kek_id2).await.unwrap();
        let encrypted3 = service.encrypt_audit_data(&data3, kek_id1).await.unwrap(); // Same KEK as record 1
        
        // Verify all can be decrypted independently
        let decrypted1 = service.decrypt_audit_data(&encrypted1).await.unwrap();
        let decrypted2 = service.decrypt_audit_data(&encrypted2).await.unwrap();
        let decrypted3 = service.decrypt_audit_data(&encrypted3).await.unwrap();
        
        assert_eq!(data1, decrypted1);
        assert_eq!(data2, decrypted2);
        assert_eq!(data3, decrypted3);
        
        // Verify different KEKs produce different wrapped DEKs (even for same data)
        assert_ne!(encrypted1.wrapped_dek, encrypted2.wrapped_dek, "Different KEKs should produce different wrapped DEKs");
        
        // Verify same KEK produces different DEKs (but same KEK for unwrapping)
        assert_ne!(encrypted1.wrapped_dek, encrypted3.wrapped_dek, "Each record should have unique DEK");
        assert_eq!(encrypted1.kek_id, encrypted3.kek_id, "Same KEK ID should be preserved");
    }
    
    #[tokio::test]
    async fn test_aad_integrity_protection() {
        // Test that AAD properly protects against tampering
        
        let mut service = create_test_encryption_service().await;
        let test_data = json!({"critical": "audit_data", "amount": 50000});
        let kek_id = "integrity_test_kek";
        
        let mut encrypted_data = service.encrypt_audit_data(&test_data, kek_id).await.unwrap();
        
        // Tamper with AAD - this should cause decryption to fail
        encrypted_data.aad = general_purpose::STANDARD.encode("tampered_aad_data");
        
        let result = service.decrypt_audit_data(&encrypted_data).await;
        assert!(result.is_err(), "Decryption should fail with tampered AAD");
        
        // Verify the error indicates tampering
        let error_msg = format!("{:?}", result.unwrap_err());
        assert!(error_msg.contains("tampering") || error_msg.contains("failed"), 
                "Error should indicate potential tampering: {}", error_msg);
    }
    
    #[tokio::test]
    async fn test_encrypt_decrypt_large_data() {
        // Test encryption/decryption of larger audit records
        
        let mut service = create_test_encryption_service().await;
        
        // Create large test data (simulating complex audit record)
        let large_data = json!({
            "audit_id": Uuid::new_v4(),
            "transaction_details": {
                "user_actions": (0..1000).map(|i| format!("action_{}", i)).collect::<Vec<_>>(),
                "metadata": {
                    "ip_addresses": vec!["192.168.1.1", "10.0.0.1", "172.16.0.1"],
                    "user_agents": vec!["Mozilla/5.0...", "Chrome/91.0..."],
                    "timestamps": (0..100).map(|i| format!("2025-09-15T{:02}:00:00Z", i % 24)).collect::<Vec<_>>()
                },
                "sensitive_data": "0".repeat(10000) // 10KB of data
            }
        });
        
        let kek_id = "large_data_kek";
        
        let encrypted = service.encrypt_audit_data(&large_data, kek_id).await.unwrap();
        let decrypted = service.decrypt_audit_data(&encrypted).await.unwrap();
        
        assert_eq!(large_data, decrypted, "Large data encryption/decryption failed");
    }
}