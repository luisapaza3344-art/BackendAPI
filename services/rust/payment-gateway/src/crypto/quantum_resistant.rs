use pqcrypto_kyber::kyber1024::{self, PublicKey as KyberPublicKey, SecretKey as KyberSecretKey, Ciphertext};
use pqcrypto_dilithium::dilithium5::{self, PublicKey as DilithiumPublicKey, SecretKey as DilithiumSecretKey, DetachedSignature};
use pqcrypto_sphincsplus::sphincsshake256256ssimple::{self, PublicKey as SphincsPlusPublicKey, SecretKey as SphincsPlusSecretKey};
use pqcrypto_traits::kem::PublicKey as KemPublicKey;
use pqcrypto_traits::sign::{PublicKey as SignPublicKey, DetachedSignature as SignDetachedSignature};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, warn, error};
use chrono::{DateTime, Utc};

/// Post-Quantum Cryptography System for Financial-Grade Security
/// Implements NIST Post-Quantum Cryptography Standards for protection against quantum computing threats
#[derive(Clone)]
pub struct PostQuantumCrypto {
    // Kyber: Key Encapsulation Mechanism (KEM)
    kyber_public_key: Option<KyberPublicKey>,
    kyber_secret_key: Option<KyberSecretKey>,
    
    // Dilithium: Digital Signatures
    dilithium_public_key: Option<DilithiumPublicKey>,
    dilithium_secret_key: Option<DilithiumSecretKey>,
    
    // SPHINCS+: Stateless Hash-Based Signatures
    sphincs_public_key: Option<SphincsPlusPublicKey>,
    sphincs_secret_key: Option<SphincsPlusSecretKey>,
    
    fips_compliant: bool,
    algorithm_suite: String,
}

/// Quantum-resistant cryptographic operation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumCryptoResult {
    pub operation: String,
    pub algorithm: String,
    pub success: bool,
    pub timestamp: DateTime<Utc>,
    pub key_id: String,
    pub nist_standard: String,
}

/// Encrypted payload using post-quantum cryptography
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumEncryptedPayload {
    pub algorithm: String,
    pub ciphertext: Vec<u8>,
    pub encapsulated_key: Vec<u8>, // For Kyber KEM
    pub signature: Option<Vec<u8>>, // Quantum-resistant signature
    pub timestamp: DateTime<Utc>,
    pub nist_level: u8, // Security level (1-5)
}

/// Quantum-resistant signature with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumSignature {
    pub algorithm: String,
    pub signature: Vec<u8>,
    pub public_key_hash: String,
    pub timestamp: DateTime<Utc>,
    pub message_hash: String,
    pub nist_category: String, // "signature" or "hash-based"
}

impl PostQuantumCrypto {
    /// Initialize Post-Quantum Cryptography with NIST standards
    pub async fn new() -> Result<Self, anyhow::Error> {
        info!("🔐 Initializing Post-Quantum Cryptography with NIST standards");
        
        let mut pqc = Self {
            kyber_public_key: None,
            kyber_secret_key: None,
            dilithium_public_key: None,
            dilithium_secret_key: None,
            sphincs_public_key: None,
            sphincs_secret_key: None,
            fips_compliant: true,
            algorithm_suite: "NIST-PQC-Suite".to_string(),
        };
        
        // Generate quantum-resistant key pairs
        pqc.generate_kyber_keypair().await?;
        pqc.generate_dilithium_keypair().await?;
        pqc.generate_sphincs_keypair().await?;
        
        info!("✅ Post-Quantum Cryptography initialized with NIST standards",
            "kyber" = "Kyber-1024 (NIST Level 5)",
            "dilithium" = "Dilithium-5 (NIST Level 5)",
            "sphincs" = "SPHINCS+-SHAKE256-256s-simple"
        );
        
        Ok(pqc)
    }
    
    /// Generate Kyber key pair for quantum-resistant key encapsulation
    async fn generate_kyber_keypair(&mut self) -> Result<(), anyhow::Error> {
        info!("🔑 Generating Kyber-1024 key pair (NIST Level 5 security)");
        
        let (public_key, secret_key) = kyber1024::keypair();
        
        self.kyber_public_key = Some(public_key);
        self.kyber_secret_key = Some(secret_key);
        
        info!("✅ Kyber-1024 key pair generated successfully");
        Ok(())
    }
    
    /// Generate Dilithium key pair for quantum-resistant signatures
    async fn generate_dilithium_keypair(&mut self) -> Result<(), anyhow::Error> {
        info!("🔑 Generating Dilithium-5 key pair (NIST Level 5 security)");
        
        let (public_key, secret_key) = dilithium5::keypair();
        
        self.dilithium_public_key = Some(public_key);
        self.dilithium_secret_key = Some(secret_key);
        
        info!("✅ Dilithium-5 key pair generated successfully");
        Ok(())
    }
    
    /// Generate SPHINCS+ key pair for stateless hash-based signatures
    async fn generate_sphincs_keypair(&mut self) -> Result<(), anyhow::Error> {
        info!("🔑 Generating SPHINCS+-SHAKE256 key pair");
        
        let (public_key, secret_key) = sphincsshake256256ssimple::keypair();
        
        self.sphincs_public_key = Some(public_key);
        self.sphincs_secret_key = Some(secret_key);
        
        info!("✅ SPHINCS+-SHAKE256 key pair generated successfully");
        Ok(())
    }
    
    /// Encrypt payment data using quantum-resistant Kyber KEM
    pub async fn encrypt_payment_data(
        &self,
        plaintext: &[u8],
        recipient_public_key: Option<&KyberPublicKey>,
    ) -> Result<QuantumEncryptedPayload, anyhow::Error> {
        info!("🔐 Encrypting payment data with Kyber-1024 (quantum-resistant)");
        
        let public_key = recipient_public_key
            .or(self.kyber_public_key.as_ref())
            .ok_or_else(|| anyhow::anyhow!("No Kyber public key available"))?;
        
        // Generate shared secret and encapsulated key
        let (ciphertext, shared_secret) = kyber1024::encapsulate(public_key);
        
        // Use shared secret for symmetric encryption
        let encrypted_data = self.symmetric_encrypt(plaintext, &shared_secret)?;
        
        // Sign the encrypted payload for integrity
        let signature = self.sign_with_dilithium(&encrypted_data).await?;
        
        let payload = QuantumEncryptedPayload {
            algorithm: "Kyber-1024".to_string(),
            ciphertext: encrypted_data,
            encapsulated_key: ciphertext.as_bytes().to_vec(),
            signature: Some(signature.signature),
            timestamp: Utc::now(),
            nist_level: 5, // Kyber-1024 provides NIST Level 5 security
        };
        
        info!("✅ Payment data encrypted with quantum-resistant cryptography",
            "payload_size" = payload.ciphertext.len(),
            "nist_level" = payload.nist_level
        );
        
        Ok(payload)
    }
    
    /// Decrypt payment data using quantum-resistant Kyber KEM
    pub async fn decrypt_payment_data(
        &self,
        payload: &QuantumEncryptedPayload,
    ) -> Result<Vec<u8>, anyhow::Error> {
        info!("🔓 Decrypting payment data with Kyber-1024");
        
        let secret_key = self.kyber_secret_key.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No Kyber secret key available"))?;
        
        // Reconstruct ciphertext from bytes
        let ciphertext = Ciphertext::from_bytes(&payload.encapsulated_key)?;
        
        // Decapsulate to get shared secret
        let shared_secret = kyber1024::decapsulate(&ciphertext, secret_key);
        
        // Verify signature first
        if let Some(signature_bytes) = &payload.signature {
            let signature = DetachedSignature::from_bytes(signature_bytes)?;
            let is_valid = self.verify_dilithium_signature(&payload.ciphertext, &signature).await?;
            
            if !is_valid {
                error!("❌ Quantum signature verification failed");
                return Err(anyhow::anyhow!("Signature verification failed"));
            }
        }
        
        // Decrypt using shared secret
        let plaintext = self.symmetric_decrypt(&payload.ciphertext, &shared_secret)?;
        
        info!("✅ Payment data decrypted successfully");
        Ok(plaintext)
    }
    
    /// Sign data with Dilithium quantum-resistant signature
    pub async fn sign_with_dilithium(&self, data: &[u8]) -> Result<QuantumSignature, anyhow::Error> {
        info!("✍️ Signing data with Dilithium-5 (quantum-resistant)");
        
        let secret_key = self.dilithium_secret_key.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No Dilithium secret key available"))?;
        
        let public_key = self.dilithium_public_key.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No Dilithium public key available"))?;
        
        // Sign the data
        let signature = dilithium5::detached_sign(data, secret_key);
        
        // Create metadata
        let public_key_hash = self.hash_public_key(public_key.as_bytes())?;
        let message_hash = self.hash_data(data)?;
        
        let quantum_signature = QuantumSignature {
            algorithm: "Dilithium-5".to_string(),
            signature: signature.as_bytes().to_vec(),
            public_key_hash,
            timestamp: Utc::now(),
            message_hash,
            nist_category: "signature".to_string(),
        };
        
        info!("✅ Dilithium-5 signature generated",
            "signature_size" = quantum_signature.signature.len()
        );
        
        Ok(quantum_signature)
    }
    
    /// Verify Dilithium quantum-resistant signature
    pub async fn verify_dilithium_signature(
        &self,
        data: &[u8],
        signature: &DetachedSignature,
    ) -> Result<bool, anyhow::Error> {
        info!("🔍 Verifying Dilithium-5 signature");
        
        let public_key = self.dilithium_public_key.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No Dilithium public key available"))?;
        
        // Verify signature
        let is_valid = dilithium5::verify_detached_signature(signature, data, public_key).is_ok();
        
        if is_valid {
            info!("✅ Dilithium-5 signature verified successfully");
        } else {
            warn!("❌ Dilithium-5 signature verification failed");
        }
        
        Ok(is_valid)
    }
    
    /// Sign with SPHINCS+ hash-based signature (stateless)
    pub async fn sign_with_sphincs(&self, data: &[u8]) -> Result<QuantumSignature, anyhow::Error> {
        info!("✍️ Signing data with SPHINCS+-SHAKE256 (stateless hash-based)");
        
        let secret_key = self.sphincs_secret_key.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No SPHINCS+ secret key available"))?;
        
        let public_key = self.sphincs_public_key.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No SPHINCS+ public key available"))?;
        
        // Sign the data
        let signature = sphincsshake256256ssimple::detached_sign(data, secret_key);
        
        // Create metadata
        let public_key_hash = self.hash_public_key(public_key.as_bytes())?;
        let message_hash = self.hash_data(data)?;
        
        let quantum_signature = QuantumSignature {
            algorithm: "SPHINCS+-SHAKE256-256s-simple".to_string(),
            signature: signature.as_bytes().to_vec(),
            public_key_hash,
            timestamp: Utc::now(),
            message_hash,
            nist_category: "hash-based".to_string(),
        };
        
        info!("✅ SPHINCS+ signature generated",
            "signature_size" = quantum_signature.signature.len()
        );
        
        Ok(quantum_signature)
    }
    
    /// Symmetric encryption using shared secret from Kyber KEM
    fn symmetric_encrypt(&self, plaintext: &[u8], shared_secret: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit, aead::Aead};
        use ark_std::rand::{thread_rng, RngCore};
        
        // Use first 32 bytes of shared secret as AES key
        let key = Key::<Aes256Gcm>::from_slice(&shared_secret[..32]);
        let cipher = Aes256Gcm::new(key);
        
        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Encrypt
        let mut ciphertext = cipher.encrypt(nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("AES-GCM encryption failed: {}", e))?;
        
        // Prepend nonce to ciphertext
        let mut result = nonce_bytes.to_vec();
        result.append(&mut ciphertext);
        
        Ok(result)
    }
    
    /// Symmetric decryption using shared secret from Kyber KEM
    fn symmetric_decrypt(&self, ciphertext: &[u8], shared_secret: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit, aead::Aead};
        
        if ciphertext.len() < 12 {
            return Err(anyhow::anyhow!("Ciphertext too short"));
        }
        
        // Extract nonce and ciphertext
        let nonce = Nonce::from_slice(&ciphertext[..12]);
        let encrypted_data = &ciphertext[12..];
        
        // Use first 32 bytes of shared secret as AES key
        let key = Key::<Aes256Gcm>::from_slice(&shared_secret[..32]);
        let cipher = Aes256Gcm::new(key);
        
        // Decrypt
        let plaintext = cipher.decrypt(nonce, encrypted_data)
            .map_err(|e| anyhow::anyhow!("AES-GCM decryption failed: {}", e))?;
        
        Ok(plaintext)
    }
    
    /// Hash public key for identification
    fn hash_public_key(&self, public_key: &[u8]) -> Result<String, anyhow::Error> {
        use sha2::{Digest, Sha256};
        
        let hash = Sha256::digest(public_key);
        Ok(hex::encode(hash))
    }
    
    /// Hash data for integrity verification
    fn hash_data(&self, data: &[u8]) -> Result<String, anyhow::Error> {
        use sha2::{Digest, Sha256};
        
        let hash = Sha256::digest(data);
        Ok(hex::encode(hash))
    }
    
    /// Get quantum cryptography statistics for monitoring
    pub fn get_stats(&self) -> HashMap<String, serde_json::Value> {
        let mut stats = HashMap::new();
        
        stats.insert("fips_compliant".to_string(), serde_json::Value::Bool(self.fips_compliant));
        stats.insert("algorithm_suite".to_string(), serde_json::Value::String(self.algorithm_suite.clone()));
        stats.insert("kyber_ready".to_string(), serde_json::Value::Bool(self.kyber_public_key.is_some()));
        stats.insert("dilithium_ready".to_string(), serde_json::Value::Bool(self.dilithium_public_key.is_some()));
        stats.insert("sphincs_ready".to_string(), serde_json::Value::Bool(self.sphincs_public_key.is_some()));
        stats.insert("nist_level".to_string(), serde_json::Value::Number(5.into()));
        
        stats
    }
    
    /// Export public keys for secure communication
    pub fn export_public_keys(&self) -> Result<HashMap<String, Vec<u8>>, anyhow::Error> {
        let mut keys = HashMap::new();
        
        if let Some(kyber_pk) = &self.kyber_public_key {
            keys.insert("kyber-1024".to_string(), kyber_pk.as_bytes().to_vec());
        }
        
        if let Some(dilithium_pk) = &self.dilithium_public_key {
            keys.insert("dilithium-5".to_string(), dilithium_pk.as_bytes().to_vec());
        }
        
        if let Some(sphincs_pk) = &self.sphincs_public_key {
            keys.insert("sphincs-shake256".to_string(), sphincs_pk.as_bytes().to_vec());
        }
        
        Ok(keys)
    }
}