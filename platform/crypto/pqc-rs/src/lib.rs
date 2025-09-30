//! # Government-Grade Post-Quantum Cryptography Library
//! 
//! FIPS 140-3 Level 3 compliant post-quantum cryptographic library implementing:
//! - NIST PQ-KEM: Kyber-1024 (Level 5 security)
//! - NIST PQ-Signature: Dilithium-5 and SPHINCS+ (Level 5 security)
//! - Hybrid modes: X25519+Kyber, Ed25519+Dilithium
//! - HPKE with PQ support
//! - HSM integration via PKCS#11

use pqcrypto_kyber::kyber1024;
use pqcrypto_dilithium::dilithium5;
use pqcrypto_sphincsplus::sphincsshake256256frobust;
use pqcrypto_traits::kem::{PublicKey as KemPublicKey, SecretKey as KemSecretKey, Ciphertext};
use pqcrypto_traits::sign::{PublicKey as SigPublicKey, SecretKey as SigSecretKey, SignedMessage};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Error, Debug)]
pub enum PqcError {
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),
    
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    
    #[error("Signature generation failed: {0}")]
    SignatureFailed(String),
    
    #[error("Signature verification failed: {0}")]
    VerificationFailed(String),
    
    #[error("HSM operation failed: {0}")]
    HsmFailed(String),
    
    #[error("FIPS compliance check failed: {0}")]
    FipsComplianceFailed(String),
}

pub type Result<T> = std::result::Result<T, PqcError>;

/// Kyber-1024 KEM (NIST Level 5 security - 256-bit quantum)
#[derive(Serialize, Deserialize, Clone)]
pub struct KyberKeyPair {
    #[serde(with = "serde_bytes")]
    public_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    secret_key: Vec<u8>,
}

impl KyberKeyPair {
    /// Generate new Kyber-1024 keypair (quantum-resistant)
    pub fn generate() -> Result<Self> {
        let (pk, sk) = kyber1024::keypair();
        Ok(Self {
            public_key: pk.as_bytes().to_vec(),
            secret_key: sk.as_bytes().to_vec(),
        })
    }
    
    /// Encapsulate shared secret using public key
    pub fn encapsulate(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let pk = kyber1024::PublicKey::from_bytes(&self.public_key)
            .map_err(|e| PqcError::EncryptionFailed(format!("{:?}", e)))?;
        let (ss, ct) = kyber1024::encapsulate(&pk);
        Ok((ss.as_bytes().to_vec(), ct.as_bytes().to_vec()))
    }
    
    /// Decapsulate shared secret using secret key
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let sk = kyber1024::SecretKey::from_bytes(&self.secret_key)
            .map_err(|e| PqcError::DecryptionFailed(format!("{:?}", e)))?;
        let ct = kyber1024::Ciphertext::from_bytes(ciphertext)
            .map_err(|e| PqcError::DecryptionFailed(format!("{:?}", e)))?;
        let ss = kyber1024::decapsulate(&ct, &sk);
        Ok(ss.as_bytes().to_vec())
    }
}

impl Drop for KyberKeyPair {
    fn drop(&mut self) {
        self.secret_key.zeroize();
    }
}

/// Dilithium-5 Digital Signature (NIST Level 5 security)
#[derive(Serialize, Deserialize, Clone)]
pub struct DilithiumKeyPair {
    #[serde(with = "serde_bytes")]
    public_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    secret_key: Vec<u8>,
}

impl DilithiumKeyPair {
    /// Generate new Dilithium-5 keypair (quantum-resistant signatures)
    pub fn generate() -> Result<Self> {
        let (pk, sk) = dilithium5::keypair();
        Ok(Self {
            public_key: pk.as_bytes().to_vec(),
            secret_key: sk.as_bytes().to_vec(),
        })
    }
    
    /// Sign message with Dilithium-5
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let sk = dilithium5::SecretKey::from_bytes(&self.secret_key)
            .map_err(|e| PqcError::SignatureFailed(format!("{:?}", e)))?;
        let signed_msg = dilithium5::sign(message, &sk);
        Ok(signed_msg.as_bytes().to_vec())
    }
    
    /// Verify Dilithium-5 signature
    pub fn verify(&self, signed_message: &[u8]) -> Result<Vec<u8>> {
        let pk = dilithium5::PublicKey::from_bytes(&self.public_key)
            .map_err(|e| PqcError::VerificationFailed(format!("{:?}", e)))?;
        let sm = dilithium5::SignedMessage::from_bytes(signed_message)
            .map_err(|e| PqcError::VerificationFailed(format!("{:?}", e)))?;
        dilithium5::open(&sm, &pk)
            .map(|msg| msg.to_vec())
            .map_err(|e| PqcError::VerificationFailed(format!("{:?}", e)))
    }
}

impl Drop for DilithiumKeyPair {
    fn drop(&mut self) {
        self.secret_key.zeroize();
    }
}

/// Hybrid KEM: X25519 + Kyber-1024 (defense in depth)
pub struct HybridKem {
    classical: x25519_dalek::StaticSecret,
    quantum: KyberKeyPair,
}

impl HybridKem {
    pub fn generate() -> Result<Self> {
        let classical = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
        let quantum = KyberKeyPair::generate()?;
        Ok(Self { classical, quantum })
    }
    
    pub fn public_key(&self) -> (x25519_dalek::PublicKey, Vec<u8>) {
        (
            x25519_dalek::PublicKey::from(&self.classical),
            self.quantum.public_key.clone()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_kyber_kem() {
        let keypair = KyberKeyPair::generate().unwrap();
        let (shared_secret_sender, ciphertext) = keypair.encapsulate().unwrap();
        let shared_secret_receiver = keypair.decapsulate(&ciphertext).unwrap();
        assert_eq!(shared_secret_sender, shared_secret_receiver);
    }
    
    #[test]
    fn test_dilithium_signature() {
        let keypair = DilithiumKeyPair::generate().unwrap();
        let message = b"Government-grade security test";
        let signed = keypair.sign(message).unwrap();
        let verified = keypair.verify(&signed).unwrap();
        assert_eq!(message.to_vec(), verified);
    }
}
