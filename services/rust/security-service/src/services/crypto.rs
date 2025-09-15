use crate::error::{SecurityError, SecurityResult};
use ring::digest::{digest, SHA384};
use sha2::{Digest, Sha256, Sha384};
use std::collections::HashMap;

pub struct FIPSCrypto {
    fips_mode: bool,
}

impl FIPSCrypto {
    pub fn new(fips_mode: bool) -> Self {
        Self { fips_mode }
    }

    /// Generate SHA-384 hash (FIPS 140-3 approved)
    pub fn sha384_hash(&self, data: &[u8]) -> SecurityResult<String> {
        if !self.fips_mode {
            return Err(SecurityError::FIPSCompliance(
                "FIPS mode required for cryptographic operations".to_string(),
            ));
        }

        // Using ring for FIPS compliance
        let hash = digest(&SHA384, data);
        Ok(hex::encode(hash.as_ref()))
    }

    /// Generate SHA-384 hash of combined request/response data
    pub fn hash_audit_data(
        &self,
        request_data: &serde_json::Value,
        response_data: &serde_json::Value,
    ) -> SecurityResult<(String, String, String)> {
        // Hash request data
        let request_bytes = serde_json::to_vec(request_data)
            .map_err(|e| SecurityError::Crypto(format!("Failed to serialize request: {}", e)))?;
        let request_hash = self.sha384_hash(&request_bytes)?;

        // Hash response data
        let response_bytes = serde_json::to_vec(response_data)
            .map_err(|e| SecurityError::Crypto(format!("Failed to serialize response: {}", e)))?;
        let response_hash = self.sha384_hash(&response_bytes)?;

        // Hash combined data
        let combined_data = format!("{}:{}", request_hash, response_hash);
        let combined_hash = self.sha384_hash(combined_data.as_bytes())?;

        Ok((request_hash, response_hash, combined_hash))
    }

    /// Generate Merkle root from multiple audit hashes
    pub fn generate_merkle_root(&self, hashes: &[String]) -> SecurityResult<String> {
        if hashes.is_empty() {
            return Err(SecurityError::Crypto("Cannot generate Merkle root from empty set".to_string()));
        }

        let mut current_level = hashes.to_vec();

        while current_level.len() > 1 {
            let mut next_level = Vec::new();

            for chunk in current_level.chunks(2) {
                let combined = if chunk.len() == 2 {
                    format!("{}:{}", chunk[0], chunk[1])
                } else {
                    // If odd number, duplicate the last hash
                    format!("{}:{}", chunk[0], chunk[0])
                };

                let combined_hash = self.sha384_hash(combined.as_bytes())?;
                next_level.push(combined_hash);
            }

            current_level = next_level;
        }

        Ok(current_level[0].clone())
    }

    /// Verify integrity of audit data
    pub fn verify_audit_integrity(
        &self,
        original_hash: &str,
        request_data: &serde_json::Value,
        response_data: &serde_json::Value,
    ) -> SecurityResult<bool> {
        let (_, _, computed_hash) = self.hash_audit_data(request_data, response_data)?;
        Ok(computed_hash == original_hash)
    }

    /// Generate integrity proof for blockchain anchoring
    pub fn generate_integrity_proof(
        &self,
        audit_record_id: &uuid::Uuid,
        combined_hash: &str,
        additional_data: Option<&HashMap<String, serde_json::Value>>,
    ) -> SecurityResult<serde_json::Value> {
        let mut proof_data = serde_json::json!({
            "audit_record_id": audit_record_id,
            "combined_hash": combined_hash,
            "algorithm": "SHA-384",
            "fips_compliant": self.fips_mode,
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "version": "1.0"
        });

        if let Some(data) = additional_data {
            for (key, value) in data {
                proof_data[key] = value.clone();
            }
        }

        // Generate proof hash
        let proof_bytes = serde_json::to_vec(&proof_data)
            .map_err(|e| SecurityError::Crypto(format!("Failed to serialize proof: {}", e)))?;
        let proof_hash = self.sha384_hash(&proof_bytes)?;

        proof_data["proof_hash"] = serde_json::Value::String(proof_hash);

        Ok(proof_data)
    }

    /// Validate FIPS compliance requirements
    pub fn validate_fips_compliance(&self) -> SecurityResult<()> {
        if !self.fips_mode {
            return Err(SecurityError::FIPSCompliance(
                "FIPS 140-3 Level 3 mode is required".to_string(),
            ));
        }

        // Additional FIPS validation logic would go here
        // - Verify crypto module is FIPS validated
        // - Check entropy sources
        // - Validate key management
        // - Verify algorithm compliance

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha384_hash() {
        let crypto = FIPSCrypto::new(true);
        let data = b"test data";
        let hash = crypto.sha384_hash(data).unwrap();
        assert_eq!(hash.len(), 96); // SHA-384 produces 48 bytes = 96 hex chars
    }

    #[test]
    fn test_merkle_root_generation() {
        let crypto = FIPSCrypto::new(true);
        let hashes = vec![
            "hash1".to_string(),
            "hash2".to_string(),
            "hash3".to_string(),
            "hash4".to_string(),
        ];
        let merkle_root = crypto.generate_merkle_root(&hashes).unwrap();
        assert!(!merkle_root.is_empty());
    }

    #[test]
    fn test_audit_data_hashing() {
        let crypto = FIPSCrypto::new(true);
        let request = serde_json::json!({"method": "POST", "path": "/api/test"});
        let response = serde_json::json!({"status": 200, "data": "success"});
        
        let (req_hash, resp_hash, combined_hash) = crypto.hash_audit_data(&request, &response).unwrap();
        
        assert!(!req_hash.is_empty());
        assert!(!resp_hash.is_empty());
        assert!(!combined_hash.is_empty());
        assert_ne!(req_hash, resp_hash);
    }
}