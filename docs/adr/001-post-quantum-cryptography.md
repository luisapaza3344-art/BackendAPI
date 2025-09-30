# ADR 001: Post-Quantum Cryptography Implementation

**Status**: Accepted  
**Date**: 2025-09-27  
**Decision Makers**: Security Team, Architecture Team  
**Compliance**: FIPS 140-3 Level 3, NIST Post-Quantum Cryptography

## Context
The advent of large-scale quantum computers poses an existential threat to current public-key cryptography (RSA, ECC). Government agencies and financial institutions must prepare for the "Q-Day" when quantum computers can break current encryption in polynomial time.

### Threat Landscape
- **Shor's Algorithm**: Breaks RSA-2048 and ECC-256 in polynomial time
- **Grover's Algorithm**: Reduces symmetric key strength by half (AES-256 → AES-128 equivalent)
- **Harvest Now, Decrypt Later (HNDL)**: Adversaries capture encrypted data today to decrypt with future quantum computers

### Timeline
- **2025-2030**: Quantum computers reaching cryptographically relevant scale
- **2024**: NIST finalizes Post-Quantum Cryptography standards
- **Government Mandate**: Migrate to PQC by 2030

## Decision
We will implement **NIST-approved Post-Quantum Cryptography** across all services, using a **hybrid approach** (classical + quantum-resistant) for defense-in-depth.

### Selected Algorithms
| Purpose | Algorithm | Security Level | Status |
|---------|-----------|----------------|--------|
| Key Encapsulation | **Kyber-1024** | NIST Level 5 (256-bit quantum) | ✅ Primary |
| Digital Signatures | **Dilithium-5** | NIST Level 5 (256-bit quantum) | ✅ Primary |
| Hash-based Signatures | **SPHINCS+** | NIST Level 5 (stateless) | ✅ Secondary |
| Hybrid KEM | **X25519 + Kyber-1024** | Defense-in-depth | ✅ Enabled |
| Hybrid Signatures | **Ed25519 + Dilithium-5** | Defense-in-depth | ✅ Enabled |

### Implementation Strategy
1. **Shared Libraries**: Centralized PQC libraries in `platform/crypto/`
   - `pqc-rs`: Rust library with pqcrypto crates
   - `pqc-go`: Go library with Open Quantum Safe (liboqs)
   - `pqc-py`: Python library with oqs-python

2. **Service Integration**: All services consume shared PQC libraries
   - Payment Gateway: Kyber-1024 for card data encryption
   - Auth Service: Dilithium-5 for JWT signatures
   - API Gateway: Hybrid TLS 1.3 (X25519+Kyber)

3. **HSM Integration**: FIPS 140-3 Level 3 HSMs store PQ keys
   - AWS CloudHSM with PKCS#11 interface
   - Post-quantum key generation in HSM
   - Secure key backup with quantum-resistant encryption

## Consequences

### Positive
- **Quantum-Resistant Security**: Protection against future quantum attacks
- **Government-Grade Compliance**: Meets NIST PQC standards
- **Defense-in-Depth**: Hybrid mode provides dual protection
- **Forward Secrecy**: New keys per session prevent retroactive decryption
- **Audit Trail**: Blockchain-anchored logs with PQ signatures

### Negative
- **Performance Overhead**: PQ operations are slower than classical crypto
  - Kyber-1024 encapsulation: ~0.5ms (vs ~0.1ms for X25519)
  - Dilithium-5 signature: ~2ms (vs ~0.3ms for Ed25519)
- **Larger Keys/Signatures**: Increased bandwidth requirements
  - Kyber-1024 public key: 1,568 bytes (vs 32 bytes for X25519)
  - Dilithium-5 signature: 4,595 bytes (vs 64 bytes for Ed25519)
- **Library Maturity**: Some PQ implementations are newer (careful vetting required)

### Mitigations
- **Caching**: Cache PQ public keys to reduce key exchange overhead
- **Compression**: Use efficient encoding for PQ signatures
- **Batching**: Batch signature verifications when possible
- **Hardware Acceleration**: Use AVX2/AVX-512 optimized implementations

## Alternatives Considered

### 1. Continue with Classical Cryptography
**Rejected**: Vulnerable to quantum attacks; fails government compliance requirements.

### 2. Quantum Key Distribution (QKD)
**Partial Adoption**: QKD provides perfect forward secrecy but requires specialized hardware. We will use QKD for inter-datacenter links but rely on PQC for general use.

### 3. Hash-Based Signatures Only (SPHINCS+)
**Rejected**: SPHINCS+ signatures are very large (49KB). Dilithium-5 provides better performance with comparable security.

## Implementation Plan

### Phase 1: Foundation (Completed ✅)
- [x] Create `platform/crypto/` with PQC libraries
- [x] Implement Kyber-1024 KEM in Rust, Go, Python
- [x] Implement Dilithium-5 signatures in Rust, Go, Python
- [x] Add hybrid modes (X25519+Kyber, Ed25519+Dilithium)

### Phase 2: Service Integration (In Progress 🟡)
- [x] Payment Gateway: Encrypt card data with Kyber-1024
- [x] Auth Service: Sign JWTs with Dilithium-5
- [ ] API Gateway: Enable hybrid TLS 1.3
- [ ] All Services: Use PQC for inter-service communication

### Phase 3: HSM Integration (Pending ⏳)
- [ ] Configure AWS CloudHSM for PQ key generation
- [ ] Implement PKCS#11 interface for PQC operations
- [ ] Secure key backup with quantum-resistant encryption

### Phase 4: Audit & Compliance (Pending ⏳)
- [ ] FIPS 140-3 validation of PQC implementations
- [ ] NIST PQC compliance audit
- [ ] Government certification process

## Monitoring & Success Metrics
- **PQC Adoption Rate**: Percentage of requests using PQC (Target: 100%)
- **Performance Impact**: P95 latency increase (Target: <10%)
- **Security Incidents**: Zero successful quantum attacks
- **Compliance Status**: FIPS 140-3 Level 3 certified

## References
- [NIST Post-Quantum Cryptography Project](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [FIPS 140-3 Standard](https://csrc.nist.gov/publications/detail/fips/140/3/final)
- [Open Quantum Safe Project](https://openquantumsafe.org/)
- [Kyber Specification](https://pq-crystals.org/kyber/)
- [Dilithium Specification](https://pq-crystals.org/dilithium/)

## Approval
- **Architecture Team**: ✅ Approved
- **Security Team**: ✅ Approved
- **Compliance Officer**: ✅ Approved
- **CTO**: ✅ Approved
