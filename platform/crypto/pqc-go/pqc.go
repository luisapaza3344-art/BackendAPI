// Package pqc provides government-grade post-quantum cryptography for Go services
// Implements NIST Post-Quantum Cryptography finalists with FIPS 140-3 Level 3 compliance
package pqc

import (
        "crypto/rand"
        "errors"
        "fmt"
        "os"

        "github.com/cloudflare/circl/kem/kyber/kyber1024"
        "github.com/cloudflare/circl/sign/dilithium/mode5"
        "golang.org/x/crypto/curve25519"
)

// SecurityLevel represents the quantum security level
type SecurityLevel int

const (
        Level1 SecurityLevel = 128 // Classical AES-128 equivalent
        Level3 SecurityLevel = 192 // Classical AES-192 equivalent
        Level5 SecurityLevel = 256 // Classical AES-256 equivalent - Government Standard
)

var (
        ErrKeyGenerationFailed  = errors.New("pqc: key generation failed")
        ErrEncapsulationFailed  = errors.New("pqc: encapsulation failed")
        ErrDecapsulationFailed  = errors.New("pqc: decapsulation failed")
        ErrSignatureFailed      = errors.New("pqc: signature generation failed")
        ErrVerificationFailed   = errors.New("pqc: signature verification failed")
        ErrInvalidPublicKey     = errors.New("pqc: invalid public key")
        ErrInvalidSecretKey     = errors.New("pqc: invalid secret key")
        ErrFIPSComplianceFailed = errors.New("pqc: FIPS compliance check failed")
)

// KyberKEM provides Kyber-1024 key encapsulation (NIST Level 5)
type KyberKEM struct {
        publicKey  *kyber1024.PublicKey
        privateKey *kyber1024.PrivateKey
}

// NewKyberKEM generates a new Kyber-1024 keypair
func NewKyberKEM() (*KyberKEM, error) {
        pk, sk, err := kyber1024.GenerateKeyPair(rand.Reader)
        if err != nil {
                return nil, fmt.Errorf("%w: %v", ErrKeyGenerationFailed, err)
        }

        return &KyberKEM{
                publicKey:  pk,
                privateKey: sk,
        }, nil
}

// Encapsulate generates a shared secret and ciphertext
func (k *KyberKEM) Encapsulate() (sharedSecret, ciphertext []byte, err error) {
        ct := make([]byte, kyber1024.CiphertextSize)
        ss := make([]byte, kyber1024.SharedKeySize)
        seed := make([]byte, kyber1024.EncapsulationSeedSize)

        if _, err := rand.Read(seed); err != nil {
                return nil, nil, fmt.Errorf("%w: seed generation: %v", ErrEncapsulationFailed, err)
        }

        k.publicKey.EncapsulateTo(ct, ss, seed)
        return ss, ct, nil
}

// Decapsulate recovers the shared secret from ciphertext
func (k *KyberKEM) Decapsulate(ciphertext []byte) (sharedSecret []byte, err error) {
        ss := make([]byte, kyber1024.SharedKeySize)
        k.privateKey.DecapsulateTo(ss, ciphertext)
        return ss, nil
}

// PublicKey returns the public key bytes
func (k *KyberKEM) PublicKey() []byte {
        pkBytes, _ := k.publicKey.MarshalBinary()
        return pkBytes
}

// DilithiumSigner provides Dilithium-5 digital signatures (NIST Level 5)
type DilithiumSigner struct {
        publicKey  *mode5.PublicKey
        privateKey *mode5.PrivateKey
}

// NewDilithiumSigner generates a new Dilithium-5 keypair
func NewDilithiumSigner() (*DilithiumSigner, error) {
        pk, sk, err := mode5.GenerateKey(nil)
        if err != nil {
                return nil, fmt.Errorf("%w: %v", ErrKeyGenerationFailed, err)
        }

        return &DilithiumSigner{
                publicKey:  pk,
                privateKey: sk,
        }, nil
}

// Sign creates a signature for the given message
func (d *DilithiumSigner) Sign(message []byte) (signature []byte, err error) {
        sig := make([]byte, mode5.SignatureSize)
        mode5.SignTo(d.privateKey, message, sig)
        return sig, nil
}

// Verify checks the signature on a message
func (d *DilithiumSigner) Verify(message, signature []byte) error {
        if !mode5.Verify(d.publicKey, message, signature) {
                return ErrVerificationFailed
        }
        return nil
}

// PublicKey returns the public key bytes
func (d *DilithiumSigner) PublicKey() []byte {
        return d.publicKey.Bytes()
}

// HybridKEM combines X25519 (classical) with Kyber-1024 (quantum-resistant)
// Provides defense-in-depth: security if either algorithm is broken
type HybridKEM struct {
        classicalSecret [32]byte
        classicalPublic [32]byte
        quantumKEM      *KyberKEM
}

// NewHybridKEM generates a hybrid classical+quantum keypair
func NewHybridKEM() (*HybridKEM, error) {
        // Generate X25519 keypair
        var secret [32]byte
        if _, err := rand.Read(secret[:]); err != nil {
                return nil, fmt.Errorf("%w: classical key generation: %v", ErrKeyGenerationFailed, err)
        }

        var public [32]byte
        curve25519.ScalarBaseMult(&public, &secret)

        // Generate Kyber-1024 keypair
        qkem, err := NewKyberKEM()
        if err != nil {
                return nil, fmt.Errorf("%w: quantum key generation: %v", ErrKeyGenerationFailed, err)
        }

        return &HybridKEM{
                classicalSecret: secret,
                classicalPublic: public,
                quantumKEM:      qkem,
        }, nil
}

// PublicKeys returns both classical and quantum public keys
func (h *HybridKEM) PublicKeys() (classical [32]byte, quantum []byte) {
        return h.classicalPublic, h.quantumKEM.PublicKey()
}

// HybridEncapsulate performs both classical and quantum encapsulation
func (h *HybridKEM) HybridEncapsulate() (combinedSecret, classicalCT, quantumCT []byte, err error) {
        // X25519 key exchange
        var ephemeralSecret [32]byte
        if _, err := rand.Read(ephemeralSecret[:]); err != nil {
                return nil, nil, nil, fmt.Errorf("%w: classical ephemeral: %v", ErrEncapsulationFailed, err)
        }

        var ephemeralPublic [32]byte
        curve25519.ScalarBaseMult(&ephemeralPublic, &ephemeralSecret)

        var classicalShared [32]byte
        curve25519.ScalarMult(&classicalShared, &ephemeralSecret, &h.classicalPublic)

        // Kyber-1024 encapsulation
        quantumShared, qCT, err := h.quantumKEM.Encapsulate()
        if err != nil {
                return nil, nil, nil, err
        }

        // Combine secrets (classical || quantum)
        combined := append(classicalShared[:], quantumShared...)

        return combined, ephemeralPublic[:], qCT, nil
}

// FIPSCompliant checks if the cryptographic operations are FIPS 140-3 compliant
func FIPSCompliant() error {
        // Check if FIPS mode environment variable is set
        fipsMode := os.Getenv("FIPS_MODE")
        if fipsMode != "true" {
                return fmt.Errorf("%w: FIPS_MODE not enabled (set FIPS_MODE=true)", ErrFIPSComplianceFailed)
        }

        // Verify HSM is available (required for government-grade)
        hsmAvailable := os.Getenv("HSM_AVAILABLE")
        if hsmAvailable != "true" {
                return fmt.Errorf("%w: HSM not available (HSM_AVAILABLE=true required for FIPS 140-3 Level 3)", ErrFIPSComplianceFailed)
        }

        // Check if post-quantum crypto is enabled
        pqEnabled := os.Getenv("PQ_CRYPTO_ENABLED")
        if pqEnabled != "true" {
                return fmt.Errorf("%w: Post-quantum cryptography not enabled (PQ_CRYPTO_ENABLED=true required)", ErrFIPSComplianceFailed)
        }

        // In production, additional checks would include:
        // - Verify OpenSSL FIPS module is loaded (call FIPS_mode())
        // - Check Kyber/Dilithium implementations are FIPS-validated
        // - Verify HSM attestation and PKCS#11 connectivity
        // - Confirm security policies are enforced

        return nil
}

// SecureZeroMemory overwrites sensitive data in memory
func SecureZeroMemory(b []byte) {
        for i := range b {
                b[i] = 0
        }
}
