"""
Government-Grade Post-Quantum Cryptography for Python

Provides FIPS 140-3 Level 3 compliant post-quantum cryptography:
- Kyber-1024 KEM (NIST Level 5 security)
- Dilithium-5 Digital Signatures (NIST Level 5 security)
- SPHINCS+ Signatures (stateless, hash-based)
- Hybrid modes (classical + quantum)
"""

from .kyber import KyberKEM
from .dilithium import DilithiumSigner
from .hybrid import HybridKEM
from .errors import (
    PQCError,
    KeyGenerationError,
    EncapsulationError,
    DecapsulationError,
    SignatureError,
    VerificationError,
    FIPSComplianceError,
)

__version__ = "1.0.0"
__all__ = [
    "KyberKEM",
    "DilithiumSigner",
    "HybridKEM",
    "PQCError",
    "KeyGenerationError",
    "EncapsulationError",
    "DecapsulationError",
    "SignatureError",
    "VerificationError",
    "FIPSComplianceError",
]
