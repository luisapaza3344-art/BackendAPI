"""Post-Quantum Cryptography Error Types"""


class PQCError(Exception):
    """Base exception for all PQC operations"""
    pass


class KeyGenerationError(PQCError):
    """Raised when key generation fails"""
    pass


class EncapsulationError(PQCError):
    """Raised when KEM encapsulation fails"""
    pass


class DecapsulationError(PQCError):
    """Raised when KEM decapsulation fails"""
    pass


class SignatureError(PQCError):
    """Raised when signature generation fails"""
    pass


class VerificationError(PQCError):
    """Raised when signature verification fails"""
    pass


class FIPSComplianceError(PQCError):
    """Raised when FIPS compliance check fails"""
    pass
