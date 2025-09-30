"""Kyber-1024 Key Encapsulation Mechanism (NIST Level 5 Security)"""

import oqs
from typing import Tuple
from .errors import KeyGenerationError, EncapsulationError, DecapsulationError


class KyberKEM:
    """
    Kyber-1024 KEM providing quantum-resistant key encapsulation.
    
    Security Level: NIST Level 5 (256-bit quantum security)
    Equivalent to: AES-256 against quantum attacks
    """
    
    ALGORITHM = "Kyber1024"
    
    def __init__(self):
        """Initialize Kyber-1024 KEM"""
        try:
            self._kem = oqs.KeyEncapsulation(self.ALGORITHM)
        except Exception as e:
            raise KeyGenerationError(f"Failed to initialize Kyber-1024: {e}")
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a new Kyber-1024 keypair.
        
        Returns:
            Tuple[bytes, bytes]: (public_key, secret_key)
        
        Raises:
            KeyGenerationError: If key generation fails
        """
        try:
            public_key = self._kem.generate_keypair()
            secret_key = self._kem.export_secret_key()
            return (public_key, secret_key)
        except Exception as e:
            raise KeyGenerationError(f"Kyber keypair generation failed: {e}")
    
    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulate a shared secret using the public key.
        
        Args:
            public_key: Kyber-1024 public key
            
        Returns:
            Tuple[bytes, bytes]: (ciphertext, shared_secret)
            
        Raises:
            EncapsulationError: If encapsulation fails
        """
        try:
            ciphertext, shared_secret = self._kem.encap_secret(public_key)
            return (ciphertext, shared_secret)
        except Exception as e:
            raise EncapsulationError(f"Kyber encapsulation failed: {e}")
    
    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """
        Decapsulate the shared secret using the secret key.
        
        Args:
            secret_key: Kyber-1024 secret key
            ciphertext: Encapsulated ciphertext
            
        Returns:
            bytes: Shared secret
            
        Raises:
            DecapsulationError: If decapsulation fails
        """
        try:
            shared_secret = self._kem.decap_secret(ciphertext)
            return shared_secret
        except Exception as e:
            raise DecapsulationError(f"Kyber decapsulation failed: {e}")
    
    @property
    def public_key_size(self) -> int:
        """Get public key size in bytes"""
        return self._kem.details['length_public_key']
    
    @property
    def secret_key_size(self) -> int:
        """Get secret key size in bytes"""
        return self._kem.details['length_secret_key']
    
    @property
    def ciphertext_size(self) -> int:
        """Get ciphertext size in bytes"""
        return self._kem.details['length_ciphertext']
    
    @property
    def shared_secret_size(self) -> int:
        """Get shared secret size in bytes"""
        return self._kem.details['length_shared_secret']
