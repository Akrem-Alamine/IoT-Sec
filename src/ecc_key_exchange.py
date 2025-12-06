"""
ECC Key Exchange using Curve25519 (ECDH)
Implements secure key exchange between two parties
"""

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
import os


class ECCKeyExchange:
    """
    Implements ECDH key exchange using Curve25519
    for secure symmetric key establishment
    """

    def __init__(self):
        """Initialize with a new private key"""
        self.private_key = x25519.X25519PrivateKey.generate()
        self.peer_public_key = None

    def get_public_key(self) -> bytes:
        """
        Get the public key to share with the peer
        
        Returns:
            bytes: The public key in raw format
        """
        public_key = self.private_key.public_key()
        return public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def set_peer_public_key(self, peer_public_key_bytes: bytes) -> None:
        """
        Set the peer's public key for shared secret generation
        
        Args:
            peer_public_key_bytes: The peer's public key in raw format
        """
        self.peer_public_key = x25519.X25519PublicKey.from_public_bytes(
            peer_public_key_bytes
        )

    def derive_shared_secret(self) -> bytes:
        """
        Derive the shared secret using ECDH
        
        Returns:
            bytes: The 32-byte shared secret
            
        Raises:
            ValueError: If peer public key is not set
        """
        if self.peer_public_key is None:
            raise ValueError("Peer public key must be set first")
        
        shared_secret = self.private_key.exchange(self.peer_public_key)
        return shared_secret

    @staticmethod
    def generate_key_pair():
        """
        Generate a new ECC key pair (static method)
        
        Returns:
            tuple: (private_key_bytes, public_key_bytes)
        """
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        return private_key_bytes, public_key_bytes

    @staticmethod
    def perform_key_exchange(private_key_bytes: bytes, peer_public_key_bytes: bytes) -> bytes:
        """
        Perform key exchange with raw key bytes (static method)
        
        Args:
            private_key_bytes: The private key in raw format
            peer_public_key_bytes: The peer's public key in raw format
            
        Returns:
            bytes: The 32-byte shared secret
        """
        private_key = x25519.X25519PrivateKey.from_private_bytes(private_key_bytes)
        peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_key_bytes)
        shared_secret = private_key.exchange(peer_public_key)
        return shared_secret


class KeyExchangeSession:
    """
    Manages a complete key exchange session between two parties
    """

    def __init__(self, party_id: str):
        """
        Initialize a key exchange session
        
        Args:
            party_id: Identifier for this party (e.g., 'Alice', 'Bob')
        """
        self.party_id = party_id
        self.ecc = ECCKeyExchange()
        self.shared_secret = None

    def get_public_key(self) -> bytes:
        """Get this party's public key to send to the peer"""
        return self.ecc.get_public_key()

    def establish_secret(self, peer_public_key: bytes) -> bytes:
        """
        Establish the shared secret with the peer's public key
        
        Args:
            peer_public_key: The peer's public key
            
        Returns:
            bytes: The established shared secret (32 bytes)
        """
        self.ecc.set_peer_public_key(peer_public_key)
        self.shared_secret = self.ecc.derive_shared_secret()
        return self.shared_secret

    def get_secret_digest(self, length: int = 32) -> bytes:
        """
        Get a digest of the shared secret (useful for deriving AES keys)
        
        Args:
            length: The desired length of the digest (default 32 for 256-bit)
            
        Returns:
            bytes: The secret digest truncated to the desired length
        """
        if self.shared_secret is None:
            raise ValueError("Shared secret not yet established")
        return self.shared_secret[:length]
