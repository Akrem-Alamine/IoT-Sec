"""
AES-128 Encryption and Decryption Module
Implements AES-128 in CBC mode for image encryption
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os


class AESCipher:
    """
    Implements AES-128 encryption and decryption in CBC mode
    """

    def __init__(self, key: bytes = None):
        """
        Initialize AES cipher with a given key or generate a new one
        
        Args:
            key: 16-byte (128-bit) AES key. If None, generates a random key.
        """
        if key is None:
            self.key = os.urandom(16)  # 128-bit key
        elif len(key) == 16:
            self.key = key
        else:
            raise ValueError(f"Key must be 16 bytes (128-bit), got {len(key)} bytes")
        
        self.backend = default_backend()

    @staticmethod
    def generate_key() -> bytes:
        """
        Generate a random 128-bit AES key
        
        Returns:
            bytes: 16-byte key
        """
        return os.urandom(16)

    @staticmethod
    def derive_key_from_password(password: str, salt: bytes = None) -> tuple:
        """
        Derive an AES key from a password using PBKDF2
        
        Args:
            password: The password string
            salt: Optional salt bytes. If None, generates a random salt.
            
        Returns:
            tuple: (derived_key, salt)
        """
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=16,  # 128-bit key
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        
        key = kdf.derive(password.encode())
        return key, salt

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt plaintext using AES-128 in CBC mode
        
        Args:
            plaintext: The data to encrypt (must be multiple of 16 bytes)
            
        Returns:
            bytes: IV (16 bytes) + ciphertext
        """
        # Generate random IV
        iv = os.urandom(16)
        
        # Pad plaintext to multiple of 16 bytes if needed
        padded_plaintext = self._pad(plaintext)
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=self.backend
        )
        
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        
        # Return IV + ciphertext (IV needed for decryption)
        return iv + ciphertext

    def decrypt(self, encrypted_data: bytes) -> bytes:
        """
        Decrypt AES-128 encrypted data in CBC mode
        
        Args:
            encrypted_data: The encrypted data (IV + ciphertext)
            
        Returns:
            bytes: The decrypted plaintext
        """
        # Extract IV (first 16 bytes) and ciphertext (rest)
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=self.backend
        )
        
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        plaintext = self._unpad(padded_plaintext)
        return plaintext

    @staticmethod
    def _pad(data: bytes) -> bytes:
        """
        Apply PKCS7 padding to data
        
        Args:
            data: The data to pad
            
        Returns:
            bytes: Padded data
        """
        padding_length = 16 - (len(data) % 16)
        padding = bytes([padding_length] * padding_length)
        return data + padding

    @staticmethod
    def _unpad(data: bytes) -> bytes:
        """
        Remove PKCS7 padding from data
        
        Args:
            data: The padded data
            
        Returns:
            bytes: Unpadded data
        """
        padding_length = data[-1]
        return data[:-padding_length]

    def get_key(self) -> bytes:
        """Get the current AES key"""
        return self.key

    def set_key(self, key: bytes) -> None:
        """
        Set a new AES key
        
        Args:
            key: 16-byte key
        """
        if len(key) != 16:
            raise ValueError(f"Key must be 16 bytes (128-bit), got {len(key)} bytes")
        self.key = key


class ImageAESCipher:
    """
    Specialized AES cipher for image data
    Handles image-specific encryption requirements
    """

    def __init__(self, key: bytes = None):
        """
        Initialize image cipher
        
        Args:
            key: AES key (16 bytes for AES-128)
        """
        self.cipher = AESCipher(key)

    def encrypt_image_data(self, image_bytes: bytes) -> tuple:
        """
        Encrypt image data
        
        Args:
            image_bytes: Raw image bytes
            
        Returns:
            tuple: (encrypted_data, key) where key can be used for decryption
        """
        encrypted = self.cipher.encrypt(image_bytes)
        return encrypted, self.cipher.get_key()

    def decrypt_image_data(self, encrypted_data: bytes, key: bytes) -> bytes:
        """
        Decrypt image data
        
        Args:
            encrypted_data: The encrypted image data (IV + ciphertext)
            key: The AES key used for encryption
            
        Returns:
            bytes: The decrypted image data
        """
        cipher = AESCipher(key)
        return cipher.decrypt(encrypted_data)

    def set_key(self, key: bytes) -> None:
        """Set the AES key"""
        self.cipher.set_key(key)

    def get_key(self) -> bytes:
        """Get the current AES key"""
        return self.cipher.get_key()
