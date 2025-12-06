"""
Main Application Module
CLI interface for image encryption/decryption with ECC key exchange
"""

import argparse
import sys
import os
from pathlib import Path
import json
from typing import Optional

# Import project modules
from src.ecc_key_exchange import ECCKeyExchange, KeyExchangeSession
from src.aes_cipher import AESCipher, ImageAESCipher
from src.image_processor import ImageProcessor
from src.metrics import ImageQualityMetrics


class ImageEncryptionApp:
    """
    Main application for image encryption/decryption
    """

    def __init__(self, key: Optional[bytes] = None):
        """
        Initialize the application
        
        Args:
            key: Optional AES key (16 bytes). If None, will generate a new one.
        """
        if key is None:
            self.cipher = ImageAESCipher(AESCipher.generate_key())
        else:
            self.cipher = ImageAESCipher(key)

    def encrypt_image(self, input_image_path: str, output_encrypted_path: str) -> dict:
        """
        Encrypt an image file
        
        Args:
            input_image_path: Path to the original image
            output_encrypted_path: Path to save encrypted data
            
        Returns:
            dict: Operation results including key and metadata
        """
        print(f"[*] Loading image from: {input_image_path}")
        image_bytes, metadata = ImageProcessor.load_image(input_image_path)
        
        print(f"[*] Image loaded: {metadata['size']} pixels, mode: {metadata['mode']}")
        print(f"[*] Image size: {len(image_bytes)} bytes")
        
        print(f"[*] Encrypting image with AES-128...")
        encrypted_data, key = self.cipher.encrypt_image_data(image_bytes)
        
        print(f"[*] Encrypted data size: {len(encrypted_data)} bytes")
        
        print(f"[*] Saving encrypted image to: {output_encrypted_path}")
        ImageProcessor.save_encrypted_image(encrypted_data, output_encrypted_path)
        
        # Save metadata alongside encrypted file
        metadata_path = output_encrypted_path.replace('.enc', '.json')
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        return {
            'status': 'success',
            'input_path': input_image_path,
            'output_path': output_encrypted_path,
            'metadata_path': metadata_path,
            'key_hex': key.hex(),
            'key_b64': __import__('base64').b64encode(key).decode(),
            'original_size_bytes': len(image_bytes),
            'encrypted_size_bytes': len(encrypted_data),
            'metadata': metadata
        }

    def decrypt_image(self, input_encrypted_path: str, output_image_path: str, key: bytes, metadata: Optional[dict] = None) -> dict:
        """
        Decrypt an image file
        
        Args:
            input_encrypted_path: Path to the encrypted image file
            output_image_path: Path to save the decrypted image
            key: AES key (16 bytes) used for encryption
            metadata: Optional metadata dict (will try to load from .json if not provided)
            
        Returns:
            dict: Operation results
        """
        print(f"[*] Loading encrypted image from: {input_encrypted_path}")
        encrypted_data = ImageProcessor.load_encrypted_image(input_encrypted_path)
        
        print(f"[*] Encrypted data size: {len(encrypted_data)} bytes")
        
        # Load metadata if not provided
        if metadata is None:
            metadata_path = input_encrypted_path.replace('.enc', '.json')
            if os.path.exists(metadata_path):
                print(f"[*] Loading metadata from: {metadata_path}")
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)
            else:
                print("[!] Warning: No metadata file found. Using default assumptions.")
                metadata = None
        
        print(f"[*] Decrypting image with AES-128...")
        self.cipher.set_key(key)
        decrypted_bytes = self.cipher.decrypt_image_data(encrypted_data, key)
        
        print(f"[*] Decrypted data size: {len(decrypted_bytes)} bytes")
        
        if metadata:
            print(f"[*] Saving decrypted image to: {output_image_path}")
            ImageProcessor.save_image(decrypted_bytes, metadata, output_image_path)
        else:
            # Fallback: save as raw bytes
            print("[!] Cannot reconstruct image without metadata. Saving raw bytes.")
            os.makedirs(os.path.dirname(output_image_path), exist_ok=True)
            with open(output_image_path, 'wb') as f:
                f.write(decrypted_bytes)
        
        return {
            'status': 'success',
            'input_path': input_encrypted_path,
            'output_path': output_image_path,
            'decrypted_size_bytes': len(decrypted_bytes),
            'metadata': metadata
        }

    def evaluate_quality(self, original_image_path: str, decrypted_image_path: str) -> dict:
        """
        Evaluate the quality of the decrypted image
        
        Args:
            original_image_path: Path to the original image
            decrypted_image_path: Path to the decrypted image
            
        Returns:
            dict: Quality metrics (PSNR, MSE, SSIM)
        """
        print(f"[*] Comparing original and decrypted images...")
        metrics = ImageQualityMetrics.compare_images_quality(original_image_path, decrypted_image_path)
        
        print(f"\n=== Image Quality Metrics ===")
        print(f"MSE (Mean Squared Error): {metrics['mse']:.6f}")
        print(f"PSNR (Peak Signal-to-Noise Ratio): {metrics['psnr']} dB")
        print(f"SSIM (Structural Similarity): {metrics['ssim']:.6f}")
        print(f"Images Identical: {metrics['images_identical']}")
        
        return metrics


class KeyExchangeDemo:
    """
    Demonstrates ECDH key exchange between two parties
    """

    @staticmethod
    def run_key_exchange(party_a_name: str = "Alice", party_b_name: str = "Bob") -> dict:
        """
        Run a complete key exchange simulation
        
        Args:
            party_a_name: Name of party A
            party_b_name: Name of party B
            
        Returns:
            dict: Key exchange results
        """
        print(f"\n=== ECC Key Exchange Simulation ({party_a_name} & {party_b_name}) ===\n")
        
        # Initialize both parties
        print(f"[*] {party_a_name} generates a key pair...")
        alice = KeyExchangeSession(party_a_name)
        alice_public = alice.get_public_key()
        print(f"    Public key length: {len(alice_public)} bytes")
        
        print(f"[*] {party_b_name} generates a key pair...")
        bob = KeyExchangeSession(party_b_name)
        bob_public = bob.get_public_key()
        print(f"    Public key length: {len(bob_public)} bytes")
        
        # Exchange public keys
        print(f"\n[*] {party_a_name} and {party_b_name} exchange public keys...")
        alice_secret = alice.establish_secret(bob_public)
        bob_secret = bob.establish_secret(alice_public)
        
        print(f"    Shared secret length: {len(alice_secret)} bytes")
        
        # Verify secrets match
        secrets_match = alice_secret == bob_secret
        print(f"\n[*] Verification: Secrets match = {secrets_match}")
        
        if secrets_match:
            print(f"[+] Key exchange successful!")
        else:
            print(f"[-] Key exchange failed!")
        
        # Derive AES keys from shared secret
        aes_key = alice_secret[:16]  # Use first 16 bytes for AES-128
        
        return {
            'alice_public_key_hex': alice_public.hex(),
            'bob_public_key_hex': bob_public.hex(),
            'shared_secret_hex': alice_secret.hex(),
            'aes_key_hex': aes_key.hex(),
            'secrets_match': secrets_match,
            'status': 'success' if secrets_match else 'failed'
        }


def main():
    """
    Main CLI interface
    """
    parser = argparse.ArgumentParser(
        description='Image Encryption/Decryption using AES-128 with ECC (Curve25519) Key Exchange'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Encrypt command
    encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt an image')
    encrypt_parser.add_argument('image', help='Path to the image file')
    encrypt_parser.add_argument('-o', '--output', help='Output path for encrypted image', default=None)
    encrypt_parser.add_argument('-k', '--key', help='AES key in hex format (optional)', default=None)
    
    # Decrypt command
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt an image')
    decrypt_parser.add_argument('encrypted', help='Path to the encrypted image file')
    decrypt_parser.add_argument('-k', '--key', required=True, help='AES key in hex format')
    decrypt_parser.add_argument('-o', '--output', help='Output path for decrypted image', default=None)
    
    # Metrics command
    metrics_parser = subparsers.add_parser('metrics', help='Calculate image quality metrics')
    metrics_parser.add_argument('original', help='Path to original image')
    metrics_parser.add_argument('decrypted', help='Path to decrypted image')
    
    # Key exchange demo
    subparsers.add_parser('keyexchange', help='Run ECC key exchange demonstration')
    
    # Generate key
    keygen_parser = subparsers.add_parser('keygen', help='Generate a new AES-128 key')
    
    args = parser.parse_args()
    
    if args.command == 'encrypt':
        # Prepare output path
        if args.output is None:
            base_path = os.path.splitext(args.image)[0]
            args.output = f"{base_path}.enc"
        
        # Prepare AES key
        if args.key:
            key = bytes.fromhex(args.key)
        else:
            key = None
        
        app = ImageEncryptionApp(key)
        result = app.encrypt_image(args.image, args.output)
        
        print(f"\n[+] Encryption completed successfully!")
        print(f"[+] Encrypted file: {result['output_path']}")
        print(f"[+] Metadata file: {result['metadata_path']}")
        print(f"[+] AES Key (Hex): {result['key_hex']}")
        print(f"[+] AES Key (Base64): {result['key_b64']}")
        
    elif args.command == 'decrypt':
        # Convert key from hex
        try:
            key = bytes.fromhex(args.key)
        except ValueError:
            print(f"[-] Invalid key format. Please provide key in hexadecimal format.")
            sys.exit(1)
        
        # Prepare output path
        if args.output is None:
            base_path = os.path.splitext(args.encrypted)[0]
            args.output = f"{base_path}_decrypted.png"
        
        app = ImageEncryptionApp(key)
        result = app.decrypt_image(args.encrypted, args.output, key)
        
        print(f"\n[+] Decryption completed successfully!")
        print(f"[+] Decrypted file: {result['output_path']}")
        
    elif args.command == 'metrics':
        metrics = ImageQualityMetrics.compare_images_quality(args.original, args.decrypted)
        print(f"\n[+] Metrics comparison completed!")
        
    elif args.command == 'keyexchange':
        result = KeyExchangeDemo.run_key_exchange()
        print(f"\nDerived AES-128 Key (Hex): {result['aes_key_hex']}")
        
    elif args.command == 'keygen':
        key = AESCipher.generate_key()
        print(f"Generated AES-128 Key")
        print(f"Hex: {key.hex()}")
        print(f"Base64: {__import__('base64').b64encode(key).decode()}")


if __name__ == '__main__':
    main()
