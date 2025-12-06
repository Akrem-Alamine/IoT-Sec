"""
Configuration and Constants
"""

# Project Info
PROJECT_NAME = "Image Encryption/Decryption System"
VERSION = "1.0.0"
AUTHOR = "IoT Security Project"
DESCRIPTION = "AES-128 image encryption with ECC (Curve25519) key exchange"

# Cryptographic Parameters
AES_KEY_SIZE = 16  # 128 bits
AES_BLOCK_SIZE = 16  # 128 bits
IV_SIZE = 16  # 128 bits
ECC_KEY_SIZE = 32  # 256 bits (Curve25519)
SHARED_SECRET_SIZE = 32  # 256 bits

# Image Processing
SUPPORTED_FORMATS = ['PNG', 'JPEG', 'JPG', 'BMP', 'GIF', 'TIFF']
MAX_IMAGE_SIZE_MB = 500  # Maximum recommended image size
DEFAULT_IMAGE_MODE = 'RGB'

# PBKDF2 Parameters for Password-Based Key Derivation
PBKDF2_ITERATIONS = 100000
PBKDF2_SALT_SIZE = 16
PBKDF2_ALGORITHM = 'SHA256'

# File Extensions
ENCRYPTED_EXTENSION = '.enc'
METADATA_EXTENSION = '.json'

# Quality Metrics Thresholds
PERFECT_QUALITY_MSE = 0.0
PERFECT_QUALITY_PSNR = float('inf')
PERFECT_QUALITY_SSIM = 1.0

# Default Output Paths
DEFAULT_OUTPUT_DIR = 'data/output'
DEFAULT_INPUT_DIR = 'data/input'

# CLI Colors for Output (optional for enhancement)
COLORS = {
    'SUCCESS': '\033[92m',      # Green
    'WARNING': '\033[93m',      # Yellow
    'ERROR': '\033[91m',        # Red
    'INFO': '\033[94m',         # Blue
    'RESET': '\033[0m'          # Reset
}

# Error Messages
ERROR_MESSAGES = {
    'INVALID_KEY_LENGTH': 'Key must be {expected} bytes, got {actual}',
    'FILE_NOT_FOUND': 'File not found: {path}',
    'INVALID_IMAGE': 'Invalid or corrupted image: {path}',
    'ENCRYPTION_FAILED': 'Encryption failed: {error}',
    'DECRYPTION_FAILED': 'Decryption failed: {error}',
    'KEY_EXCHANGE_FAILED': 'Key exchange failed: {error}',
    'METRICS_FAILED': 'Metrics calculation failed: {error}'
}

# Success Messages
SUCCESS_MESSAGES = {
    'KEY_GENERATED': 'Successfully generated AES-128 key',
    'KEY_EXCHANGE_SUCCESS': 'Key exchange successful',
    'ENCRYPTION_SUCCESS': 'Image encrypted successfully',
    'DECRYPTION_SUCCESS': 'Image decrypted successfully',
    'METRICS_CALCULATED': 'Quality metrics calculated successfully'
}
