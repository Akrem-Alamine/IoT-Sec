"""
Image Processing Module
Handles loading, encryption, decryption, and saving of images
"""

from PIL import Image
import numpy as np
import os
from typing import Tuple


class ImageProcessor:
    """
    Handles image I/O and processing operations
    """

    @staticmethod
    def load_image(image_path: str) -> Tuple[bytes, dict]:
        """
        Load an image from file and return raw bytes plus metadata
        
        Args:
            image_path: Path to the image file
            
        Returns:
            tuple: (image_bytes, metadata_dict)
                - image_bytes: Raw pixel data
                - metadata_dict: Contains format, size, mode, and original path
        """
        if not os.path.exists(image_path):
            raise FileNotFoundError(f"Image file not found: {image_path}")
        
        # Open image
        img = Image.open(image_path)
        
        # Store metadata
        metadata = {
            'format': img.format,
            'size': img.size,  # (width, height)
            'mode': img.mode,  # RGB, RGBA, L, etc.
            'original_path': image_path,
            'filename': os.path.basename(image_path)
        }
        
        # Convert to bytes
        image_bytes = img.tobytes()
        
        return image_bytes, metadata

    @staticmethod
    def save_image(image_bytes: bytes, metadata: dict, output_path: str) -> str:
        """
        Save decrypted image bytes back to file
        
        Args:
            image_bytes: Raw pixel data
            metadata: Image metadata dictionary
            output_path: Path to save the image
            
        Returns:
            str: The saved file path
        """
        try:
            # Reconstruct image from bytes
            img = Image.frombytes(
                mode=metadata['mode'],
                size=metadata['size'],
                data=image_bytes
            )
            
            # Create output directory if it doesn't exist
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            # Save image
            img.save(output_path)
            
            return output_path
        
        except Exception as e:
            raise ValueError(f"Failed to save image: {str(e)}")

    @staticmethod
    def save_encrypted_image(encrypted_data: bytes, output_path: str) -> str:
        """
        Save encrypted image data to file
        
        Args:
            encrypted_data: Encrypted image bytes
            output_path: Path to save the encrypted data
            
        Returns:
            str: The saved file path
        """
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        with open(output_path, 'wb') as f:
            f.write(encrypted_data)
        
        return output_path

    @staticmethod
    def load_encrypted_image(encrypted_path: str) -> bytes:
        """
        Load encrypted image data from file
        
        Args:
            encrypted_path: Path to the encrypted image file
            
        Returns:
            bytes: The encrypted image data
        """
        if not os.path.exists(encrypted_path):
            raise FileNotFoundError(f"Encrypted image file not found: {encrypted_path}")
        
        with open(encrypted_path, 'rb') as f:
            encrypted_data = f.read()
        
        return encrypted_data

    @staticmethod
    def image_to_array(image_path: str) -> np.ndarray:
        """
        Load image and convert to numpy array
        
        Args:
            image_path: Path to the image file
            
        Returns:
            np.ndarray: Image data as numpy array
        """
        img = Image.open(image_path)
        return np.array(img)

    @staticmethod
    def array_to_image(array: np.ndarray, output_path: str) -> str:
        """
        Convert numpy array back to image and save
        
        Args:
            array: Image data as numpy array
            output_path: Path to save the image
            
        Returns:
            str: The saved file path
        """
        img = Image.fromarray(array.astype('uint8'))
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        img.save(output_path)
        return output_path

    @staticmethod
    def get_image_info(image_path: str) -> dict:
        """
        Get detailed information about an image
        
        Args:
            image_path: Path to the image file
            
        Returns:
            dict: Image information
        """
        img = Image.open(image_path)
        
        return {
            'format': img.format,
            'size': img.size,
            'width': img.width,
            'height': img.height,
            'mode': img.mode,
            'file_size_kb': os.path.getsize(image_path) / 1024,
            'is_animated': hasattr(img, 'is_animated') and img.is_animated
        }

    @staticmethod
    def verify_image_integrity(original_bytes: bytes, recovered_bytes: bytes) -> bool:
        """
        Verify that recovered image is identical to original
        
        Args:
            original_bytes: Original image bytes
            recovered_bytes: Recovered image bytes after encryption/decryption
            
        Returns:
            bool: True if bytes are identical
        """
        return original_bytes == recovered_bytes

    @staticmethod
    def compare_images(image_path1: str, image_path2: str) -> dict:
        """
        Compare two images and return similarity metrics
        
        Args:
            image_path1: Path to first image
            image_path2: Path to second image
            
        Returns:
            dict: Comparison results
        """
        img1 = np.array(Image.open(image_path1))
        img2 = np.array(Image.open(image_path2))
        
        if img1.shape != img2.shape:
            return {
                'identical': False,
                'shapes_match': False,
                'error': 'Images have different dimensions'
            }
        
        # Calculate pixel-by-pixel comparison
        identical = np.array_equal(img1, img2)
        difference = np.sum(np.abs(img1.astype(float) - img2.astype(float)))
        
        return {
            'identical': identical,
            'shapes_match': True,
            'total_pixel_difference': difference,
            'mean_pixel_difference': difference / img1.size if img1.size > 0 else 0
        }
