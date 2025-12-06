"""
Image Quality Metrics Module
Implements PSNR (Peak Signal-to-Noise Ratio) and MSE (Mean Squared Error)
for evaluating decrypted image quality
"""

import numpy as np
import math
from PIL import Image


class ImageQualityMetrics:
    """
    Calculates image quality metrics for comparing original and recovered images
    """

    @staticmethod
    def calculate_mse(original: np.ndarray, recovered: np.ndarray) -> float:
        """
        Calculate Mean Squared Error (EQM in French)
        
        MSE = (1 / (M * N)) * Σ Σ (I₀(i,j) - Iᵣ(i,j))²
        
        Where:
        - M × N is the image size
        - I₀ is the original image
        - Iᵣ is the recovered image
        
        Args:
            original: Original image as numpy array
            recovered: Recovered image as numpy array
            
        Returns:
            float: Mean Squared Error
        """
        if original.shape != recovered.shape:
            raise ValueError("Images must have the same shape")
        
        # Convert to float to avoid overflow
        original_float = original.astype(np.float64)
        recovered_float = recovered.astype(np.float64)
        
        # Calculate MSE
        squared_error = (original_float - recovered_float) ** 2
        mse = np.mean(squared_error)
        
        return float(mse)

    @staticmethod
    def calculate_psnr(original: np.ndarray, recovered: np.ndarray, max_pixel_value: int = 255) -> float:
        """
        Calculate Peak Signal-to-Noise Ratio
        
        PSNR = 10 * log₁₀(d² / MSE)
        
        Where:
        - d is the maximum possible pixel value (typically 255 for 8-bit images)
        - MSE is the Mean Squared Error
        
        Args:
            original: Original image as numpy array
            recovered: Recovered image as numpy array
            max_pixel_value: Maximum pixel value (default 255 for 8-bit)
            
        Returns:
            float: PSNR in dB, or float('inf') if images are identical
        """
        if original.shape != recovered.shape:
            raise ValueError("Images must have the same shape")
        
        # Calculate MSE
        mse = ImageQualityMetrics.calculate_mse(original, recovered)
        
        # If MSE is 0, images are identical
        if mse == 0:
            return float('inf')
        
        # Calculate PSNR
        psnr = 10 * math.log10((max_pixel_value ** 2) / mse)
        return float(psnr)

    @staticmethod
    def calculate_ssim(original: np.ndarray, recovered: np.ndarray, data_range: int = 255) -> float:
        """
        Calculate Structural Similarity Index (SSIM)
        
        SSIM measures perceived image quality based on luminance, contrast, and structure
        
        Args:
            original: Original image as numpy array
            recovered: Recovered image as numpy array
            data_range: Maximum pixel value range
            
        Returns:
            float: SSIM value (ranges from -1 to 1, higher is better)
        """
        if original.shape != recovered.shape:
            raise ValueError("Images must have the same shape")
        
        # Convert to float
        original_float = original.astype(np.float64)
        recovered_float = recovered.astype(np.float64)
        
        # Constants for stability
        c1 = (0.01 * data_range) ** 2
        c2 = (0.03 * data_range) ** 2
        
        # Calculate means
        mu1 = original_float
        mu2 = recovered_float
        
        # Calculate variances and covariance
        mu1_sq = mu1 ** 2
        mu2_sq = mu2 ** 2
        mu1_mu2 = mu1 * mu2
        
        sigma1_sq = original_float ** 2 - mu1_sq
        sigma2_sq = recovered_float ** 2 - mu2_sq
        sigma12 = original_float * recovered_float - mu1_mu2
        
        # Calculate SSIM
        numerator = (2 * mu1_mu2 + c1) * (2 * sigma12 + c2)
        denominator = (mu1_sq + mu2_sq + c1) * (sigma1_sq + sigma2_sq + c2)
        
        ssim = np.mean(numerator / denominator)
        
        return float(np.clip(ssim, -1, 1))

    @staticmethod
    def compare_images_quality(original_path: str, recovered_path: str) -> dict:
        """
        Compare quality of two images and return all metrics
        
        Args:
            original_path: Path to original image
            recovered_path: Path to recovered/decrypted image
            
        Returns:
            dict: Dictionary containing all quality metrics
        """
        # Load images
        original_img = Image.open(original_path)
        recovered_img = Image.open(recovered_path)
        
        # Convert to numpy arrays
        original = np.array(original_img)
        recovered = np.array(recovered_img)
        
        # Calculate metrics
        mse = ImageQualityMetrics.calculate_mse(original, recovered)
        psnr = ImageQualityMetrics.calculate_psnr(original, recovered)
        ssim = ImageQualityMetrics.calculate_ssim(original, recovered)
        
        return {
            'mse': mse,
            'psnr': psnr,
            'ssim': ssim,
            'images_identical': mse == 0,
            'original_shape': original.shape,
            'recovered_shape': recovered.shape
        }

    @staticmethod
    def evaluate_encryption_impact(original_path: str, encrypted_path: str, decrypted_path: str) -> dict:
        """
        Full evaluation of encryption/decryption impact on image quality
        
        Args:
            original_path: Path to original image
            encrypted_path: Path to encrypted image file
            decrypted_path: Path to decrypted image
            
        Returns:
            dict: Comprehensive quality assessment
        """
        # Load and compare original with decrypted
        quality_metrics = ImageQualityMetrics.compare_images_quality(original_path, decrypted_path)
        
        # Check encrypted file size
        encrypted_size = os.path.getsize(encrypted_path)
        original_size = os.path.getsize(original_path)
        
        return {
            'quality_metrics': quality_metrics,
            'encrypted_file_size_bytes': encrypted_size,
            'original_file_size_bytes': original_size,
            'overhead_percentage': ((encrypted_size - original_size) / original_size) * 100,
            'encryption_successful': quality_metrics['images_identical']
        }


# Import os for file operations in evaluate_encryption_impact
import os
