#!/usr/bin/env python3
"""
File Carver
===========

Forensic file carving module for recovering deleted files and extracting
embedded files from disk images and file systems.

Author: Brainless Security Team
Module: auxiliary/forensic/file_carver
Type: auxiliary
Rank: excellent
"""

import os
import sys
import re
import struct
import binascii
from pathlib import Path

# Add framework path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from core.logger import LoggerMixin

NAME = "File Carver"
DESCRIPTION = "Forensic file carving for recovering deleted files and extracting embedded files"
AUTHOR = "Brainless Security Team"
VERSION = "1.0"
RANK = "excellent"
MODULE_TYPE = "auxiliary"

class FileCarver(LoggerMixin):
    """
    Forensic file carving module
    """
    
    def __init__(self):
        super().__init__('FileCarver')
        self.target_file = None
        self.output_dir = "./carved_files"
        self.file_signatures = {}
        self.min_file_size = 1024  # Minimum file size to carve
        self.max_file_size = 100 * 1024 * 1024  # 100MB max file size
        self.results = []
        
        # Initialize file signatures
        self.initialize_signatures()
    
    def set_option(self, option: str, value: str):
        """Set module options"""
        if option.lower() == 'target_file':
            self.target_file = value
        elif option.lower() == 'output_dir':
            self.output_dir = value
        elif option.lower() == 'min_file_size':
            self.min_file_size = int(value)
        elif option.lower() == 'max_file_size':
            self.max_file_size = int(value)
    
    def get_options(self) -> dict:
        """Get module options"""
        return {
            'TARGET_FILE': {'description': 'Target file or disk image to carve', 'required': True, 'default': ''},
            'OUTPUT_DIR': {'description': 'Output directory for carved files', 'required': False, 'default': './carved_files'},
            'MIN_FILE_SIZE': {'description': 'Minimum file size to carve (bytes)', 'required': False, 'default': '1024'},
            'MAX_FILE_SIZE': {'description': 'Maximum file size to carve (bytes)', 'required': False, 'default': '104857600'}
        }
    
    def initialize_signatures(self):
        """
        Initialize file signatures database
        """
        # File signatures (magic numbers) for different file types
        self.file_signatures = {
            'JPEG': {
                'header': b'\xFF\xD8\xFF',
                'footer': b'\xFF\xD9',
                'extension': '.jpg'
            },
            'PNG': {
                'header': b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A',
                'footer': b'\x49\x45\x4E\x44\xAE\x42\x60\x82',
                'extension': '.png'
            },
            'PDF': {
                'header': b'\x25\x50\x44\x46',
                'footer': b'\x25\x25\x45\x4F\x46',
                'extension': '.pdf'
            },
            'ZIP': {
                'header': b'\x50\x4B\x03\x04',
                'footer': b'\x50\x4B\x05\x06',  # End of central directory
                'extension': '.zip'
            },
            'RAR': {
                'header': b'\x52\x61\x72\x21\x1A\x07\x00',
                'footer': None,
                'extension': '.rar'
            },
            'GZIP': {
                'header': b'\x1F\x8B\x08',
                'footer': None,
                'extension': '.gz'
            },
            'TAR': {
                'header': b'ustar',
                'footer': None,
                'extension': '.tar'
            },
            'DOC': {
                'header': b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1',
                'footer': None,
                'extension': '.doc'
            },
            'DOCX': {
                'header': b'PK\x03\x04',
                'footer': None,
                'extension': '.docx'
            },
            'XLS': {
                'header': b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1',
                'footer': None,
                'extension': '.xls'
            },
            'XLSX': {
                'header': b'PK\x03\x04',
                'footer': None,
                'extension': '.xlsx'
            },
            'PPT': {
                'header': b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1',
                'footer': None,
                'extension': '.ppt'
            },
            'PPTX': {
                'header': b'PK\x03\x04',
                'footer': None,
                'extension': '.pptx'
            },
            'MP3': {
                'header': b'\xFF\xFB',
                'footer': None,
                'extension': '.mp3'
            },
            'AVI': {
                'header': b'RIFF',
                'footer': b'AVI ',
                'extension': '.avi'
            },
            'MP4': {
                'header': b'\x00\x00\x00\x20\x66\x74\x79\x70',
                'footer': None,
                'extension': '.mp4'
            },
            'MOV': {
                'header': b'\x00\x00\x00\x14\x66\x74\x79\x70',
                'footer': None,
                'extension': '.mov'
            },
            'WAV': {
                'header': b'RIFF',
                'footer': b'WAVE',
                'extension': '.wav'
            },
            'BMP': {
                'header': b'BM',
                'footer': None,
                'extension': '.bmp'
            },
            'GIF': {
                'header': b'GIF8',
                'footer': None,
                'extension': '.gif'
            }
        }
    
    def create_output_directory(self):
        """
        Create output directory for carved files
        """
        try:
            os.makedirs(self.output_dir, exist_ok=True)
            self.info(f"Output directory: {self.output_dir}")
        except Exception as e:
            self.error(f"Failed to create output directory: {e}")
            return False
        return True
    
    def get_file_type_from_signature(self, data: bytes) -> str:
        """
        Determine file type from signature
        """
        for file_type, signature in self.file_signatures.items():
            if data.startswith(signature['header']):
                return file_type
        return None
    
    def find_file_boundaries(self, data: bytes, file_type: str, start_pos: int) -> tuple:
        """
        Find file boundaries using header and footer signatures
        """
        signature = self.file_signatures[file_type]
        header = signature['header']
        footer = signature['footer']
        
        # Find header position
        header_pos = data.find(header, start_pos)
        if header_pos == -1:
            return None
        
        # Find footer position
        if footer:
            footer_pos = data.find(footer, header_pos + len(header))
            if footer_pos == -1:
                return None
            file_size = footer_pos + len(footer) - header_pos
        else:
            # For files without clear footer, estimate size
            file_size = self.estimate_file_size(data, header_pos, file_type)
            if file_size == 0:
                return None
            footer_pos = header_pos + file_size
        
        return (header_pos, footer_pos, file_size)
    
    def estimate_file_size(self, data: bytes, start_pos: int, file_type: str) -> int:
        """
        Estimate file size for formats without clear footer
        """
        # ZIP files have specific structure
        if file_type in ['ZIP', 'DOCX', 'XLSX', 'PPTX']:
            return self.estimate_zip_size(data, start_pos)
        
        # Office documents (OLE2)
        elif file_type in ['DOC', 'XLS', 'PPT']:
            return self.estimate_ole_size(data, start_pos)
        
        # Media files - use reasonable defaults
        elif file_type == 'MP3':
            return min(10 * 1024 * 1024, len(data) - start_pos)  # Max 10MB
        
        elif file_type in ['MP4', 'MOV']:
            return min(50 * 1024 * 1024, len(data) - start_pos)  # Max 50MB
        
        elif file_type == 'GZIP':
            return min(5 * 1024 * 1024, len(data) - start_pos)  # Max 5MB
        
        # Default fallback
        return min(1024 * 1024, len(data) - start_pos)  # Max 1MB
    
    def estimate_zip_size(self, data: bytes, start_pos: int) -> int:
        """
        Estimate ZIP file size by finding end of central directory
        """
        # Look for end of central directory signature
        end_sig = b'\x50\x4B\x05\x06'
        end_pos = data.find(end_sig, start_pos)
        
        if end_pos != -1:
            # Parse end of central directory record
            if end_pos + 22 <= len(data):
                # Extract directory size and offset
                dir_size = struct.unpack('<L', data[end_pos + 12:end_pos + 16])[0]
                dir_offset = struct.unpack('<L', data[end_pos + 16:end_pos + 20])[0]
                
                # Calculate total size
                total_size = dir_offset + dir_size + 22
                return total_size
        
        # Fallback: search for next ZIP signature
        next_zip = data.find(b'PK\x03\x04', start_pos + 4)
        if next_zip != -1:
            return next_zip - start_pos
        
        return 0
    
    def estimate_ole_size(self, data: bytes, start_pos: int) -> int:
        """
        Estimate OLE2 file size (DOC, XLS, PPT)
        """
        # OLE2 files have a specific header structure
        if start_pos + 32 > len(data):
            return 0
        
        # Check for OLE2 signature
        ole_sig = data[start_pos:start_pos + 8]
        if ole_sig != b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1':
            return 0
        
        # Try to read file size from OLE header (if available)
        # This is a simplified approach
        return min(10 * 1024 * 1024, len(data) - start_pos)  # Max 10MB
    
    def carve_file(self, data: bytes, start_pos: int, file_type: str, file_index: int) -> dict:
        """
        Carve a single file from the data
        """
        boundaries = self.find_file_boundaries(data, file_type, start_pos)
        if not boundaries:
            return None
        
        header_pos, footer_pos, file_size = boundaries
        
        # Validate file size
        if file_size < self.min_file_size or file_size > self.max_file_size:
            return None
        
        # Extract file data
        file_data = data[header_pos:footer_pos]
        
        # Generate filename
        extension = self.file_signatures[file_type]['extension']
        filename = f"{file_type.lower()}_{file_index:04d}{extension}"
        filepath = os.path.join(self.output_dir, filename)
        
        try:
            # Save carved file
            with open(filepath, 'wb') as f:
                f.write(file_data)
            
            # Calculate file hash
            file_hash = binascii.hexlify(file_data[:1024]).decode()[:16]
            
            result = {
                'filename': filename,
                'filepath': filepath,
                'file_type': file_type,
                'size': file_size,
                'offset': header_pos,
                'hash': file_hash,
                'carved_at': os.times()[4]
            }
            
            self.results.append(result)
            self.info(f"Carved {file_type}: {filename} ({file_size} bytes)")
            
            return result
            
        except Exception as e:
            self.error(f"Failed to save {filename}: {e}")
            return None
    
    def carve_all_files(self) -> dict:
        """
        Carve all files from the target
        """
        if not self.target_file:
            return {'success': False, 'message': 'Target file not specified'}
        
        if not os.path.exists(self.target_file):
            return {'success': False, 'message': f'Target file not found: {self.target_file}'}
        
        # Create output directory
        if not self.create_output_directory():
            return {'success': False, 'message': 'Failed to create output directory'}
        
        try:
            self.info(f"Starting file carving on {self.target_file}")
            
            # Read target file
            with open(self.target_file, 'rb') as f:
                data = f.read()
            
            self.info(f"File size: {len(data)} bytes")
            
            # Carve files for each type
            file_index = {}
            step = 1024  # Search step size
            
            for i in range(0, len(data), step):
                # Check for file signatures
                chunk = data[i:i + 1024]
                
                file_type = self.get_file_type_from_signature(chunk)
                if file_type:
                    if file_type not in file_index:
                        file_index[file_type] = 0
                    
                    # Carve the file
                    result = self.carve_file(data, i, file_type, file_index[file_type])
                    
                    if result:
                        file_index[file_type] += 1
                    
                    # Skip ahead to avoid duplicate carving
                    if result:
                        i += result['size'] - step
            
            # Generate summary
            summary = {
                'target_file': self.target_file,
                'output_dir': self.output_dir,
                'total_files_carved': len(self.results),
                'files_by_type': file_index,
                'results': self.results
            }
            
            self.info(f"File carving completed. Carved {len(self.results)} files.")
            
            return {'success': True, 'summary': summary}
            
        except Exception as e:
            self.error(f"File carving failed: {e}")
            return {'success': False, 'message': f'Carving failed: {str(e)}'}
    
    def validate_carved_files(self) -> dict:
        """
        Validate carved files by checking their signatures
        """
        validation_results = []
        
        for result in self.results:
            try:
                with open(result['filepath'], 'rb') as f:
                    file_data = f.read(1024)
                
                file_type = self.get_file_type_from_signature(file_data)
                
                validation_results.append({
                    'filename': result['filename'],
                    'expected_type': result['file_type'],
                    'detected_type': file_type,
                    'valid': file_type == result['file_type']
                })
                
            except Exception as e:
                validation_results.append({
                    'filename': result['filename'],
                    'error': str(e),
                    'valid': False
                })
        
        return validation_results
    
    def run(self) -> dict:
        """
        Main module execution
        """
        return self.carve_all_files()


def run(options: dict = None) -> dict:
    """
    Entry point for the module
    """
    carver = FileCarver()
    
    # Set options if provided
    if options:
        for key, value in options.items():
            carver.set_option(key, value)
    
    return carver.run()


if __name__ == '__main__':
    # Example usage
    options = {
        'TARGET_FILE': '/path/to/disk.img',
        'OUTPUT_DIR': './carved_files',
        'MIN_FILE_SIZE': '1024',
        'MAX_FILE_SIZE': '104857600'
    }
    
    result = run(options)
    print(result)