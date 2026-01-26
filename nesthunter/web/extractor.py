"""
Core extraction engine for NestHunter.
Recursively extracts nested archives and builds extraction tree.
"""

import os
import hashlib
import tempfile
import shutil
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Set, Tuple
from datetime import datetime
from enum import Enum

# Try to import python-magic for MIME type detection
try:
    import magic
    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False


class FileType(Enum):
    """Supported archive types"""
    ZIP = "zip"
    RAR = "rar"
    SEVEN_ZIP = "7z"
    ISO = "iso"
    VHD = "vhd"
    TAR = "tar"
    GZIP = "gz"
    TAR_GZ = "tar.gz"
    UNKNOWN = "unknown"
    REGULAR = "regular"


@dataclass
class ExtractionNode:
    """Represents a file in the extraction tree"""
    id: str
    name: str
    path: str
    file_type: FileType
    size: int
    sha256: str
    sha1: str
    md5: str
    depth: int
    parent_id: Optional[str] = None
    children: List['ExtractionNode'] = field(default_factory=list)
    is_archive: bool = False
    extraction_error: Optional[str] = None
    suspicious_flags: List[str] = field(default_factory=list)
    mime_type: Optional[str] = None
    mime_mismatch: bool = False
    estimated_size: int = 0  # Pre-extraction estimated size
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'name': self.name,
            'path': self.path,
            'file_type': self.file_type.value,
            'size': self.size,
            'sha256': self.sha256,
            'sha1': self.sha1,
            'md5': self.md5,
            'depth': self.depth,
            'parent_id': self.parent_id,
            'children': [child.to_dict() for child in self.children],
            'is_archive': self.is_archive,
            'extraction_error': self.extraction_error,
            'suspicious_flags': self.suspicious_flags,
            'mime_type': self.mime_type,
            'mime_mismatch': self.mime_mismatch,
            'estimated_size': self.estimated_size
        }


@dataclass
class ExtractionResult:
    """Result of extraction operation"""
    root: ExtractionNode
    total_files: int
    total_archives: int
    max_depth_reached: int
    hash_collisions: Dict[str, List[str]]  # hash -> list of paths
    suspicious_patterns: List[dict]
    extraction_time: float
    temp_dir: str
    cumulative_extracted_size: int = 0
    estimated_total_size: int = 0
    single_file_chain_length: int = 0
    mime_mismatches: List[dict] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            'root': self.root.to_dict(),
            'total_files': self.total_files,
            'total_archives': self.total_archives,
            'max_depth_reached': self.max_depth_reached,
            'hash_collisions': self.hash_collisions,
            'suspicious_patterns': self.suspicious_patterns,
            'extraction_time': self.extraction_time,
            'cumulative_extracted_size': self.cumulative_extracted_size,
            'estimated_total_size': self.estimated_total_size,
            'single_file_chain_length': self.single_file_chain_length,
            'mime_mismatches': self.mime_mismatches
        }


class NestHunterExtractor:
    """Main extraction engine"""
    
    # File signatures (magic bytes)
    SIGNATURES = {
        b'PK\x03\x04': FileType.ZIP,
        b'PK\x05\x06': FileType.ZIP,
        b'Rar!\x1a\x07': FileType.RAR,
        b"7z\xbc\xaf'\x1c": FileType.SEVEN_ZIP,
        b'\x1f\x8b': FileType.GZIP,
        b'CD001': FileType.ISO,  # At offset 32769
        b'conectix': FileType.VHD,  # VHD footer
    }
    
    # Expected MIME types for each file type
    EXPECTED_MIME_TYPES = {
        FileType.ZIP: ['application/zip', 'application/x-zip-compressed'],
        FileType.RAR: ['application/x-rar-compressed', 'application/vnd.rar', 'application/x-rar'],
        FileType.SEVEN_ZIP: ['application/x-7z-compressed'],
        FileType.ISO: ['application/x-iso9660-image', 'application/octet-stream'],
        FileType.VHD: ['application/x-vhd', 'application/octet-stream'],
        FileType.TAR: ['application/x-tar'],
        FileType.GZIP: ['application/gzip', 'application/x-gzip'],
        FileType.TAR_GZ: ['application/gzip', 'application/x-gzip', 'application/x-compressed-tar'],
    }
    
    # Suspicious patterns
    SUSPICIOUS_EXTENSIONS = {
        '.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.vbs', 
        '.js', '.jse', '.wsf', '.wsh', '.msi', '.hta', '.pif'
    }
    
    SUSPICIOUS_NESTING = [
        ('iso', 'zip'),
        ('iso', 'rar'),
        ('vhd', 'zip'),
        ('vhd', 'rar'),
        ('zip', 'iso'),
        ('rar', 'iso'),
    ]
    
    # Default cumulative size limit (2GB)
    DEFAULT_CUMULATIVE_LIMIT = 2 * 1024 * 1024 * 1024
    
    # Compression ratio threshold for zip bomb detection
    COMPRESSION_RATIO_THRESHOLD = 100
    
    def __init__(self, max_depth: int = 10, max_file_size: int = 500 * 1024 * 1024,
                 max_cumulative_size: int = None):
        """
        Initialize extractor.
        
        Args:
            max_depth: Maximum nesting depth (default 10)
            max_file_size: Maximum single file size to extract (default 500MB)
            max_cumulative_size: Maximum total extracted size (default 2GB)
        """
        self.max_depth = max_depth
        self.max_file_size = max_file_size
        self.max_cumulative_size = max_cumulative_size or self.DEFAULT_CUMULATIVE_LIMIT
        self.node_counter = 0
        self.hash_map: Dict[str, List[str]] = {}
        self.suspicious_patterns: List[dict] = []
        self.cumulative_extracted_size = 0
        self.mime_mismatches: List[dict] = []
        self.single_file_chain_count = 0
        
    def _generate_node_id(self) -> str:
        """Generate unique node ID"""
        self.node_counter += 1
        return f"node_{self.node_counter}"
    
    def _compute_hashes(self, filepath: str) -> Tuple[str, str, str]:
        """Compute SHA256, SHA1, and MD5 hashes of a file"""
        sha256_hash = hashlib.sha256()
        sha1_hash = hashlib.sha1()
        md5_hash = hashlib.md5()
        
        try:
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256_hash.update(chunk)
                    sha1_hash.update(chunk)
                    md5_hash.update(chunk)
            return sha256_hash.hexdigest(), sha1_hash.hexdigest(), md5_hash.hexdigest()
        except Exception:
            return "error", "error", "error"
    
    def _detect_mime_type(self, filepath: str) -> Optional[str]:
        """Detect MIME type using python-magic"""
        if not HAS_MAGIC:
            return None
        try:
            mime = magic.Magic(mime=True)
            return mime.from_file(filepath)
        except Exception:
            return None
    
    def _check_mime_mismatch(self, filepath: str, detected_type: FileType, 
                             mime_type: Optional[str]) -> bool:
        """Check if MIME type matches expected type for the file"""
        if not mime_type or detected_type == FileType.REGULAR:
            return False
        
        expected_mimes = self.EXPECTED_MIME_TYPES.get(detected_type, [])
        if not expected_mimes:
            return False
        
        # Check if detected MIME matches any expected
        is_mismatch = mime_type not in expected_mimes
        
        if is_mismatch:
            self.mime_mismatches.append({
                'path': filepath,
                'expected': expected_mimes,
                'actual': mime_type,
                'detected_type': detected_type.value
            })
            self.suspicious_patterns.append({
                'type': 'mime_mismatch',
                'description': f'MIME type mismatch: expected {expected_mimes}, got {mime_type}',
                'path': filepath,
                'severity': 'high'
            })
        
        return is_mismatch
    
    def _detect_file_type(self, filepath: str) -> FileType:
        """Detect file type using magic bytes and extension"""
        try:
            with open(filepath, 'rb') as f:
                header = f.read(32)
                
                # Check standard signatures
                for sig, ftype in self.SIGNATURES.items():
                    if header.startswith(sig):
                        return ftype
                
                # Check for TAR (ustar at offset 257)
                f.seek(257)
                if f.read(5) == b'ustar':
                    return FileType.TAR
                
                # Check for ISO (CD001 at offset 32769)
                f.seek(32769)
                if f.read(5) == b'CD001':
                    return FileType.ISO
                    
        except Exception:
            pass
        
        # Fallback to extension
        ext = os.path.splitext(filepath)[1].lower()
        ext_map = {
            '.zip': FileType.ZIP,
            '.rar': FileType.RAR,
            '.7z': FileType.SEVEN_ZIP,
            '.iso': FileType.ISO,
            '.vhd': FileType.VHD,
            '.vhdx': FileType.VHD,
            '.tar': FileType.TAR,
            '.gz': FileType.GZIP,
            '.tgz': FileType.TAR_GZ,
            '.tar.gz': FileType.TAR_GZ,
        }
        
        return ext_map.get(ext, FileType.REGULAR)
    
    def _is_archive(self, file_type: FileType) -> bool:
        """Check if file type is an archive"""
        return file_type not in (FileType.UNKNOWN, FileType.REGULAR)
    
    def _track_hash(self, sha256: str, filepath: str):
        """Track file hash for collision detection"""
        if sha256 not in self.hash_map:
            self.hash_map[sha256] = []
        self.hash_map[sha256].append(filepath)
    
    def _estimate_archive_size(self, filepath: str, file_type: FileType) -> int:
        """
        Estimate decompressed size before extraction.
        Returns estimated size in bytes, or 0 if unable to estimate.
        """
        try:
            if file_type == FileType.ZIP:
                return self._estimate_zip_size(filepath)
            elif file_type == FileType.RAR:
                return self._estimate_rar_size(filepath)
            elif file_type == FileType.SEVEN_ZIP:
                return self._estimate_7z_size(filepath)
            elif file_type == FileType.TAR or file_type == FileType.TAR_GZ:
                return self._estimate_tar_size(filepath)
            elif file_type == FileType.GZIP:
                return self._estimate_gzip_size(filepath)
        except Exception:
            pass
        return 0
    
    def _estimate_zip_size(self, filepath: str) -> int:
        """Estimate uncompressed size of ZIP archive"""
        import zipfile
        total = 0
        try:
            with zipfile.ZipFile(filepath, 'r') as zf:
                for info in zf.infolist():
                    total += info.file_size
        except Exception:
            pass
        return total
    
    def _estimate_rar_size(self, filepath: str) -> int:
        """Estimate uncompressed size of RAR archive"""
        try:
            import rarfile
            total = 0
            with rarfile.RarFile(filepath, 'r') as rf:
                for info in rf.infolist():
                    total += info.file_size
            return total
        except Exception:
            return 0
    
    def _estimate_7z_size(self, filepath: str) -> int:
        """Estimate uncompressed size of 7z archive"""
        try:
            import py7zr
            total = 0
            with py7zr.SevenZipFile(filepath, 'r') as szf:
                for name, bio in szf.readall().items():
                    bio.seek(0, 2)  # Seek to end
                    total += bio.tell()
            return total
        except Exception:
            return 0
    
    def _estimate_tar_size(self, filepath: str) -> int:
        """Estimate uncompressed size of TAR archive"""
        import tarfile
        total = 0
        try:
            mode = 'r:gz' if filepath.endswith(('.gz', '.tgz')) else 'r'
            with tarfile.open(filepath, mode) as tf:
                for member in tf.getmembers():
                    if member.isfile():
                        total += member.size
        except Exception:
            pass
        return total
    
    def _estimate_gzip_size(self, filepath: str) -> int:
        """Estimate uncompressed size of GZIP file (from trailer)"""
        try:
            with open(filepath, 'rb') as f:
                f.seek(-4, 2)  # Last 4 bytes contain uncompressed size (mod 2^32)
                size_bytes = f.read(4)
                return int.from_bytes(size_bytes, 'little')
        except Exception:
            return 0
    
    def _check_pre_extraction_safety(self, filepath: str, file_type: FileType,
                                     compressed_size: int) -> Tuple[bool, int, str]:
        """
        Check if it's safe to extract based on pre-extraction estimates.
        
        Returns:
            (is_safe, estimated_size, warning_message)
        """
        estimated_size = self._estimate_archive_size(filepath, file_type)
        
        # Check compression ratio
        if compressed_size > 0 and estimated_size > 0:
            ratio = estimated_size / compressed_size
            if ratio > self.COMPRESSION_RATIO_THRESHOLD:
                return (False, estimated_size, 
                        f"Dangerous compression ratio ({ratio:.1f}:1) - potential zip bomb")
        
        # Check if extraction would exceed cumulative limit
        if self.cumulative_extracted_size + estimated_size > self.max_cumulative_size:
            return (False, estimated_size,
                    f"Extraction would exceed cumulative size limit ({self.max_cumulative_size / (1024*1024):.0f}MB)")
        
        return (True, estimated_size, "")
    
    def _count_archive_files(self, filepath: str, file_type: FileType) -> int:
        """Count number of files in archive without extracting"""
        try:
            if file_type == FileType.ZIP:
                import zipfile
                with zipfile.ZipFile(filepath, 'r') as zf:
                    return len([i for i in zf.infolist() if not i.is_dir()])
            elif file_type == FileType.RAR:
                import rarfile
                with rarfile.RarFile(filepath, 'r') as rf:
                    return len([i for i in rf.infolist() if not i.is_dir()])
            elif file_type == FileType.TAR or file_type == FileType.TAR_GZ:
                import tarfile
                mode = 'r:gz' if filepath.endswith(('.gz', '.tgz')) else 'r'
                with tarfile.open(filepath, mode) as tf:
                    return len([m for m in tf.getmembers() if m.isfile()])
        except Exception:
            pass
        return 0
    
    def _check_suspicious_patterns(self, node: ExtractionNode, parent_type: Optional[FileType]):
        """Check for suspicious patterns"""
        flags = []
        
        # Check for suspicious file extensions
        ext = os.path.splitext(node.name)[1].lower()
        if ext in self.SUSPICIOUS_EXTENSIONS:
            flags.append(f"suspicious_extension:{ext}")
        
        # Check for hidden files
        if node.name.startswith('.'):
            flags.append("hidden_file")
        
        # Check for double extensions
        parts = node.name.split('.')
        if len(parts) > 2:
            flags.append("double_extension")
        
        # Check for suspicious nesting patterns
        if parent_type and node.is_archive:
            parent_ext = parent_type.value
            child_ext = node.file_type.value
            if (parent_ext, child_ext) in self.SUSPICIOUS_NESTING:
                flags.append(f"suspicious_nesting:{parent_ext}->{child_ext}")
                self.suspicious_patterns.append({
                    'type': 'suspicious_nesting',
                    'description': f"Archive nested inside {parent_ext}: {child_ext}",
                    'path': node.path,
                    'severity': 'high'
                })
        
        # Check for excessive depth
        if node.depth >= self.max_depth - 2:
            flags.append("excessive_depth")
        
        # Check for very small archives (potential zip bomb indicator)
        if node.is_archive and node.size < 1000:
            flags.append("tiny_archive")
        
        node.suspicious_flags = flags
        return flags
    
    def extract(self, filepath: str) -> ExtractionResult:
        """
        Main extraction method.
        
        Args:
            filepath: Path to the archive file to extract
            
        Returns:
            ExtractionResult with complete extraction tree
        """
        import time
        start_time = time.time()
        
        # Reset state
        self.node_counter = 0
        self.hash_map = {}
        self.suspicious_patterns = []
        self.cumulative_extracted_size = 0
        self.mime_mismatches = []
        self.single_file_chain_count = 0
        
        # Create temporary directory for extraction
        temp_dir = tempfile.mkdtemp(prefix="nesthunter_")
        
        # Get file info
        file_size = os.path.getsize(filepath)
        sha256, sha1, md5 = self._compute_hashes(filepath)
        file_type = self._detect_file_type(filepath)
        mime_type = self._detect_mime_type(filepath)
        
        # Check MIME type mismatch for root file
        mime_mismatch = self._check_mime_mismatch(filepath, file_type, mime_type)
        
        # Pre-extraction safety check
        estimated_size = 0
        if self._is_archive(file_type):
            is_safe, estimated_size, warning = self._check_pre_extraction_safety(
                filepath, file_type, file_size
            )
            if not is_safe:
                self.suspicious_patterns.append({
                    'type': 'pre_extraction_warning',
                    'description': warning,
                    'path': filepath,
                    'severity': 'critical'
                })
        
        # Create root node
        root = ExtractionNode(
            id=self._generate_node_id(),
            name=os.path.basename(filepath),
            path=filepath,
            file_type=file_type,
            size=file_size,
            sha256=sha256,
            sha1=sha1,
            md5=md5,
            depth=0,
            is_archive=self._is_archive(file_type),
            mime_type=mime_type,
            mime_mismatch=mime_mismatch,
            estimated_size=estimated_size
        )
        
        self._track_hash(sha256, filepath)
        
        # Track statistics
        total_files = 1
        total_archives = 1 if root.is_archive else 0
        max_depth = 0
        
        # Recursively extract if it's an archive
        if root.is_archive:
            stats = self._extract_recursive(root, temp_dir, None, [])
            total_files += stats['files']
            total_archives += stats['archives']
            max_depth = stats['max_depth']
        
        # Find hash collisions (same file appearing multiple times)
        hash_collisions = {h: paths for h, paths in self.hash_map.items() if len(paths) > 1}
        
        # Add hash collision warnings
        for sha256_key, paths in hash_collisions.items():
            self.suspicious_patterns.append({
                'type': 'file_reuse',
                'description': f"Same file appears {len(paths)} times",
                'paths': paths,
                'sha256': sha256_key,
                'severity': 'medium'
            })
        
        extraction_time = time.time() - start_time
        
        return ExtractionResult(
            root=root,
            total_files=total_files,
            total_archives=total_archives,
            max_depth_reached=max_depth,
            hash_collisions=hash_collisions,
            suspicious_patterns=self.suspicious_patterns,
            extraction_time=extraction_time,
            temp_dir=temp_dir,
            cumulative_extracted_size=self.cumulative_extracted_size,
            estimated_total_size=estimated_size,
            single_file_chain_length=self.single_file_chain_count,
            mime_mismatches=self.mime_mismatches
        )
    
    def _extract_recursive(self, node: ExtractionNode, temp_dir: str, 
                          parent_type: Optional[FileType],
                          single_file_chain: List[str]) -> dict:
        """Recursively extract archive contents"""
        stats = {'files': 0, 'archives': 0, 'max_depth': node.depth}
        
        # Check depth limit
        if node.depth >= self.max_depth:
            node.extraction_error = f"Max depth ({self.max_depth}) reached"
            self.suspicious_patterns.append({
                'type': 'depth_limit',
                'description': f"Maximum nesting depth reached at {node.name}",
                'path': node.path,
                'severity': 'high'
            })
            return stats
        
        # Check cumulative size limit
        if self.cumulative_extracted_size >= self.max_cumulative_size:
            node.extraction_error = f"Cumulative size limit ({self.max_cumulative_size / (1024*1024):.0f}MB) reached"
            self.suspicious_patterns.append({
                'type': 'cumulative_size_limit',
                'description': f"Cumulative extraction size limit exceeded",
                'path': node.path,
                'severity': 'critical'
            })
            return stats
        
        # Pre-extraction safety check
        is_safe, estimated_size, warning = self._check_pre_extraction_safety(
            node.path, node.file_type, node.size
        )
        node.estimated_size = estimated_size
        
        if not is_safe:
            node.extraction_error = warning
            self.suspicious_patterns.append({
                'type': 'pre_extraction_warning',
                'description': warning,
                'path': node.path,
                'severity': 'critical'
            })
            return stats
        
        # Create extraction directory
        extract_dir = os.path.join(temp_dir, f"depth_{node.depth}_{node.id}")
        os.makedirs(extract_dir, exist_ok=True)
        
        try:
            # Extract based on file type
            extracted_files = self._extract_archive(node.path, extract_dir, node.file_type)
            
            # Check for single-file archive chain
            file_count = len([f for f in extracted_files if os.path.isfile(f)])
            current_chain = single_file_chain.copy()
            
            if file_count == 1:
                current_chain.append(node.file_type.value)
                if len(current_chain) >= 3:
                    self.single_file_chain_count = max(self.single_file_chain_count, len(current_chain))
                    if len(current_chain) == 3:  # Only flag once at threshold
                        self.suspicious_patterns.append({
                            'type': 'single_file_chain',
                            'description': f"Single-file archive chain detected: {' → '.join(current_chain)}",
                            'path': node.path,
                            'severity': 'high',
                            'chain': current_chain
                        })
            else:
                current_chain = []  # Reset chain if multiple files
            
            for extracted_path in extracted_files:
                if not os.path.exists(extracted_path):
                    continue
                    
                # Skip directories
                if os.path.isdir(extracted_path):
                    continue
                
                file_size = os.path.getsize(extracted_path)
                
                # Update cumulative size
                self.cumulative_extracted_size += file_size
                
                # Check cumulative limit after each file
                if self.cumulative_extracted_size > self.max_cumulative_size:
                    self.suspicious_patterns.append({
                        'type': 'cumulative_size_exceeded',
                        'description': f"Cumulative extraction size exceeded limit during extraction",
                        'path': extracted_path,
                        'severity': 'critical'
                    })
                    break
                
                # Check file size limit
                if file_size > self.max_file_size:
                    continue
                
                sha256, sha1, md5 = self._compute_hashes(extracted_path)
                file_type = self._detect_file_type(extracted_path)
                is_archive = self._is_archive(file_type)
                mime_type = self._detect_mime_type(extracted_path)
                mime_mismatch = self._check_mime_mismatch(extracted_path, file_type, mime_type)
                
                # Estimate size for nested archives
                child_estimated_size = 0
                if is_archive:
                    child_estimated_size = self._estimate_archive_size(extracted_path, file_type)
                
                child_node = ExtractionNode(
                    id=self._generate_node_id(),
                    name=os.path.basename(extracted_path),
                    path=extracted_path,
                    file_type=file_type,
                    size=file_size,
                    sha256=sha256,
                    sha1=sha1,
                    md5=md5,
                    depth=node.depth + 1,
                    parent_id=node.id,
                    is_archive=is_archive,
                    mime_type=mime_type,
                    mime_mismatch=mime_mismatch,
                    estimated_size=child_estimated_size
                )
                
                self._track_hash(sha256, extracted_path)
                self._check_suspicious_patterns(child_node, node.file_type)
                
                node.children.append(child_node)
                stats['files'] += 1
                stats['max_depth'] = max(stats['max_depth'], child_node.depth)
                
                if is_archive:
                    stats['archives'] += 1
                    child_stats = self._extract_recursive(child_node, temp_dir, node.file_type, current_chain)
                    stats['files'] += child_stats['files']
                    stats['archives'] += child_stats['archives']
                    stats['max_depth'] = max(stats['max_depth'], child_stats['max_depth'])
                    
        except Exception as e:
            node.extraction_error = str(e)
            
        return stats
    
    def _extract_archive(self, filepath: str, extract_dir: str, 
                        file_type: FileType) -> List[str]:
        """Extract archive contents to directory"""
        extracted_files = []
        
        try:
            if file_type == FileType.ZIP:
                extracted_files = self._extract_zip(filepath, extract_dir)
            elif file_type == FileType.RAR:
                extracted_files = self._extract_rar(filepath, extract_dir)
            elif file_type == FileType.SEVEN_ZIP:
                extracted_files = self._extract_7z(filepath, extract_dir)
            elif file_type == FileType.TAR or file_type == FileType.TAR_GZ:
                extracted_files = self._extract_tar(filepath, extract_dir)
            elif file_type == FileType.GZIP:
                extracted_files = self._extract_gzip(filepath, extract_dir)
            elif file_type == FileType.ISO:
                extracted_files = self._extract_iso(filepath, extract_dir)
            elif file_type == FileType.VHD:
                extracted_files = self._extract_vhd(filepath, extract_dir)
        except Exception as e:
            raise Exception(f"Extraction failed: {str(e)}")
            
        return extracted_files
    
    def _extract_zip(self, filepath: str, extract_dir: str) -> List[str]:
        """Extract ZIP archive"""
        import zipfile
        extracted = []
        with zipfile.ZipFile(filepath, 'r') as zf:
            for info in zf.infolist():
                if not info.is_dir():
                    # Prevent path traversal
                    safe_name = os.path.basename(info.filename)
                    if not safe_name:
                        safe_name = info.filename.replace('/', '_').replace('\\', '_')
                    target_path = os.path.join(extract_dir, safe_name)
                    
                    with zf.open(info) as source:
                        with open(target_path, 'wb') as target:
                            shutil.copyfileobj(source, target)
                    extracted.append(target_path)
        return extracted
    
    def _extract_rar(self, filepath: str, extract_dir: str) -> List[str]:
        """Extract RAR archive"""
        try:
            import rarfile
            extracted = []
            with rarfile.RarFile(filepath, 'r') as rf:
                for info in rf.infolist():
                    if not info.is_dir():
                        safe_name = os.path.basename(info.filename)
                        if not safe_name:
                            safe_name = info.filename.replace('/', '_').replace('\\', '_')
                        target_path = os.path.join(extract_dir, safe_name)
                        
                        with rf.open(info) as source:
                            with open(target_path, 'wb') as target:
                                shutil.copyfileobj(source, target)
                        extracted.append(target_path)
            return extracted
        except ImportError:
            raise Exception("rarfile library not installed")
    
    def _extract_7z(self, filepath: str, extract_dir: str) -> List[str]:
        """Extract 7z archive"""
        try:
            import py7zr
            extracted = []
            with py7zr.SevenZipFile(filepath, 'r') as szf:
                szf.extractall(path=extract_dir)
                for root, dirs, files in os.walk(extract_dir):
                    for f in files:
                        extracted.append(os.path.join(root, f))
            return extracted
        except ImportError:
            raise Exception("py7zr library not installed")
    
    def _extract_tar(self, filepath: str, extract_dir: str) -> List[str]:
        """Extract TAR/TAR.GZ archive"""
        import tarfile
        extracted = []
        mode = 'r:gz' if filepath.endswith(('.gz', '.tgz')) else 'r'
        with tarfile.open(filepath, mode) as tf:
            for member in tf.getmembers():
                if member.isfile():
                    safe_name = os.path.basename(member.name)
                    if not safe_name:
                        safe_name = member.name.replace('/', '_').replace('\\', '_')
                    target_path = os.path.join(extract_dir, safe_name)
                    
                    source = tf.extractfile(member)
                    if source:
                        with open(target_path, 'wb') as target:
                            shutil.copyfileobj(source, target)
                        extracted.append(target_path)
        return extracted
    
    def _extract_gzip(self, filepath: str, extract_dir: str) -> List[str]:
        """Extract GZIP file"""
        import gzip
        extracted = []
        base_name = os.path.basename(filepath)
        if base_name.endswith('.gz'):
            base_name = base_name[:-3]
        else:
            base_name = base_name + '_decompressed'
        
        target_path = os.path.join(extract_dir, base_name)
        with gzip.open(filepath, 'rb') as source:
            with open(target_path, 'wb') as target:
                shutil.copyfileobj(source, target)
        extracted.append(target_path)
        return extracted
    
    def _extract_iso(self, filepath: str, extract_dir: str) -> List[str]:
        """Extract ISO image"""
        try:
            import pycdlib
            extracted = []
            iso = pycdlib.PyCdlib()
            iso.open(filepath)
            
            for dirname, dirlist, filelist in iso.walk(iso_path='/'):
                for filename in filelist:
                    iso_path = f"{dirname}/{filename}" if dirname != '/' else f"/{filename}"
                    # Clean up ISO filename (remove version number)
                    clean_name = filename.split(';')[0]
                    target_path = os.path.join(extract_dir, clean_name)
                    
                    with open(target_path, 'wb') as f:
                        iso.get_file_from_iso_fp(f, iso_path=iso_path)
                    extracted.append(target_path)
            
            iso.close()
            return extracted
        except ImportError:
            raise Exception("pycdlib library not installed")
    
    def _extract_vhd(self, filepath: str, extract_dir: str) -> List[str]:
        """Extract VHD/VHDX image - requires Windows or specific tools"""
        # VHD extraction is complex and platform-specific
        # On Windows, could use diskpart or PowerShell
        # For cross-platform, would need vhd-file or similar library
        raise Exception("VHD extraction not fully implemented - requires platform-specific tools")
    
    def cleanup(self, result: ExtractionResult):
        """Clean up temporary extraction directory"""
        if result.temp_dir and os.path.exists(result.temp_dir):
            shutil.rmtree(result.temp_dir, ignore_errors=True)
