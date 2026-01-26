"""
Suspicious pattern analyzer for NestHunter.
Detects malware delivery patterns and zip bomb indicators.
"""

from dataclasses import dataclass
from typing import List, Dict, Optional
from enum import Enum


class Severity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SuspiciousPattern:
    """Represents a detected suspicious pattern"""
    pattern_type: str
    description: str
    severity: Severity
    path: str
    details: Optional[Dict] = None
    
    def to_dict(self) -> dict:
        return {
            'pattern_type': self.pattern_type,
            'description': self.description,
            'severity': self.severity.value,
            'path': self.path,
            'details': self.details
        }


class PatternAnalyzer:
    """Analyzes extraction results for suspicious patterns"""
    
    # Known malware delivery patterns
    MALWARE_NESTING_PATTERNS = [
        # ISO containing executable archives - common in malware campaigns
        {'parent': 'iso', 'child': 'zip', 'severity': Severity.HIGH,
         'description': 'ISO containing ZIP - common malware delivery method'},
        {'parent': 'iso', 'child': 'rar', 'severity': Severity.HIGH,
         'description': 'ISO containing RAR - common malware delivery method'},
        {'parent': 'iso', 'child': '7z', 'severity': Severity.HIGH,
         'description': 'ISO containing 7z - potential malware delivery'},
        
        # VHD used to bypass email filters
        {'parent': 'vhd', 'child': 'zip', 'severity': Severity.CRITICAL,
         'description': 'VHD containing ZIP - advanced evasion technique'},
        {'parent': 'vhd', 'child': 'rar', 'severity': Severity.CRITICAL,
         'description': 'VHD containing RAR - advanced evasion technique'},
        
        # Double-packed archives
        {'parent': 'zip', 'child': 'zip', 'severity': Severity.MEDIUM,
         'description': 'Double-packed ZIP - possible evasion attempt'},
        {'parent': 'rar', 'child': 'rar', 'severity': Severity.MEDIUM,
         'description': 'Double-packed RAR - possible evasion attempt'},
    ]
    
    # Suspicious file extensions
    EXECUTABLE_EXTENSIONS = {
        '.exe': Severity.HIGH,
        '.dll': Severity.HIGH,
        '.scr': Severity.HIGH,
        '.com': Severity.HIGH,
        '.pif': Severity.HIGH,
        '.bat': Severity.MEDIUM,
        '.cmd': Severity.MEDIUM,
        '.ps1': Severity.HIGH,
        '.vbs': Severity.HIGH,
        '.vbe': Severity.HIGH,
        '.js': Severity.MEDIUM,
        '.jse': Severity.MEDIUM,
        '.wsf': Severity.HIGH,
        '.wsh': Severity.HIGH,
        '.msi': Severity.MEDIUM,
        '.msp': Severity.MEDIUM,
        '.hta': Severity.HIGH,
        '.cpl': Severity.HIGH,
        '.jar': Severity.MEDIUM,
        '.reg': Severity.MEDIUM,
        '.lnk': Severity.HIGH,  # Shortcut files - very suspicious in archives
    }
    
    # Extension combinations that indicate masquerading
    MASQUERADE_PATTERNS = [
        # Document extensions hiding executables
        ('.pdf.exe', Severity.CRITICAL),
        ('.doc.exe', Severity.CRITICAL),
        ('.docx.exe', Severity.CRITICAL),
        ('.xls.exe', Severity.CRITICAL),
        ('.xlsx.exe', Severity.CRITICAL),
        ('.jpg.exe', Severity.CRITICAL),
        ('.png.exe', Severity.CRITICAL),
        ('.mp3.exe', Severity.CRITICAL),
        ('.mp4.exe', Severity.CRITICAL),
        # Script extensions
        ('.pdf.js', Severity.HIGH),
        ('.doc.vbs', Severity.HIGH),
        ('.jpg.scr', Severity.CRITICAL),
    ]
    
    # Zip bomb indicators
    ZIP_BOMB_INDICATORS = {
        'compression_ratio': 100,  # If extracted size > 100x compressed
        'nested_depth': 5,  # More than 5 levels of same archive type
        'file_count': 10000,  # More than 10k files in single archive
    }
    
    def __init__(self):
        self.patterns_found: List[SuspiciousPattern] = []
    
    def analyze(self, extraction_result) -> List[SuspiciousPattern]:
        """
        Analyze extraction result for suspicious patterns.
        
        Args:
            extraction_result: ExtractionResult from extractor
            
        Returns:
            List of detected suspicious patterns
        """
        self.patterns_found = []
        
        # Analyze the tree structure
        self._analyze_node(extraction_result.root, parent_type=None, nesting_chain=[])
        
        # Check for zip bomb indicators
        self._check_zip_bomb_indicators(extraction_result)
        
        # Check for file reuse (same hash appearing multiple times)
        self._analyze_hash_reuse(extraction_result.hash_collisions)
        
        # Check overall depth
        if extraction_result.max_depth_reached >= 5:
            self.patterns_found.append(SuspiciousPattern(
                pattern_type='excessive_nesting',
                description=f'Archive nested {extraction_result.max_depth_reached} levels deep',
                severity=Severity.HIGH if extraction_result.max_depth_reached >= 7 else Severity.MEDIUM,
                path=extraction_result.root.path,
                details={'depth': extraction_result.max_depth_reached}
            ))
        
        # Check for single-file archive chains
        self._analyze_single_file_chains(extraction_result.root, chain=[])
        
        # Check for MIME type mismatches
        if hasattr(extraction_result, 'mime_mismatches') and extraction_result.mime_mismatches:
            for mismatch in extraction_result.mime_mismatches:
                self.patterns_found.append(SuspiciousPattern(
                    pattern_type='mime_mismatch',
                    description=f"MIME type mismatch: expected {mismatch['expected']}, got {mismatch['actual']}",
                    severity=Severity.HIGH,
                    path=mismatch['path'],
                    details=mismatch
                ))
        
        # Check cumulative size for zip bomb
        if hasattr(extraction_result, 'cumulative_extracted_size'):
            original = extraction_result.root.size
            extracted = extraction_result.cumulative_extracted_size
            if original > 0 and extracted > 0:
                ratio = extracted / original
                if ratio > self.ZIP_BOMB_INDICATORS['compression_ratio']:
                    self.patterns_found.append(SuspiciousPattern(
                        pattern_type='cumulative_size_bomb',
                        description=f'Cumulative extraction ratio extremely high ({ratio:.1f}:1)',
                        severity=Severity.CRITICAL,
                        path=extraction_result.root.path,
                        details={
                            'original_size': original,
                            'cumulative_extracted': extracted,
                            'ratio': ratio
                        }
                    ))
        
        return self.patterns_found
    
    def _analyze_node(self, node, parent_type: Optional[str], nesting_chain: List[str]):
        """Recursively analyze nodes for patterns"""
        
        current_type = node.file_type.value if node.is_archive else None
        
        # Update nesting chain
        if current_type:
            new_chain = nesting_chain + [current_type]
        else:
            new_chain = nesting_chain
        
        # Check nesting patterns
        if parent_type and current_type:
            for pattern in self.MALWARE_NESTING_PATTERNS:
                if pattern['parent'] == parent_type and pattern['child'] == current_type:
                    self.patterns_found.append(SuspiciousPattern(
                        pattern_type='malware_nesting',
                        description=pattern['description'],
                        severity=pattern['severity'],
                        path=node.path,
                        details={
                            'parent_type': parent_type,
                            'child_type': current_type,
                            'chain': new_chain
                        }
                    ))
        
        # Check filename for suspicious extensions
        self._check_filename(node)
        
        # Recurse into children
        for child in node.children:
            self._analyze_node(child, current_type if node.is_archive else parent_type, new_chain)
    
    def _check_filename(self, node):
        """Check filename for suspicious patterns"""
        filename = node.name.lower()
        
        # Check for executable extensions
        for ext, severity in self.EXECUTABLE_EXTENSIONS.items():
            if filename.endswith(ext):
                self.patterns_found.append(SuspiciousPattern(
                    pattern_type='executable_in_archive',
                    description=f'Executable file ({ext}) found in archive',
                    severity=severity,
                    path=node.path,
                    details={'extension': ext, 'filename': node.name}
                ))
                break
        
        # Check for masquerading patterns
        for pattern, severity in self.MASQUERADE_PATTERNS:
            if filename.endswith(pattern.lower()):
                self.patterns_found.append(SuspiciousPattern(
                    pattern_type='extension_masquerading',
                    description=f'File appears to masquerade as different type ({pattern})',
                    severity=severity,
                    path=node.path,
                    details={'pattern': pattern, 'filename': node.name}
                ))
                break
        
        # Check for hidden files (starting with dot)
        if node.name.startswith('.') and node.depth > 0:
            self.patterns_found.append(SuspiciousPattern(
                pattern_type='hidden_file',
                description='Hidden file detected in archive',
                severity=Severity.LOW,
                path=node.path,
                details={'filename': node.name}
            ))
        
        # Check for unicode tricks in filename
        if any(ord(c) > 127 for c in node.name):
            self.patterns_found.append(SuspiciousPattern(
                pattern_type='unicode_filename',
                description='Filename contains non-ASCII characters (potential RLO attack)',
                severity=Severity.MEDIUM,
                path=node.path,
                details={'filename': node.name}
            ))
    
    def _check_zip_bomb_indicators(self, result):
        """Check for zip bomb indicators"""
        # Calculate total extracted size
        total_size = self._calculate_total_size(result.root)
        original_size = result.root.size
        
        if original_size > 0:
            ratio = total_size / original_size
            if ratio > self.ZIP_BOMB_INDICATORS['compression_ratio']:
                self.patterns_found.append(SuspiciousPattern(
                    pattern_type='zip_bomb_indicator',
                    description=f'Extreme compression ratio detected ({ratio:.1f}x)',
                    severity=Severity.CRITICAL,
                    path=result.root.path,
                    details={
                        'original_size': original_size,
                        'extracted_size': total_size,
                        'ratio': ratio
                    }
                ))
        
        # Check file count
        if result.total_files > self.ZIP_BOMB_INDICATORS['file_count']:
            self.patterns_found.append(SuspiciousPattern(
                pattern_type='zip_bomb_indicator',
                description=f'Excessive file count ({result.total_files} files)',
                severity=Severity.HIGH,
                path=result.root.path,
                details={'file_count': result.total_files}
            ))
    
    def _calculate_total_size(self, node) -> int:
        """Calculate total size of node and all children"""
        total = node.size
        for child in node.children:
            total += self._calculate_total_size(child)
        return total
    
    def _analyze_hash_reuse(self, hash_collisions: Dict[str, List[str]]):
        """Analyze files that appear multiple times"""
        for sha256, paths in hash_collisions.items():
            if len(paths) > 2:
                self.patterns_found.append(SuspiciousPattern(
                    pattern_type='excessive_file_reuse',
                    description=f'Same file appears {len(paths)} times in archive',
                    severity=Severity.MEDIUM,
                    path=paths[0],
                    details={
                        'sha256': sha256,
                        'occurrences': len(paths),
                        'paths': paths
                    }
                ))
    
    def _analyze_single_file_chains(self, node, chain: List[dict]):
        """
        Detect single-file archive chains (matryoshka pattern).
        Archives that contain only one file, which is also an archive.
        """
        if node.is_archive:
            # Check if this archive has exactly one child and it's an archive
            archive_children = [c for c in node.children if c.is_archive]
            non_archive_children = [c for c in node.children if not c.is_archive]
            
            if len(node.children) == 1 and len(archive_children) == 1:
                # Single-file archive containing another archive
                new_chain = chain + [{
                    'name': node.name,
                    'type': node.file_type.value,
                    'path': node.path
                }]
                
                # Continue analysis on the nested archive
                self._analyze_single_file_chains(archive_children[0], new_chain)
            elif chain:
                # End of chain - check if it was suspicious
                final_chain = chain + [{
                    'name': node.name,
                    'type': node.file_type.value,
                    'path': node.path
                }]
                
                if len(final_chain) >= 3:
                    chain_desc = ' → '.join([f"{c['type']}" for c in final_chain])
                    self.patterns_found.append(SuspiciousPattern(
                        pattern_type='single_file_archive_chain',
                        description=f'Single-file archive chain: {chain_desc}',
                        severity=Severity.HIGH if len(final_chain) >= 4 else Severity.MEDIUM,
                        path=final_chain[0]['path'],
                        details={
                            'chain_length': len(final_chain),
                            'chain': final_chain
                        }
                    ))
                
                # Also recurse into children for any other patterns
                for child in node.children:
                    self._analyze_single_file_chains(child, [])
            else:
                # Not a single-file archive, recurse normally
                for child in node.children:
                    self._analyze_single_file_chains(child, [])
        else:
            # Regular file, check children if any
            for child in node.children:
                self._analyze_single_file_chains(child, chain)
    
    def get_summary(self) -> dict:
        """Get analysis summary"""
        severity_counts = {s.value: 0 for s in Severity}
        for pattern in self.patterns_found:
            severity_counts[pattern.severity.value] += 1
        
        # Calculate risk score (0-100)
        risk_score = min(100, (
            severity_counts['critical'] * 30 +
            severity_counts['high'] * 15 +
            severity_counts['medium'] * 5 +
            severity_counts['low'] * 1
        ))
        
        return {
            'total_patterns': len(self.patterns_found),
            'severity_counts': severity_counts,
            'risk_score': risk_score,
            'risk_level': self._get_risk_level(risk_score),
            'patterns': [p.to_dict() for p in self.patterns_found]
        }
    
    def _get_risk_level(self, score: int) -> str:
        """Convert risk score to risk level"""
        if score >= 70:
            return 'critical'
        elif score >= 40:
            return 'high'
        elif score >= 20:
            return 'medium'
        elif score > 0:
            return 'low'
        return 'clean'
