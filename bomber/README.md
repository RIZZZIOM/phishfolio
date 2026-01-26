  
```
▄▄▄▄   ▄▄▄  ▄▄   ▄▄ ▄▄▄▄  ▄▄▄▄▄ ▄▄▄▄  
██▄██ ██▀██ ██▀▄▀██ ██▄██ ██▄▄  ██▄█▄ 
██▄█▀ ▀███▀ ██   ██ ██▄█▀ ██▄▄▄ ██ ██ 
```

A Go-based archive bomb generator.

**⚠️ Disclaimer**: **This tool is for educational and authorized security testing only. Do not use maliciously or against systems you don't own or have permission to test. The author is not responsible for any misuse.**

## Features

Bomber implements two zip bomb generation methods:

### 1. Recursive Method (42.zip style)

- Creates nested ZIP archives that expand exponentially
- Each layer contains N ZIP files, each containing more ZIP files
- Final layer contains files filled with zeros (highly compressible)
- Example: 5 layers × 16 files = 16^5 = 1,048,576 files

### 2. Overlapping Method (Fifield 2019)

- Creates a single ZIP with multiple file entries pointing to the same compressed data
- Non-recursive: all files extracted in a single pass
- Maximum 65,535 files (ZIP format limit without ZIP64 extension)
- Based on David Fifield's research: https://www.bamsoftware.com/hacks/zipbomb/

## Installation

```bash
git clone https://github.com/RIZZZIOM/phishfolio
cd phishfolio/bomber
go build -o bomber.exe .
```

## Usage

```bash
$ .\bomber.exe -h

▄▄▄▄   ▄▄▄  ▄▄   ▄▄ ▄▄▄▄  ▄▄▄▄▄ ▄▄▄▄  
██▄██ ██▀██ ██▀▄▀██ ██▄██ ██▄▄  ██▄█▄ 
██▄█▀ ▀███▀ ██   ██ ██▄█▀ ██▄▄▄ ██ ██ 

        by: github.com/RIZZZIOM

Usage: bomber -method <recursive|overlap> [options]

Options:
  -count int
        Number of overlapping file entries (overlap method) (default 1000)
  -files int
        Number of files per layer (recursive method) (default 16)
  -info
        Show bomb statistics without generating
  -layers int
        Number of nesting layers (recursive method) (default 5)
  -method string
        Bomb method: 'recursive' (42.zip style) or 'overlap' (non-recursive) [REQUIRED]
  -output string
        Output filename (default "bomb.zip")
  -size int
        Base file size in bytes (default 100MB) (default 104857600)

Examples:
  bomber -method recursive -layers 5 -files 16 -output bomb.zip
  bomber -method overlap -count 10000 -size 1073741824 -output flat_bomb.zip
  bomber -method recursive -info  # Show statistics only

```

- Generate recursive bomb (42.zip style)

```  
$ bomber -method recursive -layers 5 -files 16 -size 104857600 -output bomb.zip
```

- Generate overlapping bomb (Fifield method)

```
bomber -method overlap -count 10000 -size 1073741824 -output flat_bomb.zip

```

- Show statistics only (don't generate)

```
bomber -method recursive -layers 6 -files 16 -info
```

### Command-Line Options

| **FLAG**  | **DESCRIPTION**                             | **DEFAULT**         |
| --------- | ------------------------------------------- | ------------------- |
| `-method` | Bomb method: `recursive` or `overlap`       | `recursive`         |
| `-output` | Output filename                             | `bomb.zip`          |
| `-layers` | Number of nesting layers (recursive)        | `5`                 |
| `-files`  | Files per layer (recursive)                 | `16`                |
| `-size`   | Base file size in bytes                     | `104857600` (100MB) |
| `-count`  | Number of file entries (overlap, max 65535) | `1000`              |
| `-info`   | Show statistics only                        | `false`             |

## Examples

- Small Test Bomb : Creates a 3-layer bomb with 1,000 files, each 10MB when decompressed.

```bash
$ bomber -method recursive -layers 3 -files 10 -size 10485760 -output test.zip
```

- Large Recursive Bomb : Creates ~1 million files, each 1GB when decompressed (~1 exabyte total).

```bash
bomber -method recursive -layers 5 -files 16 -size 1073741824 -output big.zip
```

- Overlapping Bomb : Creates 65,535 files (ZIP max without ZIP64) all pointing to the same 10GB data block (~655 TB total).

```bash
bomber -method overlap -count 65535 -size 10737418240 -output overlap.zip
```

## How It Works

### Recursive Method

Each layer multiplies the file count by `filesPerLayer`. The innermost files contain highly compressible zero bytes.

```
bomb.zip (42 KB)
├── 0.zip (2.5 KB)
│   ├── 0.zip (100 bytes)
│   │   └── 0 (zeros → 100MB)
│   ├── 1.zip (100 bytes)
│   │   └── 0 (zeros → 100MB)
│   └── ...
├── 1.zip (2.5 KB)
│   └── ...
└── ...
```

### Overlapping Method

A valid ZIP file where all central directory entries reference the same compressed data block. Most ZIP extractors will happily extract N copies of the same data.

```
bomb.zip
├── [Local Header for file 0]
├── [Compressed Data Block] ← All files share this!
├── [Central Directory]
│   ├── Entry 0 → points to data block
│   ├── Entry 1 → points to data block  
│   ├── Entry 2 → points to data block
│   └── ...
└── [End of Central Directory]
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE.txt) file for details.

---