/*
Package generator provides zip bomb generation algorithms.

Implements two methods:
1. Recursive (42.zip style) - Nested archives that expand exponentially
2. Overlapping (Fifield method) - Single-layer with shared compressed data
*/

package generator

import (
	"math"
)

// BombConfig holds configuration for bomb generation
type BombConfig struct {
	Method        string // "recursive" or "overlap"
	OutputFile    string
	Layers        int   // For recursive method
	FilesPerLayer int   // For recursive method
	BaseSize      int64 // Size of base file (zeros)
	NumFiles      int   // For overlap method
}

// BombStats contains calculated statistics about the bomb
type BombStats struct {
	Method           string
	TotalFiles       int64
	DecompressedSize int64
	EstimatedZipSize int64
	Layers           int
}

// CalculateStats calculates bomb statistics without generating
func CalculateStats(config BombConfig) BombStats {
	switch config.Method {
	case "recursive":
		return calculateRecursiveStats(config)
	case "overlap":
		return calculateOverlapStats(config)
	default:
		return BombStats{Method: "unknown"}
	}
}

func calculateRecursiveStats(config BombConfig) BombStats {
	// Total files = filesPerLayer^layers
	totalFiles := int64(math.Pow(float64(config.FilesPerLayer), float64(config.Layers)))

	// Each leaf file decompresses to baseSize
	decompressedSize := totalFiles * config.BaseSize

	// Estimate: zeros compress to ~0.1% of original
	// Plus overhead for nested zip structures
	baseCompressed := config.BaseSize / 1000
	if baseCompressed < 100 {
		baseCompressed = 100
	}

	// Each layer adds minimal overhead since it just contains references
	estimatedSize := baseCompressed * int64(config.FilesPerLayer) * int64(config.Layers)

	return BombStats{
		Method:           "Recursive (42.zip style)",
		TotalFiles:       totalFiles,
		DecompressedSize: decompressedSize,
		EstimatedZipSize: estimatedSize,
		Layers:           config.Layers,
	}
}

func calculateOverlapStats(config BombConfig) BombStats {
	// Cap at ZIP format limit (without ZIP64)
	numFiles := config.NumFiles
	if numFiles > 65535 {
		numFiles = 65535
	}

	// Each file entry points to the same data
	decompressedSize := int64(numFiles) * config.BaseSize

	// Only one compressed data block + headers
	// Each central directory entry is ~46 bytes + filename
	// Each local header is ~30 bytes + filename
	headerOverhead := int64(numFiles) * 100 // ~100 bytes per file entry

	// Zeros compress extremely well
	compressedData := config.BaseSize / 1000
	if compressedData < 100 {
		compressedData = 100
	}

	estimatedSize := compressedData + headerOverhead

	return BombStats{
		Method:           "Overlapping (Non-recursive)",
		TotalFiles:       int64(numFiles),
		DecompressedSize: decompressedSize,
		EstimatedZipSize: estimatedSize,
		Layers:           0,
	}
}
