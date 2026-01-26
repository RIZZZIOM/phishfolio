/*
Bomber - Archive Bomb Generator Tool
Educational tool for security research and testing archive scanners.

Supports:
- Recursive method (42.zip style nested archives)
- Non-recursive method (overlapping file entries - Fifield 2019)

WARNING: This tool is for educational and authorized security testing only.
Do not use maliciously or against systems you don't own/have permission to test.
*/

package main

import (
	"flag"
	"fmt"
	"os"

	"bomber/generator"
)

const banner = `
                                      
▄▄▄▄   ▄▄▄  ▄▄   ▄▄ ▄▄▄▄  ▄▄▄▄▄ ▄▄▄▄  
██▄██ ██▀██ ██▀▄▀██ ██▄██ ██▄▄  ██▄█▄ 
██▄█▀ ▀███▀ ██   ██ ██▄█▀ ██▄▄▄ ██ ██ 
                                      
	by: github.com/RIZZZIOM
`

func main() {
	// Define flags
	method := flag.String("method", "", "Bomb method: 'recursive' (42.zip style) or 'overlap' (non-recursive) [REQUIRED]")
	output := flag.String("output", "bomb.zip", "Output filename")

	// Recursive method flags
	layers := flag.Int("layers", 5, "Number of nesting layers (recursive method)")
	filesPerLayer := flag.Int("files", 16, "Number of files per layer (recursive method)")
	baseSize := flag.Int64("size", 1024*1024*100, "Base file size in bytes (default 100MB)")

	// Non-recursive method flags
	numFiles := flag.Int("count", 1000, "Number of overlapping file entries (overlap method)")

	// General flags
	showInfo := flag.Bool("info", false, "Show bomb statistics without generating")

	flag.Usage = func() {
		fmt.Println(banner)
		fmt.Println("Usage: bomber -method <recursive|overlap> [options]")
		fmt.Println("\nOptions:")
		flag.PrintDefaults()
		fmt.Println("\nExamples:")
		fmt.Println("  bomber -method recursive -layers 5 -files 16 -output bomb.zip")
		fmt.Println("  bomber -method overlap -count 10000 -size 1073741824 -output flat_bomb.zip")
		fmt.Println("  bomber -method recursive -info  # Show statistics only")
	}

	flag.Parse()

	fmt.Print(banner)

	// Require method to be specified
	if *method == "" {
		fmt.Println("[-] Error: -method flag is required")
		fmt.Println("    Use: -method recursive  OR  -method overlap")
		fmt.Println("\nRun 'bomber -h' for help")
		os.Exit(1)
	}

	// Validate method
	if *method != "recursive" && *method != "overlap" {
		fmt.Printf("[-] Error: Unknown method '%s'\n", *method)
		fmt.Println("    Use: -method recursive  OR  -method overlap")
		os.Exit(1)
	}

	config := generator.BombConfig{
		Method:        *method,
		OutputFile:    *output,
		Layers:        *layers,
		FilesPerLayer: *filesPerLayer,
		BaseSize:      *baseSize,
		NumFiles:      *numFiles,
	}

	// Calculate and display statistics
	stats := generator.CalculateStats(config)
	printStats(stats)

	if *showInfo {
		return
	}

	fmt.Println("\n[*] Generating archive bomb...")
	fmt.Printf("[*] Method: %s\n", *method)
	fmt.Printf("[*] Output: %s\n", *output)

	var err error
	switch *method {
	case "recursive":
		err = generator.GenerateRecursive(config)
	case "overlap":
		err = generator.GenerateOverlapping(config)
	}

	if err != nil {
		fmt.Printf("[-] Error: %v\n", err)
		os.Exit(1)
	}

	// Get output file size
	if info, err := os.Stat(*output); err == nil {
		fmt.Printf("\n[+] Success! Generated: %s (%s)\n", *output, formatSize(info.Size()))
		fmt.Printf("[+] Compression ratio: %s : 1\n", formatRatio(stats.DecompressedSize, info.Size()))
	}
}

func printStats(stats generator.BombStats) {
	fmt.Println("\n╔══════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                        BOMB STATISTICS                           ║")
	fmt.Println("╠══════════════════════════════════════════════════════════════════╣")
	fmt.Printf("║  Method:              %-43s ║\n", stats.Method)
	fmt.Printf("║  Total Files:         %-43s ║\n", formatNumber(stats.TotalFiles))
	fmt.Printf("║  Decompressed Size:   %-43s ║\n", formatSize(stats.DecompressedSize))
	fmt.Printf("║  Estimated Zip Size:  %-43s ║\n", formatSize(stats.EstimatedZipSize))
	fmt.Printf("║  Compression Ratio:   %-43s ║\n", formatRatio(stats.DecompressedSize, stats.EstimatedZipSize))
	if stats.Layers > 0 {
		fmt.Printf("║  Nesting Layers:      %-43d ║\n", stats.Layers)
	}
	fmt.Println("╚══════════════════════════════════════════════════════════════════╝")
}

func formatSize(bytes int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
		TB = GB * 1024
		PB = TB * 1024
	)

	switch {
	case bytes >= PB:
		return fmt.Sprintf("%.2f PB", float64(bytes)/float64(PB))
	case bytes >= TB:
		return fmt.Sprintf("%.2f TB", float64(bytes)/float64(TB))
	case bytes >= GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/float64(GB))
	case bytes >= MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/float64(MB))
	case bytes >= KB:
		return fmt.Sprintf("%.2f KB", float64(bytes)/float64(KB))
	default:
		return fmt.Sprintf("%d bytes", bytes)
	}
}

func formatNumber(n int64) string {
	if n >= 1_000_000_000 {
		return fmt.Sprintf("%.2f billion", float64(n)/1_000_000_000)
	}
	if n >= 1_000_000 {
		return fmt.Sprintf("%.2f million", float64(n)/1_000_000)
	}
	if n >= 1_000 {
		return fmt.Sprintf("%.2f thousand", float64(n)/1_000)
	}
	return fmt.Sprintf("%d", n)
}

func formatRatio(decompressed, compressed int64) string {
	if compressed == 0 {
		return "∞"
	}
	ratio := float64(decompressed) / float64(compressed)
	if ratio >= 1_000_000_000 {
		return fmt.Sprintf("%.2f billion", ratio/1_000_000_000)
	}
	if ratio >= 1_000_000 {
		return fmt.Sprintf("%.2f million", ratio/1_000_000)
	}
	if ratio >= 1_000 {
		return fmt.Sprintf("%.2f thousand", ratio/1_000)
	}
	return fmt.Sprintf("%.2f", ratio)
}
