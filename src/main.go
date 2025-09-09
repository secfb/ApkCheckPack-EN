package main

import (
	"archive/zip"
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Command-line arguments - exported for other packages
var (
	// File path argument
	ArgFilePath = flag.String("f", "", "Specify APK file path or directory")

	// Detection type arguments
	ArgCheckRoot     = flag.Bool("root", true, "Enable ROOT detection")
	ArgCheckEmu      = flag.Bool("emu", true, "Enable emulator detection")
	ArgCheckDebug    = flag.Bool("debug", true, "Enable anti-debug detection")
	ArgCheckProxy    = flag.Bool("proxy", true, "Enable proxy detection")
	ArgCheckSDK      = flag.Bool("sdk", true, "Enable third-party SDK detection")
	ArgCheckHardcode = flag.Bool("hardcode", false, "Enable hardcode detection")
	ArgCheckCert     = flag.Bool("cert", true, "Enable certificate detection")

	// Scan control arguments
	ArgMaxSize      = flag.Int64("maxsize", 500, "Max scan size per file (MB)")
	ArgRecursive    = flag.Bool("r", true, "Recursively scan embedded APKs")
)

// Print usage
func printUsage() {
	fmt.Println("APK Inspection Tool - Detect features in APK files")
	fmt.Println("\nUsage:")
	fmt.Println("  ApkCheckPack.exe [options] -f <APK file path>")
	
	fmt.Println("\nDetection types:")
	fmt.Println("  -root      Enable ROOT detection (default: on)")
	fmt.Println("  -emu       Enable emulator detection (default: on)")
	fmt.Println("  -debug     Enable anti-debug detection (default: on)")
	fmt.Println("  -proxy     Enable proxy detection (default: on)")
	fmt.Println("  -sdk       Enable third-party SDK detection (default: on)")
	fmt.Println("  -hardcode  Enable hardcode detection (default: off)")
	fmt.Println("  -cert      Enable certificate detection (default: on)")
	
	fmt.Println("\nScan control:")
	fmt.Println("  -maxsize   Max size per file (MB) (default: 500)")
	fmt.Println("  -r         Recursively scan embedded APKs (default: on)")
	
	fmt.Println("\nExamples:")
	fmt.Println("  ApkCheckPack.exe -f test.apk")
	fmt.Println("  ApkCheckPack.exe -f test.apk -hardcode")
	fmt.Println("  ApkCheckPack.exe -f ./apks -r=false -maxsize 100")
}

func main() {
	// Add help flag
	helpFlag := flag.Bool("help", false, "Show help information")
	flag.Parse()

	// Show help information
	if *helpFlag || len(os.Args) < 2 {
		printUsage()
		return
	}

	// Validate required arguments
	if *ArgFilePath == "" {
		fmt.Println("Error: APK file path or folder path is required")
		fmt.Println("Use -help to view help")
		return
	}

	// Show scan configuration
	fmt.Println("APK Inspection Tool - Scan configuration:")
	fmt.Printf("- File path: %s\n", *ArgFilePath)
	fmt.Printf("- Detection types: ROOT(%v) Emulator(%v) Anti-debug(%v) Proxy(%v) SDK(%v) Hardcode(%v) Certificate(%v)\n", 
		*ArgCheckRoot, *ArgCheckEmu, *ArgCheckDebug, *ArgCheckProxy, *ArgCheckSDK, *ArgCheckHardcode, *ArgCheckCert)
	fmt.Printf("- Max file size: %d MB\n", *ArgMaxSize)
	fmt.Printf("- Recursive scan: %v\n", *ArgRecursive)
	fmt.Println("---------------------------------------------------")
	
	// Check if path is valid
	info, err := os.Stat(*ArgFilePath)
	if err != nil {
		fmt.Printf("Error: Invalid path: %s\n", *ArgFilePath)
		return
	}

	if info.IsDir() {
		err := scanAPKFolder(*ArgFilePath)
		if err != nil {
			fmt.Printf("Failed to scan APK folder %s: %v\n", *ArgFilePath, err)
		}
	} else {
		err := scanAPKFile(*ArgFilePath)
		if err != nil {
			fmt.Printf("Failed to scan APK file %s: %v\n", *ArgFilePath, err)
		}
	}
}

func scanAPKFolder(folderPath string) error {
	fileList := []string{}

	err := filepath.Walk(folderPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasSuffix(path, ".apk") {
			fileList = append(fileList, path)
		}

		return nil
	})

	if err != nil {
		return err
	}

	for _, filePath := range fileList {

		//fmt.Printf("Scanning APK file %s\n", filePath)
		err := scanAPKFile(filePath)
		if err != nil {
			fmt.Printf("Failed to scan APK file %s: %v\n", filePath, err)
		}
	}

	return nil
}

func scanAPKFile(filePath string) error {

	// Open APK file
	apkReader, err := zip.OpenReader(filePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return nil
	}
	defer apkReader.Close()

	// Scan main APK
	fmt.Printf("Scanning APK file: %s\n", filePath)

	ScanAPKData(&apkReader.Reader)

	// If recursive scanning is enabled, scan embedded APKs
	if *ArgRecursive {
		scanEmbeddedAPKs(&apkReader.Reader)
	}
	
	return nil
}

// Scan embedded APK files
func scanEmbeddedAPKs(apkReader *zip.Reader) {
	for _, file := range apkReader.File {
		if path.Ext(file.Name) != ".apk" {
			continue
		}

		fmt.Printf("\tFound embedded APK file: %s\n", file.Name)
		
		if err := scanSingleEmbeddedAPK(file); err != nil {
			fmt.Printf("\tFailed to process embedded APK file %s: %v\n", file.Name, err)
		}
	}
}

// Calculate an appropriate file size limit
func calculateSizeLimit(fileSize int64) int64 {
	// Get user-configured max limit (MB to bytes)
	maxLimit := int64(1024 * 1024 * (*ArgMaxSize))

	// If file size is known and smaller than the max limit, use it
	if fileSize > 0 && fileSize < maxLimit {
		return fileSize
	}

	// Otherwise, use the max limit
	return maxLimit
}

// Scan a single embedded APK file
func scanSingleEmbeddedAPK(file *zip.File) error {
	// Get file size
	fileSize := int64(file.UncompressedSize64)

	// Open embedded APK file
	fileReader, err := file.Open()
	if err != nil {
		return fmt.Errorf("Failed to open embedded APK: %v", err)
	}

	// Use an anonymous function to ensure resources are released
	err = func() error {
		defer fileReader.Close()

		// Calculate an appropriate size limit
		sizeLimit := calculateSizeLimit(fileSize)

		// If file size is known, print info
		if fileSize > 0 {
			fmt.Printf("\tEmbedded APK size: %.2f MB, read limit: %.2f MB\n", 
				float64(fileSize)/(1024*1024), 
				float64(sizeLimit)/(1024*1024))
		}

		// Create a size-limited reader
		limitReader := io.LimitReader(fileReader, sizeLimit)

		// Read APK content in chunks
		var buffer bytes.Buffer
		_, err := io.Copy(&buffer, limitReader)
		if err != nil {
			return fmt.Errorf("Failed to read embedded APK content: %v", err)
		}

		// Create a zip reader
		apkData := buffer.Bytes()
		embeddedReader, err := zip.NewReader(bytes.NewReader(apkData), int64(len(apkData)))
		if err != nil {
			return fmt.Errorf("Failed to parse embedded APK: %v", err)
		}

		// Scan embedded APK
		ScanAPKData(embeddedReader)
		return nil
	}()

	return err
}

// Read the APK into memory and pass it in
func ScanAPKData(apkReader *zip.Reader) error {
	//verifyApk(filePath) //20241230 temporarily disabled signature verification to reduce program size

	// Detect packer/hardening features
	PackByLibSo(apkReader)

	// Run security checks based on flags
	if *ArgCheckRoot || *ArgCheckEmu || *ArgCheckDebug || *ArgCheckProxy {
		ScanAPKAnti(apkReader)
	}

	// Perform SDK detection
	if *ArgCheckSDK {
		SDKByLibSo(apkReader)
	}

	// Run hardcode detection based on flag
	if *ArgCheckHardcode {
		ScanAPKHardCoded(apkReader)
	}

	// Run certificate detection based on flag
	if *ArgCheckCert {
		ScanAPKCertificate(apkReader)
	}
	
	return nil
}
