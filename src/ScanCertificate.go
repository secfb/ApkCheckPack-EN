package main

import (
	"archive/zip"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"strings"
)

// Scan APK certificate information
func ScanAPKCertificate(apkReader *zip.Reader) {
    fmt.Printf("\n===================== Certificate Scan Results =====================\n")
	
    // Define certificate file extensions
	certExtensions := []string{
		".CRT",
		".CER",
		".PEM",
		".DER",
		".P12",
		".PFX",
		".RSA",
		".DSA",
	}

	foundCert := false
	for _, file := range apkReader.File {
        // Check if file is a certificate
		isMatch := false
		upperName := strings.ToUpper(file.Name)
		for _, ext := range certExtensions {
			if strings.HasSuffix(upperName, ext) {
				isMatch = true
				break
			}
		}

		if isMatch {
			foundCert = true
            fmt.Printf("\n[Certificate file: %s]\n", file.Name)
			
			rc, err := file.Open()
			if err != nil {
                fmt.Printf("    Unable to open certificate file: %v\n", err)
				continue
			}
			defer rc.Close()
			
			certData, err := io.ReadAll(rc)
			if err != nil {
                fmt.Printf("    Failed to read certificate file: %v\n", err)
				continue
			}
			
        // Parse certificate
			block, _ := pem.Decode(certData)
			if block == nil {
                // If not PEM format, try parsing DER directly
				cert, err := x509.ParseCertificate(certData)
				if err != nil {
                    fmt.Printf("    Failed to parse certificate: %v\n", err)
					continue
				}
				
				printCertificateInfo(cert)
            } else {
                // PEM format certificate
                cert, err := x509.ParseCertificate(block.Bytes)
                if err != nil {
                    fmt.Printf("    Failed to parse certificate: %v\n", err)
                    continue
                }

                printCertificateInfo(cert)
            }
        }
    }

    if !foundCert {
        fmt.Println("\n[!] No certificate files found")
    }
	
	// fmt.Printf("\n================================================================\n")
}

// Print certificate details
func printCertificateInfo(cert *x509.Certificate) {
    fmt.Printf("    Subject: %s\n", cert.Subject.String())
    fmt.Printf("    Issuer: %s\n", cert.Issuer.String())
    fmt.Printf("    Serial Number: %X\n", cert.SerialNumber)
    fmt.Printf("    Validity: %v to %v\n", cert.NotBefore.Format("2006-01-02 15:04:05"), cert.NotAfter.Format("2006-01-02 15:04:05"))
    fmt.Printf("    Signature Algorithm: %s\n", cert.SignatureAlgorithm.String())
	
    // Check if the certificate validity is abnormal
    if cert.NotAfter.Before(cert.NotBefore) {
        fmt.Println("    [!] Warning: Certificate validity period anomaly")
    }

    // Print certificate fingerprint
    fmt.Printf("    SHA1 Fingerprint: %X\n", cert.SubjectKeyId)

    // Print key usage
    fmt.Printf("    Key Usage:")
    if (cert.KeyUsage & x509.KeyUsageDigitalSignature) != 0 {
        fmt.Printf(" Digital Signature")
    }
    if (cert.KeyUsage & x509.KeyUsageKeyEncipherment) != 0 {
        fmt.Printf(" Key Encipherment")
    }
    if (cert.KeyUsage & x509.KeyUsageCertSign) != 0 {
        fmt.Printf(" Certificate Signing")
    }
    fmt.Println()
}
