package main

import (
	"archive/zip"
	"fmt"
	"regexp"
	"strings"
)

// Global variable to collect all packer detection results
var (
    allPackResults []string
)

// Clear all packer detection results
func clearPackResults() {
    allPackResults = []string{}
}

func PackByLibSo(apkReader *zip.Reader) bool {
    // Clear previous detection results
    clearPackResults()

    // Get packer feature map
    apkmap := GetApkPackMap()
    if apkmap == nil {
        fmt.Printf("Error retrieving packer features\n")
        return false
    }

    // Iterate file path lists
    for key, value := range apkmap {
        for _, s := range value.Sopath {
            for _, file := range apkReader.File {
                if file.Name == s {
                    // Output and collect result
                    //fmt.Printf("Found packer feature Sopath  %s->%s\n", key, file.Name)
                    result := fmt.Sprintf("    Sopath  %s -> %s", key, file.Name)
                    allPackResults = append(allPackResults, result)
                }
            }
        }
        for _, s := range value.Soname {
            for _, file := range apkReader.File {
                if strings.Contains(file.Name, s) {
                    // Output and collect result
                    //fmt.Printf("Found packer feature Soname  %s->%s\n", key, file.Name)
                    result := fmt.Sprintf("    Soname  %s -> %s", key, file.Name)
                    allPackResults = append(allPackResults, result)
                }
            }
        }
        for _, s := range value.Other {
            for _, file := range apkReader.File {
                if strings.Contains(file.Name, s) {
                    // Output and collect result
                    //fmt.Printf("Found packer feature Other   %s->%s\n", key, file.Name)
                    result := fmt.Sprintf("    Other  %s -> %s", key, file.Name)
                    allPackResults = append(allPackResults, result)
                }
            }
        }
        for _, s := range value.Soregex {
            for _, file := range apkReader.File {
                re := regexp.MustCompile(s)
                if re.MatchString(file.Name) {
                    // Output and collect result
                    //fmt.Printf("Found packer feature Soregex %s->%s\n", key, file.Name)
                    result := fmt.Sprintf("   Soregex  %s -> %s", key, file.Name)
                    allPackResults = append(allPackResults, result)
                }
            }
        }
    }

    // Output results
    fmt.Println("\n===================== Packer Feature Scan Results =====================")
    
    if len(allPackResults) > 0 {
        fmt.Println("\n[Packer Features]")
        for _, result := range allPackResults {
            fmt.Println(result)
        }
    } else {
        fmt.Println("\nNo packer features found")
    }
    
    // fmt.Println("\n================================================================")

    return true
}
