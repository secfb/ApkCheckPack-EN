package main

import (
	"archive/zip"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

// Define hardcode rule categories
type HardCodeCategory struct {
    Name     string
    Patterns []string
}

// Define hardcode rules by category
var hardCodeCategories = []HardCodeCategory{
    {
        Name: "HAE Sensitive Information",
        Patterns: []string{
			`(?i)password\s*=\s*['"][^'"]{3,}['"]`,
			`(?i)passwd\s*=\s*['"][^'"]{3,}['"]`,
			`(?i)pwd\s*=\s*['"][^'"]{3,}['"]`,
			`(?i)username\s*=\s*['"][^'"]{3,}['"]`,
			`(?i)secret\s*=\s*['"][^'"]{3,}['"]`,
			`(?i)key\s*=\s*['"][^'"]{3,}['"]`,
			`(?i)token\s*=\s*['"][^'"]{3,}['"]`,
			`(?i)auth\s*=\s*['"][^'"]{3,}['"]`,
			`(?i)pass\s*=\s*['"][^'"]{3,}['"]`,
			`(?i)login\s*=\s*['"][^'"]{3,}['"]`,
			`(?i)email\s*=\s*['"][^'"]{3,}['"]`,
			`(?i)account\s*=\s*['"][^'"]{3,}['"]`,
			`(?i)access_key\s*=\s*['"][^'"]{3,}['"]`,
			`(?i)secret_key\s*=\s*['"][^'"]{3,}['"]`,
			`(?i)client_secret\s*=\s*['"][^'"]{3,}['"]`,
			`(?i)client_id\s*=\s*['"][^'"]{3,}['"]`,
			`(?i)api[_-]?key\s*=\s*['"][^'"]{3,}['"]`,
			`(?i)api[_-]?secret\s*=\s*['"][^'"]{3,}['"]`,
			`(?i)access[_-]?token\s*=\s*['"][^'"]{3,}['"]`,
			`(?i)refresh[_-]?token\s*=\s*['"][^'"]{3,}['"]`,
		},
    },
    {
        Name: "Private Keys and Certificates",
        Patterns: []string{
			`-----BEGIN DSA PRIVATE KEY-----`,
			`-----BEGIN EC PRIVATE KEY-----`,
			`-----BEGIN PGP PRIVATE KEY BLOCK-----`,
			`-----BEGIN RSA PRIVATE KEY-----`,
		},
    },
    {
        Name: "API Keys and Tokens",
        Patterns: []string{
			`[aA][pP][iI]_?[kK][eE][yY].{0,20}['|\"][0-9a-zA-Z]{32,45}['|\"]`,
			`api_key=[0-9a-zA-Z]+`,
			`key-[0-9a-zA-Z]{32}`,
			`AIza[0-9A-Za-z\\-_]{35}`,
		},
    },
    {
        Name: "OAuth and Authentication Tokens",
        Patterns: []string{
			`access_token=[0-9a-zA-Z]+`,
			`access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}`,
			`ya29\\.[0-9A-Za-z\\-_]+`,
			`eyJhbGciOiJ`,
			`EAACEdEose0cBA[0-9A-Za-z]+`,
		},
    },
    {
        Name: "Cloud Platform Credentials",
        Patterns: []string{
			`((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})`, // AWS
			`amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`, // Amazon MWS
			`[hH][eE][rR][oO][kK][uU].{0,20}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`, // Heroku
		},
    },
    {
        Name: "Service Account Credentials",
        Patterns: []string{
			`"service_account\"`,
			`[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com`,
			`[0-9]+:AA[0-9A-Za-z\\-_]{33}`,
		},
    },
    {
        Name: "Payment-related Keys",
        Patterns: []string{
			`rk_live_[0-9a-zA-Z]{24}`,
			`sk_live_[0-9a-z]{32}`,
			`sk_live_[0-9a-zA-Z]{24}`,
			`sq0atp-[0-9A-Za-z\\-_]{22}`,
			`sq0csp-[0-9A-Za-z\\-_]{43}`,
		},
    },
    {
        Name: "Platform Service Keys",
        Patterns: []string{
			`[fF][aA][cC][eE][bB][oO][oO][kK].{0,20}['|\"][0-9a-f]{32}['|\"]`, // Facebook
			`[gG][iI][tT][hH][uU][bB].{0,20}['|\"][0-9a-zA-Z]{35,40}['|\"]`, // GitHub
			`https://hooks\\.slack\\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}`, // Slack
			`https:\/\/[a-zA-Z0-9]{40}@github\.com`, // GitHub
		},
    },
    {
        Name: "Other Sensitive Information",
        Patterns: []string{
			`[sS][eE][cC][rR][eE][tT].{0,20}['|\"][0-9a-zA-Z]{32,45}['|\"]`,
			`[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]`,
			`[0-9a-f]{32}-us[0-9]{1,2}`,
			`da2-[a-z0-9]{26}`,
			`SK[0-9a-fA-F]{32}`,
		},
	},
}

// Get all hardcode patterns
func getAllHardCodedPatterns() []string {
	var patterns []string
	for _, category := range hardCodeCategories {
		patterns = append(patterns, category.Patterns...)
	}
	return patterns
}

// Compile hardcode patterns into regular expressions
func parseHardCodedPatterns(patterns []string) []*regexp.Regexp {
	var regexps []*regexp.Regexp
	for _, pattern := range patterns {
		regexps = append(regexps, regexp.MustCompile(pattern))
	}
	return regexps
}

// Hardcode detection result structure
type HardCodedResult struct {
    FilePath    string
    Category    string
    Pattern     string
    MatchText   string
}

// Global variable to collect all hardcode detection results
var allHardCodedResults []HardCodedResult

// Clear all hardcode detection results
func clearHardCodedResults() {
    allHardCodedResults = []HardCodedResult{}
}

// Search for hardcoded patterns
func SearchHardCoded(dexData []byte, filePath string, patterns []*regexp.Regexp) {
    patternList := getAllHardCodedPatterns()
    
    for i, pattern := range patterns {
        matches := pattern.FindAll(dexData, -1)
        if len(matches) > 0 {
            // Find which category this pattern belongs to
            category := "Uncategorized"
            for _, cat := range hardCodeCategories {
                for _, catPattern := range cat.Patterns {
                    if catPattern == patternList[i] {
                        category = cat.Name
                        break
                    }
                }
                if category != "Uncategorized" {
                    break
                }
            }
			
			for _, match := range matches {
				result := HardCodedResult{
					FilePath:  filePath,
					Category:  category,
					Pattern:   patternList[i],
					MatchText: string(match),
				}
				allHardCodedResults = append(allHardCodedResults, result)
			}
		}
	}
}

// Open APK and scan directly
func ScanAPKHardCoded(apkReader *zip.Reader) bool {
    // Clear previous detection results
    clearHardCodedResults()
    
    patterns := parseHardCodedPatterns(getAllHardCodedPatterns())

    // Read and scan all files
    totalFiles := len(apkReader.File)
    for i, file := range apkReader.File {
        // Show progress
        fmt.Printf("\rHardcode scan progress: %d/%d", i+1, totalFiles)

		fileReader, err := file.Open()
		if err != nil {
			fmt.Println(err)
			continue
		}
		
        // Use parameter to control file size limit
        dexData, err := io.ReadAll(io.LimitReader(fileReader, 1024*1024*(*ArgMaxSize)))
		fileReader.Close()
		if err != nil {
			fmt.Println(err)
			continue
		}
		
		SearchHardCoded(dexData, file.Name, patterns)
	}
	
    // Output detection results
    if len(allHardCodedResults) > 0 {
        outputHardCodedResultsAsText()
    } else {
        fmt.Printf("\n\nNo hardcode patterns found\n")
    }

	return true
}

// Output hardcode results in text format
func outputHardCodedResultsAsText() {
    fmt.Printf("\n\n===================== Hardcode Detection Results =====================\n")
    
    // Group results by category
    categoryMap := make(map[string][]HardCodedResult)
    var categories []string
	
	for _, result := range allHardCodedResults {
		if _, exists := categoryMap[result.Category]; !exists {
			categories = append(categories, result.Category)
		}
		categoryMap[result.Category] = append(categoryMap[result.Category], result)
	}
	
    // Sort by category name
    sort.Strings(categories)
    
    // Output grouped results
    for _, category := range categories {
        fmt.Printf("\n[%s]\n", category)
        results := categoryMap[category]
        
        // Group by filename
        fileMap := make(map[string][]HardCodedResult)
        var files []string
		
		for _, result := range results {
			if _, exists := fileMap[result.FilePath]; !exists {
				files = append(files, result.FilePath)
			}
			fileMap[result.FilePath] = append(fileMap[result.FilePath], result)
		}
		
        // Sort by filename
        sort.Strings(files)
        
        // Output each file's results
        for _, file := range files {
            fmt.Printf("\n  File: %s\n", file)
            for _, result := range fileMap[file] {
                fmt.Printf("    Rule: %-30s\n", result.Pattern)
                fmt.Printf("    Match: %s\n", result.MatchText)
                fmt.Printf("    %s\n", strings.Repeat("-", 60))
            }
        }
    }
    
    fmt.Printf("\n================================================================\n")
}
