package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Version and banner information
const (
	VERSION = "2.1.0"
	AUTHOR  = "the5orcerer"
	BANNER  = `
 _______ __           __  _______                          __   
|    ___|__|.-----.--|  ||   _   .-----.----.----.-----.--|  |  
|    ___|  ||     |  _  ||   1___|  -__|  __|   _|  -__|  _  |  
|___|   |__||__|__|_____||____   |_____|____|__| |_____|_____|  
                          |:  1   |                             
                          |::.. . |   Secret Scanner v%s
                          '-------'   By: %s

    Current Date (UTC): %s
`
)

// Colors for terminal output
const (
	RESET   = "\033[0m"
	RED     = "\033[31m"
	GREEN   = "\033[32m"
	YELLOW  = "\033[33m"
	BLUE    = "\033[34m"
	MAGENTA = "\033[35m"
	CYAN    = "\033[36m"
	BOLD    = "\033[1m"
)

// Severity levels
const (
	CRITICAL = "CRITICAL"
	HIGH     = "HIGH"
	MEDIUM   = "MEDIUM"
	LOW      = "LOW"
	INFO     = "INFO"
)

// Data structures
type Secrets struct {
	Name     string   `json:"name"`
	Patterns []string `json:"patterns"`
	Severity string   `json:"severity,omitempty"`
}

type Finding struct {
	Source   string `json:"source"`
	Secret   string `json:"secret"`
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Line     int    `json:"line,omitempty"`
}

type ScanStats struct {
	FilesScanned   int            `json:"files_scanned"`
	SecretsFound   int            `json:"secrets_found"`
	TimeElapsed    float64        `json:"time_elapsed"`
	ScanDate       time.Time      `json:"scan_date"`
	SeverityCounts map[string]int `json:"severity_counts"`
}

// Global variables
var (
	secrets        []Secrets
	matchedSecrets []Finding
	stats          ScanStats
	useColors      bool
	startTime      time.Time
	customRegexMap map[string][]string
)

// Command-line flags
var (
	input           string
	output          string
	threads         int
	timeout         int
	updateSecrets   bool
	customPatterns  string
	excludePatterns string
	regexFile       string
	silent          bool
	verbose         bool
	noColor         bool
	saveStats       bool
	maxDepth        int
	showVersion     bool
	logFile         string
	jsonOutput      bool
	failOnHigh      bool
	configFile      string
	urlsFile        string
	recursive       bool
	skipVerify      bool
	userAgent       string
)

func init() {
	// Initialize statistics
	stats = ScanStats{
		ScanDate:       time.Now(),
		SeverityCounts: make(map[string]int),
	}
	
	// Parse command line flags
	flag.StringVar(&input, "i", "", "Input source:\n  -local JS file (e.g., -i local.js)\n  -URL to JS file (e.g., -i https://domain.tld/external.js)\n  -Domain to scan (e.g., -i https://domain.tld)\n  -List of domains in a file (e.g., -i domains.txt)")
	flag.StringVar(&output, "o", "cli", "Output destination:\n  -cli for terminal output\n  -filename.txt to save to file\n  -json for JSON output")
	flag.IntVar(&threads, "t", runtime.NumCPU(), "Number of concurrent threads")
	flag.IntVar(&timeout, "timeout", 30, "HTTP request timeout in seconds")
	flag.BoolVar(&updateSecrets, "update", false, "Update secrets database from repository")
	flag.StringVar(&customPatterns, "patterns", "", "Path to custom patterns JSON file")
	flag.StringVar(&excludePatterns, "exclude", "", "Regex patterns to exclude (comma-separated)")
	flag.StringVar(&regexFile, "regex-file", "", "File containing custom regex patterns for secrets")
	flag.BoolVar(&silent, "silent", false, "Only output findings without status messages")
	flag.BoolVar(&verbose, "v", false, "Verbose output with detailed information")
	flag.BoolVar(&noColor, "no-color", false, "Disable colored output")
	flag.BoolVar(&saveStats, "stats", false, "Save scan statistics to file")
	flag.IntVar(&maxDepth, "depth", 1, "Maximum depth for crawling linked JS files")
	flag.BoolVar(&showVersion, "version", false, "Show version information and exit")
	flag.StringVar(&logFile, "log", "", "Log output to specified file")
	flag.BoolVar(&jsonOutput, "json", false, "Output results in JSON format")
	flag.BoolVar(&failOnHigh, "fail-on-high", false, "Exit with error code if high severity findings are detected")
	flag.StringVar(&configFile, "config", "", "Path to configuration file")
	flag.StringVar(&urlsFile, "urls-file", "", "File containing list of JavaScript URLs to scan")
	flag.BoolVar(&recursive, "recursive", false, "Recursively scan for JavaScript files in linked resources")
	flag.BoolVar(&skipVerify, "skip-verify", false, "Skip TLS certificate verification")
	flag.StringVar(&userAgent, "user-agent", "FindSecret/"+VERSION, "Custom User-Agent string for HTTP requests")
}

func main() {
	startTime = time.Now()
	
	// Parse flags
	flag.Parse()
	
	// Configure color output
	useColors = !noColor && isTerminal()
	
	// Get current date and time in UTC
	currentDate := time.Now().UTC().Format("2006-01-02 15:04:05")
	
	// Display banner and version if not in silent mode
	if !silent {
		if useColors {
			fmt.Printf(CYAN+BANNER+RESET, VERSION, AUTHOR, currentDate)
		} else {
			fmt.Printf(BANNER, VERSION, AUTHOR, currentDate)
		}
	}
	
	// Show version and exit if requested
	if showVersion {
		if !silent {
			fmt.Printf("FindSecret v%s\nRuntime: %s %s/%s\nCurrent Date (UTC): %s\n", 
				VERSION, 
				runtime.Version(), 
				runtime.GOOS, 
				runtime.GOARCH,
				currentDate)
		}
		os.Exit(0)
	}
	
	// Show help if no input is provided
	if len(os.Args) == 1 {
		printUsageGuide()
		os.Exit(0)
	}
	
	// Setup logging if requested
	if logFile != "" {
		setupLogging(logFile)
	}
	
	// Load configuration file if specified
	if configFile != "" {
		loadConfig(configFile)
	}
	
	// Update secrets database if requested
	if updateSecrets {
		logInfo("Updating secrets database...")
		downloadSecret()
		logSuccess("Secrets database updated successfully")
		os.Exit(0)
	}
	
	// Check if any input method is provided
	if input == "" && urlsFile == "" && len(flag.Args()) == 0 {
		logError("No input specified. Use -i flag, -urls-file flag, or provide input as argument")
		printUsageExample()
		os.Exit(1)
	}
	
	// If no input flag but argument is provided, use it as input
	if input == "" && len(flag.Args()) > 0 {
		input = flag.Args()[0]
	}
	
	// Load secrets database
	checkSecret()
	
	// Load custom patterns if specified
	if customPatterns != "" {
		loadCustomPatterns(customPatterns)
	}
	
	// Load regex patterns from file if specified
	if regexFile != "" {
		loadRegexFromFile(regexFile)
	}
	
	// Process input based on its type
	logInfo("Starting scan...")
	
	// If URLs file is provided, prioritize it
	if urlsFile != "" {
		scanJsUrlsFromFile(urlsFile)
	} else if input != "" {
		// Process regular input
		processInput(input)
	}
	
	// Print scan summary
	printScanSummary()
	
	// Save statistics if requested
	if saveStats {
		saveStatistics()
	}
	
	// Exit with error code if high severity findings detected and fail-on-high flag is set
	if failOnHigh && (stats.SeverityCounts[CRITICAL] > 0 || stats.SeverityCounts[HIGH] > 0) {
		os.Exit(2)
	}
	
	logSuccess("Scan completed")
}

// processInput processes different input types
func processInput(input string) {
	switch checkInput(input) {
	case "url":
		scanSingleUrl(input)
		
	case "local":
		scanLocalFile(input)
		
	case "domain":
		scanDomain(input)
		
	case "list":
		scanDomainList(input)
		
	default:
		logError("Invalid input format")
		printUsageExample()
		os.Exit(1)
	}
}

// scanSingleUrl scans a single JavaScript URL
func scanSingleUrl(url string) {
	logInfo(fmt.Sprintf("Scanning URL: %s", url))
	
	JsFile := getExternalJsFile(url)
	if JsFile != "Not Found" {
		findings := scanFile(url, JsFile)
		stats.FilesScanned++
		outputResults(url, findings)
	} else {
		logError(fmt.Sprintf("Failed to retrieve JavaScript from URL: %s", url))
	}
}

// scanLocalFile scans a local JavaScript file
func scanLocalFile(filePath string) {
	logInfo(fmt.Sprintf("Scanning local file: %s", filePath))
	
	JsFile := getLocalJsFile(filePath)
	findings := scanFile(filePath, JsFile)
	stats.FilesScanned++
	outputResults(filePath, findings)
}

// scanDomain scans a domain for JavaScript files
func scanDomain(domain string) {
	logInfo(fmt.Sprintf("Scanning domain: %s", domain))
	
	JsFileList := getScripts(domain)
	logInfo(fmt.Sprintf("Found %d JavaScript files", len(JsFileList)))
	
	if len(JsFileList) == 0 {
		logWarning("No JavaScript files found. If the site uses SPA or dynamic loading, try increasing depth with -depth flag")
		return
	}
	
	scanJsUrls(JsFileList)
}

// scanDomainList scans a list of domains from a file
func scanDomainList(filePath string) {
	domains := getDomainList(filePath)
	logInfo(fmt.Sprintf("Scanning %d domains from list", len(domains)))
	
	for _, domain := range domains {
		if domain == "" {
			continue
		}
		
		logInfo(fmt.Sprintf("Processing domain: %s", domain))
		JsFileList := getScripts(domain)
		logInfo(fmt.Sprintf("Found %d JavaScript files on %s", len(JsFileList), domain))
		
		if len(JsFileList) > 0 {
			scanJsUrls(JsFileList)
		}
	}
}

// scanJsUrlsFromFile scans JavaScript URLs from a file
func scanJsUrlsFromFile(filePath string) {
	urls := readLinesFromFile(filePath)
	logInfo(fmt.Sprintf("Scanning %d JavaScript URLs from file", len(urls)))
	
	scanJsUrls(urls)
}

// scanJsUrls scans a list of JavaScript URLs concurrently
func scanJsUrls(urls []string) {
	var wg sync.WaitGroup
	resultChan := make(chan []Finding, len(urls))
	semaphore := make(chan struct{}, threads)
	
	for _, url := range urls {
		if url == "" {
			continue
		}
		
		wg.Add(1)
		semaphore <- struct{}{}
		
		go func(url string) {
			defer wg.Done()
			defer func() { <-semaphore }()
			
			if verbose {
				logInfo(fmt.Sprintf("Fetching: %s", url))
			}
			
			JsFile := getExternalJsFile(url)
			if JsFile != "Not Found" {
				findings := scanFile(url, JsFile)
				resultChan <- findings
				
				// Scan for additional JS references if recursive flag is set
				if recursive && maxDepth > 1 {
					additionalUrls := extractJsReferences(JsFile)
					for _, addUrl := range additionalUrls {
						// Make relative URLs absolute
						if !strings.HasPrefix(addUrl, "http") {
							baseUrl := getBaseUrl(url)
							addUrl = baseUrl + addUrl
						}
						
						if verbose {
							logInfo(fmt.Sprintf("Found additional JS: %s", addUrl))
						}
						
						additionalJs := getExternalJsFile(addUrl)
						if additionalJs != "Not Found" {
							addFindings := scanFile(addUrl, additionalJs)
							resultChan <- addFindings
						}
					}
				}
			}
		}(url)
	}
	
	go func() {
		wg.Wait()
		close(resultChan)
	}()
	
	for findings := range resultChan {
		if len(findings) > 0 {
			stats.FilesScanned++
			outputResults(findings[0].Source, findings)
		}
	}
}

// scanFile scans a file content for secrets using loaded patterns
func scanFile(source, content string) []Finding {
	var findings []Finding
	
	// Skip if content is empty
	if content == "" {
		return findings
	}
	
	// Check if file should be excluded
	if shouldExclude(source) {
		logInfo(fmt.Sprintf("Skipping excluded file: %s", source))
		return findings
	}
	
	// Split content into lines for line number tracking
	lines := strings.Split(content, "\n")
	
	// Scan with default patterns
	for _, secret := range secrets {
		for _, pattern := range secret.Patterns {
			re, err := regexp.Compile(pattern)
			if err != nil {
				logWarning(fmt.Sprintf("Invalid regex pattern: %s", pattern))
				continue
			}
			
			// Check each line
			for lineNum, line := range lines {
				matches := re.FindAllString(line, -1)
				
				// Save multiple matches
				for _, matchVal := range matches {
					if matchVal != "" {
						finding := Finding{
							Source:   source,
							Secret:   matchVal,
							Type:     secret.Name,
							Severity: secret.Severity,
							Line:     lineNum + 1,
						}
						findings = append(findings, finding)
						stats.SecretsFound++
						stats.SeverityCounts[secret.Severity]++
					}
				}
			}
		}
	}
	
	// Scan with custom regex patterns if provided
	if customRegexMap != nil {
		for name, patterns := range customRegexMap {
			for _, pattern := range patterns {
				re, err := regexp.Compile(pattern)
				if err != nil {
					logWarning(fmt.Sprintf("Invalid custom regex pattern: %s", pattern))
					continue
				}
				
				// Check each line
				for lineNum, line := range lines {
					matches := re.FindAllString(line, -1)
					
					// Save multiple matches
					for _, matchVal := range matches {
						if matchVal != "" {
							finding := Finding{
								Source:   source,
								Secret:   matchVal,
								Type:     name,
								Severity: "CUSTOM",
								Line:     lineNum + 1,
							}
							findings = append(findings, finding)
							stats.SecretsFound++
							stats.SeverityCounts["CUSTOM"]++
						}
					}
				}
			}
		}
	}
	
	return findings
}

// checkSecret ensures the secrets database is available
func checkSecret() {
	homeDir, err := os.UserHomeDir()
	check(err)
	
	secretsDir := filepath.Join(homeDir, "findsecret")
	secretsPath := filepath.Join(secretsDir, "secrets.json")
	
	if _, err := os.Stat(secretsPath); err != nil {
		logInfo("Secrets database not found. Downloading...")
		downloadSecret()
		logSuccess("Secrets database downloaded successfully")
	}
	
	secrets = readSecrets()
	logInfo(fmt.Sprintf("Loaded %d secret patterns", len(secrets)))
}

// downloadSecret downloads the secrets database from the repository
func downloadSecret() {
	homeDir, err := os.UserHomeDir()
	check(err)
	
	secretsDir := filepath.Join(homeDir, "findsecret")
	secretsPath := filepath.Join(secretsDir, "secrets.json")
	
	// Create directory if it doesn't exist
	if _, err := os.Stat(secretsDir); os.IsNotExist(err) {
		err = os.Mkdir(secretsDir, 0755)
		check(err)
	}
	
	// Create or truncate the secrets file
	jsonFile, err := os.Create(secretsPath)
	check(err)
	defer jsonFile.Close()
	
	// Set timeout for HTTP client
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}
	
	// Download secrets file
	resp, err := client.Get("https://raw.githubusercontent.com/burak0x01/findsecret/main/secrets.json")
	check(err)
	defer resp.Body.Close()
	
	// Check response status
	if resp.StatusCode != http.StatusOK {
		logError(fmt.Sprintf("Failed to download secrets. Status: %s", resp.Status))
		os.Exit(1)
	}
	
	// Copy response body to file
	_, err = io.Copy(jsonFile, resp.Body)
	check(err)
}

// readSecrets loads the secrets database
func readSecrets() []Secrets {
	var secrets []Secrets
	
	homeDir, err := os.UserHomeDir()
	check(err)
	
	secretsPath := filepath.Join(homeDir, "findsecret", "secrets.json")
	
	jsonFile, err := os.Open(secretsPath)
	check(err)
	defer jsonFile.Close()
	
	byteValue, _ := io.ReadAll(jsonFile)
	err = json.Unmarshal(byteValue, &secrets)
	check(err)
	
	// Set default severity if not specified
	for i := range secrets {
		if secrets[i].Severity == "" {
			secrets[i].Severity = MEDIUM
		}
	}
	
	return secrets
}

// loadCustomPatterns loads custom patterns from a JSON file
func loadCustomPatterns(path string) {
	var customSecrets []Secrets
	
	jsonFile, err := os.Open(path)
	if err != nil {
		logError(fmt.Sprintf("Failed to open custom patterns file: %v", err))
		return
	}
	defer jsonFile.Close()
	
	byteValue, _ := io.ReadAll(jsonFile)
	err = json.Unmarshal(byteValue, &customSecrets)
	if err != nil {
		logError(fmt.Sprintf("Failed to parse custom patterns: %v", err))
		return
	}
	
	// Set default severity if not specified
	for i := range customSecrets {
		if customSecrets[i].Severity == "" {
			customSecrets[i].Severity = MEDIUM
		}
	}
	
	// Append custom patterns to secrets
	secrets = append(secrets, customSecrets...)
	logInfo(fmt.Sprintf("Loaded %d custom patterns", len(customSecrets)))
}
