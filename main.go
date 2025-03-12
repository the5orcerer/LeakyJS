package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strings"
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
    Current User: %s
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

func main() {
    // Parse command line flags
    flag.Parse()

    // Set color output based on terminal and user preference
    useColors = isTerminal() && !noColor

    // Show version if requested
    if showVersion {
        fmt.Printf("FindSecret v%s\n", VERSION)
        os.Exit(0)
    }

    // Print banner with current time and user
    if !silent {
        currentTime := time.Now().UTC().Format("2006-01-02 15:04:05")
        fmt.Printf(BANNER, VERSION, AUTHOR, currentTime, "the5orcerer")
    }

    // Setup logging if specified
    if logFile != "" {
        err := setupLogging(logFile)
        if err != nil {
            logError(fmt.Sprintf("Failed to setup logging: %v", err))
            os.Exit(1)
        }
    }

    // Load configuration if specified
    if configFile != "" {
        err := loadConfig(configFile)
        if err != nil {
            logError(fmt.Sprintf("Failed to load configuration: %v", err))
            os.Exit(1)
        }
    }

    // Check input parameters
    if input == "" && !updateSecrets && urlsFile == "" {
        printUsageGuide()
        printUsageExample()
        os.Exit(1)
    }

    // Record start time
    startTime = time.Now()

    // Process input
    processInput()

    // Print summary
    if !silent {
        printScanSummary()
    }

    // Save statistics if requested
    if saveStats {
        saveStatistics()
    }
}

func processInput() {
    inputType := checkInput(input)
    switch inputType {
    case "url":
        content := getExternalJsFile(input)
        if content != "Not Found" {
            findings := scanContent(content, input)
            outputResults(input, findings)
        }
    case "local":
        content := getLocalJsFile(input)
        if content != "" {
            findings := scanContent(content, input)
            outputResults(input, findings)
        }
    case "domain":
        scripts := getScripts(input)
        for _, script := range scripts {
            content := getExternalJsFile(script)
            if content != "Not Found" {
                findings := scanContent(content, script)
                outputResults(script, findings)
            }
        }
    default:
        logError("Invalid input type")
        printUsageGuide()
        os.Exit(1)
    }
}

// Utility Functions
func isTerminal() bool {
	fileInfo, _ := os.Stdout.Stat()
	return (fileInfo.Mode() & os.ModeCharDevice) != 0
}

func printUsageGuide() {
	fmt.Printf(`Usage: findsecret [options] [input]
Options:
  -i string
    	Input source (file, URL, or domain)
  -o string
    	Output destination (default "cli")
  -t int
    	Number of concurrent threads (default: CPU cores)
  -timeout int
    	HTTP request timeout in seconds (default 30)
  -update
    	Update secrets database
  -patterns string
    	Path to custom patterns JSON file
  -exclude string
    	Regex patterns to exclude
  -regex-file string
    	File containing custom regex patterns
  -silent
    	Only output findings
  -v	Verbose output
  -no-color
    	Disable colored output
  -stats
    	Save scan statistics
  -depth int
    	Maximum crawling depth (default 1)
  -version
    	Show version information
  -log string
    	Log file path
  -json
    	Output in JSON format
  -fail-on-high
    	Exit with error on high severity findings
  -config string
    	Configuration file path
  -urls-file string
    	File containing URLs to scan
  -recursive
    	Scan recursively
  -skip-verify
    	Skip TLS verification
  -user-agent string
    	Custom User-Agent string
`)
}

func printUsageExample() {
	fmt.Printf(`
Example usage:
  findsecret -i example.js
  findsecret -i https://example.com/script.js
  findsecret -i https://example.com
  findsecret -urls-file urls.txt
  findsecret -update
`)
}

func setupLogging(logFile string) error {
	file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("error opening log file: %v", err)
	}
	os.Stdout = file
	os.Stderr = file
	return nil
}

func loadConfig(configFile string) error {
	file, err := os.Open(configFile)
	if err != nil {
		return fmt.Errorf("error opening config file: %v", err)
	}
	defer file.Close()

	type Config struct {
		ExcludePatterns []string          `json:"exclude_patterns"`
		CustomPatterns  map[string]string `json:"custom_patterns"`
		UserAgent       string           `json:"user_agent"`
		Timeout         int              `json:"timeout"`
		MaxDepth        int              `json:"max_depth"`
	}

	var config Config
	if err := json.NewDecoder(file).Decode(&config); err != nil {
		return fmt.Errorf("error parsing config file: %v", err)
	}

	if config.UserAgent != "" {
		userAgent = config.UserAgent
	}
	if config.Timeout > 0 {
		timeout = config.Timeout
	}
	if config.MaxDepth > 0 {
		maxDepth = config.MaxDepth
	}
	if len(config.ExcludePatterns) > 0 {
		excludePatterns = strings.Join(config.ExcludePatterns, ",")
	}

	return nil
}

func printScanSummary() {
	if silent {
		return
	}

	duration := time.Since(startTime).Seconds()
	stats.TimeElapsed = duration

	fmt.Printf("\nScan Summary:\n")
	fmt.Printf("============\n")
	fmt.Printf("Files Scanned: %d\n", stats.FilesScanned)
	fmt.Printf("Secrets Found: %d\n", stats.SecretsFound)
	fmt.Printf("Time Elapsed: %.2f seconds\n", duration)

	fmt.Printf("\nFindings by Severity:\n")
	fmt.Printf("===================\n")
	for severity, count := range stats.SeverityCounts {
		var color string
		switch severity {
		case CRITICAL:
			color = RED
		case HIGH:
			color = MAGENTA
		case MEDIUM:
			color = YELLOW
		case LOW:
			color = BLUE
		default:
			color = RESET
		}

		if useColors {
			fmt.Printf("%s%s: %d%s\n", color, severity, count, RESET)
		} else {
			fmt.Printf("%s: %d\n", severity, count)
		}
	}
}

func saveStatistics() {
	statsFile := fmt.Sprintf("scan_stats_%s.json", time.Now().Format("20060102_150405"))
	data, err := json.MarshalIndent(stats, "", "  ")
	if err != nil {
		logError(fmt.Sprintf("Failed to marshal statistics: %v", err))
		return
	}

	err = os.WriteFile(statsFile, data, 0644)
	if err != nil {
		logError(fmt.Sprintf("Failed to save statistics: %v", err))
		return
	}

	logSuccess(fmt.Sprintf("Statistics saved to %s", statsFile))
}

func logInfo(message string) {
	if !silent {
		if useColors {
			fmt.Printf("%s[*]%s %s\n", BLUE, RESET, message)
		} else {
			fmt.Printf("[*] %s\n", message)
		}
	}
}

func logSuccess(message string) {
	if !silent {
		if useColors {
			fmt.Printf("%s[+]%s %s\n", GREEN, RESET, message)
		} else {
			fmt.Printf("[+] %s\n", message)
		}
	}
}

func logError(message string) {
	if useColors {
		fmt.Printf("%s[-]%s %s\n", RED, RESET, message)
	} else {
		fmt.Printf("[-] %s\n", message)
	}
}

func logWarning(message string) {
	if !silent {
		if useColors {
			fmt.Printf("%s[!]%s %s\n", YELLOW, RESET, message)
		} else {
			fmt.Printf("[!] %s\n", message)
		}
	}
}

func checkInput(input string) string {
	if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
		if strings.HasSuffix(input, ".js") {
			return "url"
		}
		return "domain"
	}

	if strings.HasSuffix(input, ".txt") {
		return "list"
	}

	if strings.HasSuffix(input, ".js") {
		return "local"
	}

	return "unknown"
}

func getExternalJsFile(jsUrl string) string {
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	req, err := http.NewRequest("GET", jsUrl, nil)
	if err != nil {
		logError(fmt.Sprintf("Failed to create request: %v", err))
		return "Not Found"
	}

	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		logError(fmt.Sprintf("Failed to download JavaScript: %v", err))
		return "Not Found"
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logError(fmt.Sprintf("Failed to download JavaScript. Status: %s", resp.Status))
		return "Not Found"
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logError(fmt.Sprintf("Failed to read response body: %v", err))
		return "Not Found"
	}

	return string(body)
}

func getLocalJsFile(filePath string) string {
	content, err := os.ReadFile(filePath)
	if err != nil {
		logError(fmt.Sprintf("Failed to read file: %v", err))
		return ""
	}
	return string(content)
}

func getScripts(domain string) []string {
	var scripts []string

	if !strings.HasPrefix(domain, "http") {
		domain = "https://" + domain
	}

	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	req, err := http.NewRequest("GET", domain, nil)
	if err != nil {
		logError(fmt.Sprintf("Failed to create request: %v", err))
		return scripts
	}

	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		logError(fmt.Sprintf("Failed to fetch domain: %v", err))
		return scripts
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logError(fmt.Sprintf("Failed to fetch domain. Status: %s", resp.Status))
		return scripts
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logError(fmt.Sprintf("Failed to read response body: %v", err))
		return scripts
	}

	content := string(body)
	scriptUrls := extractScriptUrls(content)

	baseUrl, _ := url.Parse(domain)
	for _, scriptUrl := range scriptUrls {
		if strings.HasSuffix(scriptUrl, ".js") {
			if !strings.HasPrefix(scriptUrl, "http") {
				scriptUrl = makeAbsoluteUrl(baseUrl, scriptUrl)
			}
			scripts = append(scripts, scriptUrl)
		}
	}

	return scripts
}

func getDomainList(filePath string) []string {
	var domains []string

	file, err := os.Open(filePath)
	if err != nil {
		logError(fmt.Sprintf("Failed to open domain list: %v", err))
		return domains
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain != "" && !strings.HasPrefix(domain, "#") {
			domains = append(domains, domain)
		}
	}

	if err := scanner.Err(); err != nil {
		logError(fmt.Sprintf("Error reading domain list: %v", err))
	}

	return domains
}

func loadRegexFromFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open regex file: %v", err)
	}
	defer file.Close()

	customRegexMap = make(map[string][]string)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			logWarning(fmt.Sprintf("Invalid regex line format: %s", line))
			continue
		}

		name := strings.TrimSpace(parts[0])
		pattern := strings.TrimSpace(parts[1])

		customRegexMap[name] = append(customRegexMap[name], pattern)
	}

	return scanner.Err()
}

// Continue from outputResults function...
func outputResults(source string, findings []Finding) {
    if len(findings) == 0 {
        return
    }

    if jsonOutput {
        outputJSON(findings)
        return
    }

    if output != "cli" {
        outputToFile(findings)
        return
    }

    for _, finding := range findings {
        if useColors {
            var color string
            switch finding.Severity {
            case CRITICAL:
                color = RED
            case HIGH:
                color = MAGENTA
            case MEDIUM:
                color = YELLOW
            case LOW:
                color = BLUE
            default:
                color = RESET
            }

            fmt.Printf("\n%s[%s]%s Secret found in %s on line %d:\n", 
                color, finding.Severity, RESET, finding.Source, finding.Line)
            fmt.Printf("Type: %s\n", finding.Type)
            fmt.Printf("Secret: %s\n", finding.Secret)
        } else {
            fmt.Printf("\n[%s] Secret found in %s on line %d:\n", 
                finding.Severity, finding.Source, finding.Line)
            fmt.Printf("Type: %s\n", finding.Type)
            fmt.Printf("Secret: %s\n", finding.Secret)
        }
    }
}

// Helper functions for URL handling
func extractScriptUrls(content string) []string {
    var urls []string
    re := regexp.MustCompile(`<script[^>]+src=["']([^"']+)["']`)
    matches := re.FindAllStringSubmatch(content, -1)
    
    for _, match := range matches {
        if len(match) > 1 {
            urls = append(urls, match[1])
        }
    }
    
    return urls
}

func makeAbsoluteUrl(baseUrl *url.URL, relativeUrl string) string {
    if strings.HasPrefix(relativeUrl, "//") {
        return baseUrl.Scheme + ":" + relativeUrl
    }
    
    relative, err := url.Parse(relativeUrl)
    if err != nil {
        return relativeUrl
    }
    
    return baseUrl.ResolveReference(relative).String()
}

func outputJSON(findings []Finding) {
    data, err := json.MarshalIndent(findings, "", "  ")
    if err != nil {
        logError(fmt.Sprintf("Failed to marshal findings: %v", err))
        return
    }
    
    if output == "cli" {
        fmt.Println(string(data))
    } else {
        err = os.WriteFile(output, data, 0644)
        if err != nil {
            logError(fmt.Sprintf("Failed to write output file: %v", err))
        }
    }
}

func outputToFile(findings []Finding) {
    file, err := os.OpenFile(output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        logError(fmt.Sprintf("Failed to open output file: %v", err))
        return
    }
    defer file.Close()
    
    for _, finding := range findings {
        _, err := fmt.Fprintf(file, "\n[%s] Secret found in %s on line %d:\n", 
            finding.Severity, finding.Source, finding.Line)
        if err != nil {
            logError(fmt.Sprintf("Failed to write to output file: %v", err))
            return
        }
        
        fmt.Fprintf(file, "Type: %s\n", finding.Type)
        fmt.Fprintf(file, "Secret: %s\n", finding.Secret)
    }
}

func shouldExclude(source string) bool {
    if excludePatterns == "" {
        return false
    }
    
    patterns := strings.Split(excludePatterns, ",")
    for _, pattern := range patterns {
        re, err := regexp.Compile(strings.TrimSpace(pattern))
        if err != nil {
            logWarning(fmt.Sprintf("Invalid exclude pattern: %s", pattern))
            continue
        }
        
        if re.MatchString(source) {
            return true
        }
    }
    
    return false
}

// Error checking helper
func check(err error) {
    if err != nil {
        logError(fmt.Sprintf("Fatal error: %v", err))
        os.Exit(1)
    }
}

// init function to set up initial configuration
func init() {
    // Initialize statistics
    stats = ScanStats{
        ScanDate:       time.Now(),
        SeverityCounts: make(map[string]int),
    }
    
    // Parse command line flags
    flag.StringVar(&input, "i", "", "Input source (file, URL, or domain)")
    flag.StringVar(&output, "o", "cli", "Output destination")
    flag.IntVar(&threads, "t", runtime.NumCPU(), "Number of concurrent threads")
    flag.IntVar(&timeout, "timeout", 30, "HTTP request timeout in seconds")
    flag.BoolVar(&updateSecrets, "update", false, "Update secrets database")
    flag.StringVar(&customPatterns, "patterns", "", "Path to custom patterns JSON file")
    flag.StringVar(&excludePatterns, "exclude", "", "Regex patterns to exclude")
    flag.StringVar(&regexFile, "regex-file", "", "File containing custom regex patterns")
    flag.BoolVar(&silent, "silent", false, "Only output findings")
    flag.BoolVar(&verbose, "v", false, "Verbose output")
    flag.BoolVar(&noColor, "no-color", false, "Disable colored output")
    flag.BoolVar(&saveStats, "stats", false, "Save scan statistics")
    flag.IntVar(&maxDepth, "depth", 1, "Maximum crawling depth")
    flag.BoolVar(&showVersion, "version", false, "Show version information")
    flag.StringVar(&logFile, "log", "", "Log file path")
    flag.BoolVar(&jsonOutput, "json", false, "Output in JSON format")
    flag.BoolVar(&failOnHigh, "fail-on-high", false, "Exit with error on high severity findings")
    flag.StringVar(&configFile, "config", "", "Path to configuration file")
    flag.StringVar(&urlsFile, "urls-file", "", "File containing URLs to scan")
    flag.BoolVar(&recursive, "recursive", false, "Scan recursively")
    flag.BoolVar(&skipVerify, "skip-verify", false, "Skip TLS verification")
    flag.StringVar(&userAgent, "user-agent", "FindSecret/"+VERSION, "Custom User-Agent string")
}
