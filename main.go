package main

import (
	"bufio"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fatih/color"
	"gopkg.in/yaml.v3"
)

const (
	version          = "1.0.0"
	defaultTimeout   = 10 * time.Second
	defaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
	defaultPath      = "patterns" // Relative to executable
)

var (
	blue   = color.New(color.FgBlue).SprintFunc()
	red    = color.New(color.FgRed).SprintFunc()
	green  = color.New(color.FgGreen).SprintFunc()
	yellow = color.New(color.FgYellow).SprintFuncFunc()
	reset  = color.New(color.Reset).SprintFunc()

	logger = log.New(os.Stderr, "", log.LstdFlags)
)

type patternInfo struct {
	Name     string `yaml:"name"`
	Regex    string `yaml:"regex"`
	Confidence string `yaml:"confidence"`
}

type pattern struct {
	Pattern patternInfo `yaml:"pattern"`
}

type args struct {
	Verbose        bool
	Debug          bool
	ExitOnError    bool
	HealthCheck    bool
	Output         string
	Format         string
	Progress       bool
	Summary        bool
	Silent         bool
	URL            string
	URLFile        string
	Mode           string
	RegexFile      string
	Regex          string
	SecretFinder   bool
	LinkFinder     bool
	EmailFinder    bool
	UUIDFinder     bool
	Threads        int
	Timeout        int
	UserAgent      string
	Headers        string
	Cookie         string
	Insecure       bool
	FollowRedirects bool
	Retries        int
	FullPath       bool
	Delimiter      string
}

type leakJS struct {
	args              args
	urls              []string
	patterns          []*regexp.Regexp
	patternNames      []string
	patternTypes      []string
	results           []map[string]string
	loadedPatternFiles map[string]bool
	client            *http.Client
}

func parseArgs() args {
	var a args
	flag.BoolVar(&a.Verbose, "verbose", false, "Enable verbose output")
	flag.BoolVar(&a.Debug, "debug", false, "Enable debug logging")
	flag.BoolVar(&a.ExitOnError, "exit-on-error", false, "Exit on error")
	flag.BoolVar(&a.HealthCheck, "health-check", false, "Perform health check")
	flag.StringVar(&a.Output, "output", "", "Output file to write results")
	flag.StringVar(&a.Format, "format", "txt", "Output format (csv, json, txt)")
	flag.BoolVar(&a.Progress, "progress", false, "Show progress bar")
	flag.BoolVar(&a.Summary, "summary", false, "Show detailed summary at the end")
	flag.BoolVar(&a.Silent, "silent", false, "Silent mode, no output except findings")
	flag.StringVar(&a.URL, "url", "", "Single URL to scan")
	flag.StringVar(&a.URLFile, "url-file", "", "File containing URLs to scan (one per line)")
	flag.StringVar(&a.Mode, "mode", "auto", "Scanning mode: auto, lazy, anonymous")
	flag.StringVar(&a.RegexFile, "regex-file", "", "Custom regex patterns file (YAML)")
	flag.StringVar(&a.Regex, "regex", "", "Regex pattern from command line")
	flag.BoolVar(&a.SecretFinder, "secretfinder", false, "Use SecretFinder patterns")
	flag.BoolVar(&a.LinkFinder, "linkfinder", false, "Use LinkFinder patterns")
	flag.BoolVar(&a.EmailFinder, "emailfinder", false, "Use EmailFinder patterns")
	flag.BoolVar(&a.UUIDFinder, "uuidfinder", false, "Use UUIDFinder patterns")
	flag.IntVar(&a.Threads, "threads", 5, "Number of threads")
	flag.IntVar(&a.Timeout, "timeout", int(defaultTimeout.Seconds()), fmt.Sprintf("Request timeout in seconds (default: %d)", int(defaultTimeout.Seconds())))
	flag.StringVar(&a.UserAgent, "user-agent", defaultUserAgent, "Custom User-Agent")
	flag.StringVar(&a.Headers, "headers", "", "Additional headers as JSON string")
	flag.StringVar(&a.Cookie, "cookie", "", "Additional cookie as string")
	flag.BoolVar(&a.Insecure, "insecure", false, "Disable SSL verification")
	flag.BoolVar(&a.FollowRedirects, "follow-redirects", false, "Follow redirects")
	flag.IntVar(&a.Retries, "retries", 0, "Number of retries per request")
	flag.BoolVar(&a.FullPath, "fullpath", false, "Show full path in linkfinder")
	flag.StringVar(&a.Delimiter, "delimiter", ",", "Delimiter for CSV output (default: ,)")

	flag.Parse()
	return a
}

func printBanner(a args, urls []string) {
	if a.Silent {
		return
	}

	fmt.Printf("%sLeakJS v%s%s\n", blue(""), version, reset(""))
	fmt.Printf("%s%s%s\n", blue(""), strings.Repeat("=", 50), reset(""))
	fmt.Printf("URLs to scan: %d\n", len(urls))
	fmt.Printf("Threads: %d\n", a.Threads)
	fmt.Printf("Timeout: %ds\n", a.Timeout)
	fmt.Printf("Mode: %s\n", a.Mode)
	fmt.Printf("Output format: %s\n", strings.ToUpper(a.Format))
	if a.Output {
		fmt.Printf("Output file: %s\n", a.Output)
	}
	fmt.Printf("%s%s%s\n\n", blue(""), strings.Repeat("=", 50), reset(""))
}

func newLeakJS(a args) *leakJS {
	lj := &leakJS{
		args:              a,
		urls:              []string{},
		patterns:          []*regexp.Regexp{},
		patternNames:      []string{},
		patternTypes:      []string{},
		results:           []map[string]string{},
		loadedPatternFiles: make(map[string]bool),
		client: &http.Client{
			Timeout: time.Duration(a.Timeout) * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: a.Insecure},
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if a.FollowRedirects {
					return nil
				}
				return http.ErrUseLastResponse
			},
		},
	}
	lj.setupPatterns()
	return lj
}

func (lj *leakJS) setupPatterns() {
	patternsToLoad := []struct {
		file string
		ptype string
	}{}

	if lj.args.RegexFile {
		patternsToLoad = append(patternsToLoad, struct {
			file  string
			ptype string
		}{file: lj.args.RegexFile, ptype: "custom"})
	}

	if lj.args.Regex {
		re, err := regexp.Compile(lj.args.Regex)
		if err != nil {
			logger.Fatalf("%s Invalid CLI regex: %v", red("[ERR]"), err)
		}
		lj.patterns = append(lj.patterns, re)
		lj.patternNames = append(lj.patternNames, "cli-regex")
		lj.patternTypes = append(lj.patternTypes, "custom")

	}

	if !lj.args.RegexFile && !lj.args.Regex && !lj.args.SecretFinder && !lj.args.LinkFinder && !lj.args.EmailFinder && !lj.args.UUIDFinder {
		patternsToLoad = append(patternsToLoad,
			struct {
				file  string
				ptype string
			}{file: filepath.Join(defaultPath, "linkfinder.yaml"), ptype: "linkfinder"},
			struct {
				file  string
				ptype string
			}{file: filepath.Join(defaultPath, "secrets.yaml"), ptype: "secrets"},
			struct {
				file  string
				ptype string
			}{file: filepath.Join(defaultPath, "emailfinder.yaml"), ptype: "email"},
			struct {
				file  string
				ptype string
			}{file: filepath.Join(defaultPath, "uuidfinder.yaml"), ptype: "uuid"},
		)
	} else {
		appendIfTrue := func(condition bool, file, ptype string) {
			if condition {
				patternsToLoad = append(patternsToLoad, struct {
					file  string
					ptype string
				}{file: file, ptype: ptype})
			}
		}
		appendIfTrue(lj.args.LinkFinder, filepath.Join(defaultPath, "linkfinder.yaml"), "linkfinder")
		appendIfTrue(lj.args.SecretFinder, filepath.Join(defaultPath, "secrets.yaml"), "secrets")
		appendIfTrue(lj.args.EmailFinder, filepath.Join(defaultPath, "emailfinder.yaml"), "email")
		appendIfTrue(lj.args.UUIDFinder, filepath.Join(defaultPath, "uuidfinder.yaml"), "uuid")
	}

	for _, pl := range patternsToLoad {
		if _, loaded := lj.loadedPatternFiles[pl.file]; !loaded {
			lj.loadPatternFile(pl.file, pl.ptype)
			lj.loadedPatternFiles[pl.file] = true
		}
	}
}

func (lj *leakJS) loadPatternFile(patternFile string, patternType string) {
	file, err := os.Open(patternFile)
	if err != nil {
		logger.Fatalf("%s Error opening pattern file %s: %v", red("[ERR]"), patternFile, err)
		return
	}
	defer file.Close()

	decoder := yaml.NewDecoder(file)
	var patterns []pattern

	err = decoder.Decode(&patterns)

	if err != nil {
		logger.Printf("%s Error decoding pattern file %s: %v", red("[ERR]"), patternFile, err)
		return
	}

	count := 0
	for _, p := range patterns {
		re, err := regexp.Compile(p.Pattern.Regex)
		if err != nil {
			logger.Printf("%s Invalid regex in %s: %s - %v", red("[ERR]"), patternFile, p.Pattern.Name, err)
			continue
		}
		lj.patterns = append(lj.patterns, re)
		lj.patternNames = append(lj.patternNames, p.Pattern.Name)
		lj.patternTypes = append(lj.patternTypes, patternType)
		count++
	}

	if lj.args.Verbose && !lj.args.HealthCheck {
		logger.Printf("Loaded %d patterns from %s", count, patternFile)
	}
}

func (lj *leakJS) loadURLs() {
	if lj.args.URL != "" {
		lj.urls = append(lj.urls, lj.args.URL)
	} else if lj.args.URLFile != "" {
		file, err := os.Open(lj.args.URLFile)
		if err != nil {
			logger.Fatalf("%s Error opening URL file %s: %v", red("[ERR]"), lj.args.URLFile, err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			line = strings.TrimSpace(line)
			if line != "" {
				lj.urls = append(lj.urls, line)
			}
		}

		if err := scanner.Err(); err != nil {
			logger.Fatalf("%s Error reading URL file %s: %v", red("[ERR]"), lj.args.URLFile, err)
		}
	} else {
		// Read from stdin
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := scanner.Text()
			line = strings.TrimSpace(line)
			if line != "" {
				lj.urls = append(lj.urls, line)
			}
		}

		if err := scanner.Err(); err != nil {
			logger.Fatalf("%s Error reading from stdin: %v", red("[ERR]"), err)
		}
	}

	// Add scheme if missing
	for i := range lj.urls {
		if !strings.HasPrefix(lj.urls[i], "http://") && !strings.HasPrefix(lj.urls[i], "https://") {
			lj.urls[i] = "https://" + lj.urls[i]
		}
	}

	if len(lj.urls) == 0 && !lj.args.HealthCheck {
		logger.Fatalf("%s No URLs provided.", red("[ERR]"))
	}
}

func (lj *leakJS) fetchURL(urlStr string) (string, string) {
	var body string
	for i := 0; i <= lj.args.Retries; i++ {
		req, err := http.NewRequest("GET", urlStr, nil)
		if err != nil {
			logger.Printf("Attempt %d/%d: Error creating request for %s: %v", i+1, lj.args.Retries+1, urlStr, err)
			if i == lj.args.Retries {
				return urlStr, ""
			}
			time.Sleep(time.Duration(i) * 2 * time.Second) // Exponential backoff
			continue
		}

		if lj.args.Headers != "" {
			var headers map[string]string
			if err := json.Unmarshal([]byte(lj.args.Headers), &headers); err != nil {
				logger.Printf("%s Failed to parse custom headers JSON: %v", red("[ERR]"), err)
			} else {
				for k, v := range headers {
					req.Header.Set(k, v)
				}
			}
		}
		req.Header.Set("User-Agent", lj.args.UserAgent)
		if lj.args.Cookie != "" {
			req.Header.Set("Cookie", lj.args.Cookie)
		}

		resp, err := lj.client.Do(req)

		if err != nil {
			logger.Printf("Attempt %d/%d: Error fetching %s: %v", i+1, lj.args.Retries+1, urlStr, err)
			if i == lj.args.Retries {
				return urlStr, ""
			}
			time.Sleep(time.Duration(i) * 2 * time.Second) // Exponential backoff
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			b, err := io.ReadAll(resp.Body)
			if err != nil {
				logger.Printf("Attempt %d/%d: Error reading body from %s: %v", i+1, lj.args.Retries+1, urlStr, err)
				if i == lj.args.Retries {
					return urlStr, ""
				}
				time.Sleep(time.Duration(i) * 2 * time.Second) // Exponential backoff
				continue
			}
			body = string(b)
			return urlStr, body

		} else {
			logger.Printf("Attempt %d/%d: Error status code from %s: %d", i+1, lj.args.Retries+1, urlStr, resp.StatusCode)
			if i == lj.args.Retries {
				return urlStr, ""
			}
			time.Sleep(time.Duration(i) * 2 * time.Second) // Exponential backoff
			continue
		}

	}
	return urlStr, body
}

func (lj *leakJS) scanContent(urlStr, content, scanType string) []map[string]string {
	var urlResults []map[string]string
	for i, re := range lj.patterns {
		if lj.patternTypes[i] != scanType {
			continue
		}

		matches := re.FindAllString(content, -1)
		for _, match := range matches {
			if match != "" {
				result := map[string]string{
					"confidence": "medium", // Default confidence
					"url":        urlStr,
					"finding":    match,
					"pattern_name": lj.patternNames[i],
				}

				if lj.args.FullPath && scanType == "linkfinder" {
					parsedURL, _ := url.Parse(urlStr)
					fullPath, _ := url.JoinPath(fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host), match)
					result["full_path"] = fullPath
				}
				urlResults = append(urlResults, result)
			}
		}
	}
	return urlResults
}

func (lj *leakJS) processURLs() {
	var wg sync.WaitGroup
	urlChan := make(chan string, lj.args.Threads*2) // Buffered channel

	// Initialize progress bar
	var progressBar *ProgressBar
	if !lj.args.Silent && lj.args.Progress {
		progressBar = NewProgressBar(len(lj.urls), fmt.Sprintf("%s[INF]%s Processing URLs", blue(""), reset("")))
		progressBar.Start()
	}

	// Launch worker goroutines
	for i := 0; i < lj.args.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for urlStr := range urlChan {
				urlStr, content := lj.fetchURL(urlStr)
				if content != "" {
					scanType := lj.determineScanType(urlStr)
					matches := lj.scanContent(urlStr, content, scanType)
					if len(matches) > 0 {
						lj.results = append(lj.results, matches...)
						lj.printResults(urlStr, matches)
					}
				}
				if progressBar != nil {
					progressBar.Increment(fmt.Sprintf("%s[INF]%s Processing: %s", blue(""), reset(""), urlStr))
				}
			}
		}()
	}

	// Feed URLs into the channel
	for _, urlStr := range lj.urls {
		urlChan <- urlStr
	}
	close(urlChan) // Signal workers that there are no more URLs

	wg.Wait() // Wait for all workers to complete

	// Stop progress bar
	if progressBar != nil {
		progressBar.Finish()
	}
}

func (lj *leakJS) determineScanType(urlStr string) string {
	switch lj.args.Mode {
	case "auto":
		if strings.HasSuffix(urlStr, ".js") {
			return "secrets"
		}
		return "linkfinder"
	default:
		if lj.args.LinkFinder {
			return "linkfinder"
		}
		if lj.args.SecretFinder {
			return "secrets"
		}
		if lj.args.EmailFinder {
			return "email"
		}
		if lj.args.UUIDFinder {
			return "uuid"
		}
		if strings.HasSuffix(urlStr, ".js") {
			return "secrets"
		}
		return "linkfinder"
	}
}

func (lj *leakJS) printResults(urlStr string, findings []map[string]string) {
	if lj.args.Silent || !lj.args.Verbose {
		return
	}

	fmt.Printf("%s %s\n", green("[FOUND]"), urlStr)
	for _, finding := range findings {
		confidence := strings.ToLower(finding["confidence"])
		colorFunc := reset
		switch confidence {
		case "high":
			colorFunc = red
		case "medium":
			colorFunc = yellow()
		case "low":
			colorFunc = green
		}

		output := fmt.Sprintf("  [%s%s%s] %s", colorFunc(""), finding["pattern_name"], reset(""), finding["finding"])

		if fullPath, ok := finding["full_path"]; ok {
			output += fmt.Sprintf("  Full Path: %s", fullPath)
		}
		fmt.Println(output)
	}
}

func (lj *leakJS) printSummary(startTime time.Time) {
	if lj.args.Silent {
		return
	}

	elapsedTime := time.Since(startTime)

	fmt.Printf("\n%s Summary:\n", blue("[INF]"))
	fmt.Printf("Total URLs processed: %d\n", len(lj.urls))
	fmt.Printf("Findings: %d\n", len(lj.results))
	fmt.Printf("Time taken: %.2fs\n", elapsedTime.Seconds())

	if len(lj.results) == 0 {
		return
	}

	patternCounts := make(map[string]int)
	confidenceCounts := map[string]int{"high": 0, "medium": 0, "low": 0}

	for _, result := range lj.results {
		patternName := result["pattern_name"]
		patternCounts[patternName]++

		confidence := strings.ToLower(result["confidence"])
		if _, ok := confidenceCounts[confidence]; ok {
			confidenceCounts[confidence]++
		}
	}

	fmt.Printf("\n%s Findings by pattern:\n", blue("[INF]"))
	for pattern, count := range patternCounts {
		fmt.Printf("  %s: %d\n", pattern, count)
	}

	fmt.Printf("\n%s Findings by confidence:\n", blue("[INF]"))
	colors := map[string]func(a ...interface{}) string{
		"high":   red,
		"medium": yellow(),
		"low":    green,
	}
	for confidence, count := range confidenceCounts {
		colorFunc, ok := colors[confidence]
		if !ok {
			colorFunc = reset
		}
		fmt.Printf("  %s%s%s: %d\n", colorFunc(""), strings.Title(confidence), reset(""), count)
	}
}

func (lj *leakJS) writeOutput() {
	if lj.args.Output == "" {
		return
	}

	if len(lj.results) == 0 {
		logger.Println(blue("[INF]") + " No results to write.")
		return
	}

	outputFile := lj.args.Output

	if lj.args.Output == "" {
		var baseFilename string
		if len(lj.urls) > 0 {
			parsedURL, _ := url.Parse(lj.urls[0])
			baseFilename = strings.ReplaceAll(parsedURL.Host, ".", "_")
		} else {
			baseFilename = "leaks"
		}
		outputFile = fmt.Sprintf("%s_leaks.%s", baseFilename, lj.args.Format)
	}

	file, err := os.Create(outputFile)
	if err != nil {
		logger.Fatalf("%s Error creating output file %s: %v", red("[ERR]"), outputFile, err)
	}
	defer file.Close()

	switch lj.args.Format {
	case "json":
		enc := json.NewEncoder(file)
		enc.SetIndent("", "    ")
		if err := enc.Encode(lj.results); err != nil {
			logger.Fatalf("%s Error encoding JSON to file: %v", red("[ERR]"), err)
		}
	case "csv":
		writer := csv.NewWriter(file)
		writer.Comma = rune(lj.args.Delimiter[0])

		if len(lj.results) > 0 {
			header := make([]string, 0, len(lj.results[0]))
			for k := range lj.results[0] {
				header = append(header, k)
			}
			if err := writer.Write(header); err != nil {
				logger.Fatalf("%s Error writing CSV header: %v", red("[ERR]"), err)
			}

			for _, result := range lj.results {
				row := make([]string, len(header))
				for i, h := range header {
					row[i] = result[h]
				}
				if err := writer.Write(row); err != nil {
					logger.Fatalf("%s Error writing CSV row: %v", red("[ERR]"), err)
				}
			}
		}
		writer.Flush()
		if err := writer.Error(); err != nil {
			logger.Fatalf("%s Error flushing CSV writer: %v", red("[ERR]"), err)
		}

	case "txt":
		for _, result := range lj.results {
			fmt.Fprintf(file, "URL: %s\n", result["url"])
			fmt.Fprintf(file, "Finding: %s\n", result["finding"])
			fmt.Fprintf(file, "Confidence: %s\n", result["confidence"])
			if patternName, ok := result["pattern_name"]; ok {
				fmt.Fprintf(file, "Pattern Name: %s\n", patternName)
			}
			if fullPath, ok := result["full_path"]; ok {
				fmt.Fprintf(file, "Full Path: %s\n", fullPath)
			}
			fmt.Fprintln(file, strings.Repeat("-", 30))
		}

	default:
		logger.Fatalf("%s Invalid output format: %s", red("[ERR]"), lj.args.Format)
	}

	logger.Printf("%s Results written to %s in %s format.", green("[SUCCESS]"), outputFile, strings.ToUpper(lj.args.Format))
}

func (lj *leakJS) healthCheck() {
	lj.args.Silent = true
	fmt.Printf("%s Running health check...\n", blue("[INF]"))

	testFlags := []struct {
		flag  string
		value []string
	}{
		{"--url", []string{"https://example.com"}},
		{"--regex-file", []string{"test_patterns.yaml"}},
		{"--secretfinder", []string{}},
		{"--linkfinder", []string{}},
		{"--emailfinder", []string{}},
		{"--uuidfinder", []string{}},
		{"--threads", []string{"2"}},
		{"--timeout", []string{"5"}},
		{"--user-agent", []string{"TestAgent"}},
		{"--headers", []string{`{"Test-Header": "Value"}`}},
		{"--cookie", []string{"test=value"}},
		{"--insecure", []string{}},
		{"--follow-redirects", []string{}},
		{"--summary", []string{}},
		{"--progress", []string{}},
		{"--exit-on-error", []string{}},
		{"--fullpath", []string{}},
		{"--verbose", []string{}},
		{"--output", []string{"test_output.txt"}},
		{"--format", []string{"json"}},
		{"--mode", []string{"auto"}},
	}

	// Create a dummy test_patterns.yaml
	err := os.WriteFile("test_patterns.yaml", []byte(`
patterns:
  - pattern:
      name: Test Pattern
      regex: "test_pattern"
      confidence: high
`), 0644)
	if err != nil {
		logger.Printf("%s Error creating test_patterns.yaml: %v", red("[ERR]"), err)
	}
	defer os.Remove("test_patterns.yaml")

	results := []struct {
		flag   string
		status string
	}{}

	for _, tf := range testFlags {
		// Simulate command-line arguments for testing
		argsCopy := os.Args[0:1] // Keep the program name
		argsCopy = append(argsCopy, tf.flag)
		argsCopy = append(argsCopy, tf.value...)

		flagSet := flag.NewFlagSet(os.Args[0], flag.ExitOnError) // Create a new flag set
		flagSet.Usage = func() {}                                 // Suppress default usage output

		// Define flags in the new flag set
		var a args
		flagSet.BoolVar(&a.Verbose, "verbose", false, "Enable verbose output")
		flagSet.BoolVar(&a.Debug, "debug", false, "Enable debug logging")
		flagSet.BoolVar(&a.ExitOnError, "exit-on-error", false, "Exit on error")
		flagSet.BoolVar(&a.HealthCheck, "health-check", false, "Perform health check")
		flagSet.StringVar(&a.Output, "output", "", "Output file to write results")
		flagSet.StringVar(&a.Format, "format", "txt", "Output format (csv, json, txt)")
		flagSet.BoolVar(&a.Progress, "progress", false, "Show progress bar")
		flagSet.BoolVar(&a.Summary, "summary", false, "Show detailed summary at the end")
		flagSet.BoolVar(&a.Silent, "silent", false, "Silent mode, no output except findings")
		flagSet.StringVar(&a.URL, "url", "", "Single URL to scan")
		flagSet.StringVar(&a.URLFile, "url-file", "", "File containing URLs to scan (one per line)")
		flagSet.StringVar(&a.Mode, "mode", "auto", "Scanning mode: auto, lazy, anonymous")
		flagSet.StringVar(&a.RegexFile, "regex-file", "", "Custom regex patterns file (YAML)")
		flagSet.StringVar(&a.Regex, "regex", "", "Regex pattern from command line")
		flagSet.BoolVar(&a.SecretFinder, "secretfinder", false, "Use SecretFinder patterns")
		flagSet.BoolVar(&a.LinkFinder, "linkfinder", false, "Use LinkFinder patterns")
		flagSet.BoolVar(&a.EmailFinder, "emailfinder", false, "Use EmailFinder patterns")
		flagSet.BoolVar(&a.UUIDFinder, "uuidfinder", false, "Use UUIDFinder patterns")
		flagSet.IntVar(&a.Threads, "threads", 5, "Number of threads")
		flagSet.IntVar(&a.Timeout, "timeout", int(defaultTimeout.Seconds()), fmt.Sprintf("Request timeout in seconds (default: %d)", int(defaultTimeout.Seconds())))
		flagSet.StringVar(&a.UserAgent, "user-agent", defaultUserAgent, "Custom User-Agent")
		flagSet.StringVar(&a.Headers, "headers", "", "Additional headers as JSON string")
		flagSet.StringVar(&a.Cookie, "cookie", "", "Additional cookie as string")
		flagSet.BoolVar(&a.Insecure, "insecure", false, "Disable SSL verification")
		flagSet.BoolVar(&a.FollowRedirects, "follow-redirects", false, "Follow redirects")
		flagSet.IntVar(&a.Retries, "retries", 0, "Number of retries per request")
		flagSet.BoolVar(&a.FullPath, "fullpath", false, "Show full path in linkfinder")
		flagSet.StringVar(&a.Delimiter, "delimiter", ",", "Delimiter for CSV output (default: ,)")

		err := flagSet.Parse(argsCopy[1:]) // Parse the flags
		if err != nil {
			results = append(results, struct {
				flag   string
				status string
			}{flag: tf.flag, status: "ERR"})
			logger.Printf("%s Error testing flag %s: %v", red("[ERR]"), tf.flag, err)
			continue
		}
		a = args{
			Verbose:        a.Verbose,
			Debug:          a.Debug,
			ExitOnError:    a.ExitOnError,
			HealthCheck:    a.HealthCheck,
			Output:         a.Output,
			Format:         a.Format,
			Progress:       a.Progress,
			Summary:        a.Summary,
			Silent:         a.Silent,
			URL:            a.URL,
			URLFile:        a.URLFile,
			Mode:           a.Mode,
			RegexFile:      a.RegexFile,
			Regex:          a.Regex,
			SecretFinder:   a.SecretFinder,
			LinkFinder:     a.LinkFinder,
			EmailFinder:    a.EmailFinder,
			UUIDFinder:     a.UUIDFinder,
			Threads:        a.Threads,
			Timeout:        a.Timeout,
			UserAgent:      a.UserAgent,
			Headers:        a.Headers,
			Cookie:         a.Cookie,
			Insecure:       a.Insecure,
			FollowRedirects: a.FollowRedirects,
			Retries:        a.Retries,
			FullPath:       a.FullPath,
			Delimiter:      a.Delimiter,
		}
		// Create a minimal test instance
		testInstance := newLeakJS(a)

		// Trigger pattern loading to check regex
		testInstance.setupPatterns()
		results = append(results, struct {
			flag   string
			status string
		}{flag: tf.flag, status: "OK"})
	}

	fmt.Printf("\n%s Health Check Results:\n", blue("[INF]"))
	allOK := true
	for _, res := range results {
		statusMarker := green("✓")
		if res.status == "ERR" {
			statusMarker = red("✗")
			allOK = false
		}
		fmt.Printf("  %s %s\n", statusMarker, res.flag)
	}

	if allOK {
		fmt.Printf("\n%s All checks passed!\n", green("[SUCCESS]"))
	} else {
		fmt.Printf("\n%s Some checks failed.\n", red("[WARNING]"))
	}
}

func (lj *leakJS) run() {
	defer func() {
		if r := recover(); r != nil {
			logger.Println(fmt.Sprintf("%s Recovered panic: %v", red("[CRITICAL ERROR]"), r))
		}
	}()

	if lj.args.Mode == "lazy" {
		lj.args.Timeout = 4
		lj.args.FollowRedirects = true
		lj.args.Retries = 2
	} else if lj.args.Mode == "anonymous" {
		// TODO: Implement Tor/proxy setup here
	}

	if len(lj.patterns) == 0 && !lj.args.HealthCheck {
		logger.Fatalf("%s No valid patterns loaded. Exiting.", red("[ERR]"))
	}

	lj.loadURLs()
	if len(lj.urls) > 0 || lj.args.HealthCheck {
		printBanner(lj.args, lj.urls)
	}
	logger.Printf("Loaded %d URLs, %d patterns", len(lj.urls), len(lj.patterns))

	startTime := time.Now()
	lj.processURLs()

	if lj.args.Summary {
		lj.printSummary(startTime)
	}

	lj.writeOutput()
}

func main() {
	a := parseArgs()
	if a.Debug {
		logger.SetFlags(log.LstdFlags | log.Lshortfile)
	}

	lj := newLeakJS(a)

	// Handle interrupt signal (Ctrl+C)
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-signalChan
		logger.Println(red("\n[ERR] Interrupted by user. Exiting..."))
		os.Exit(1)
	}()

	if a.HealthCheck {
		lj.healthCheck()
	} else {
		lj.run()
	}
}