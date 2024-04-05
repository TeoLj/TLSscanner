package main

import (
	"crypto/tls"
	"encoding/csv"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
)

type Scanner struct {
	Domains        []string
	ScannedCiphers []string
	opts           *Options
	Mutex          *sync.Mutex
	ErrorCounts    ErrorCounter
}

type ErrorCounter struct {
	HandshakeFailures int
	NoHostFound       int
	OtherErrors       map[string]int
}

// Creates a new instance of the Scanner struct with the provided domains and options.
// It initializes the ScannedCiphers slice, sets the options, and initializes the ErrorCounts map.
// The Scanner struct is used to perform TLS scanning on the specified domains.
func newScanner(domains []string, opts *Options) *Scanner {
	return &Scanner{
		Domains:        domains,
		ScannedCiphers: make([]string, 0),
		opts:           opts,
		Mutex:          &sync.Mutex{},
		ErrorCounts: ErrorCounter{
			OtherErrors: make(map[string]int),
		},
	}
}

// Starts the TLS scanner.
// It creates an output folder to save the results, creates a file to save the error log,
// and scans the specified domains for TLS support.
// The scan results are saved to a CSV file.
func (s *Scanner) startScanner() {

	/* Create an output folder to save the results */
	if s.opts.SaveDir != "" {
		// Create a folder called output to save the results if it doesn't exist
		os.Chdir(s.opts.SaveDir)
	} else {
		// Create a folder called output to save the results if it doesn't exist
		if _, err := os.Stat("output"); err == nil {
			os.RemoveAll("output")
		}
		os.Mkdir("output", 0755)
	}

	/* Create a file to save the error logs */
	var logFileName string

	if s.opts.SaveDir != "" {
		logFileName = s.opts.SaveDir + "/errorLog.txt"
	} else {
		logFileName = "./output/errorLog.txt"
	}

	file, err := os.OpenFile(logFileName, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Error opening or creating the log file: %v\n", err)
		return
	}
	defer file.Close()

	var wg sync.WaitGroup

	/* Create a buffered channel with a capacity of s.Concurrency
	limit the number of goroutines that can run at the same time
	channel defined as empty struct cos it takes no memory */
	if !s.opts.Naive { // default
		sem := make(chan struct{}, s.opts.Concurrency) // limiting the number of goroutines that can actively perform work at the same time

		for _, domain := range s.Domains {
			wg.Add(1)                // new goroutine
			sem <- struct{}{}        // will block if the channel is full, routine sends struct to take slot in the channel
			go func(domain string) { // closure function
				defer wg.Done() // decrease the counter when the goroutine completes
				s.scanDomain(domain, file)
				<-sem // release a slot in the channel
			}(domain)
		}

		wg.Wait() // wait for all goroutines to complete
	} else {

		/* Naive scanner scans sequentially */
		for _, domain := range s.Domains {
			s.scanDomain(domain, file)
		}
	}

	/* Save the cipher scan results to a CSV file*/
	fileName := strings.TrimSuffix(strings.TrimPrefix(s.opts.CSVFilePath, "./"), ".csv")

	if s.opts.CSVFilePath != "" { // Result file takes the name of the input file
		if s.opts.SaveDir != "" {
			s.saveResultsToCSV(s.opts.SaveDir + "/" + fileName + "_cipherScan.csv")
		} else {
			s.saveResultsToCSV("./output/" + fileName + "_cipherScan.csv")
		}
	}
	if s.opts.DomainsList != "" {
		if s.opts.SaveDir != "" {
			s.saveResultsToCSV(s.opts.SaveDir + "/cipherScan.csv")
		} else {
			s.saveResultsToCSV("./output/cipherScan.csv")
		}
	}
	s.sortErrorFile(logFileName)
}

// Analyzes the results of the scan.
func (s *Scanner) analyzeResults() {
	analyzer := newAnalyzer(*s)
	analyzer.run()
}

// Scans a given domain for supported TLS cipher suites.
// It establishes a connection to the domain and checks if each cipher suite is supported.
// If a cipher suite is supported, it adds it to the list of supported ciphers for the domain.
// If an error occurs during the scan, it logs the error and updates the error counts.
func (s *Scanner) scanDomain(domain string, file *os.File) {
	var supportedCiphers []string

	fmt.Printf("Scanning domain: %s \n", domain)

	for _, cipher := range tls.CipherSuites() {
		config := &tls.Config{
			CipherSuites: []uint16{cipher.ID},
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS13,
		}

		// establish a connection to the domain
		dialer := net.Dialer{Timeout: s.opts.Timeout}

		// 443 is the default port for HTTPS
		conn, err := tls.DialWithDialer(&dialer, "tcp", domain+":443", config)
		if err == nil {
			supportedCiphers = append(supportedCiphers, cipher.Name) // lock not put here due to performance overhead(release mutex for every cipher)
			conn.Close()
		} else {

			errMsg := err.Error()

			s.Mutex.Lock()
			// Error checking logic
			switch {
			case strings.Contains(err.Error(), "handshake failure"):
				s.ErrorCounts.HandshakeFailures++
				fmt.Printf("\033[3m%s\033[0m: \033[1;31m %s for %s \033[0m  \n", domain, err, cipher.Name)
				s.logError(domain, errMsg, cipher.Name, file)
				s.Mutex.Unlock() // unlock and
				continue         // skip to next cipher (next iteration)

			case strings.Contains(err.Error(), "no such host"):
				s.ErrorCounts.NoHostFound++
				fmt.Printf("\033[3m%s\033[0m: \033[1;31m %s \033[0m  \n", domain, err)
				s.logError(domain, errMsg, cipher.Name, file)
				s.Mutex.Unlock()
				return // return to main function and go to next domain

			// Fundamental issue that is unlikely to be resolved by trying different cipher suites
			case strings.Contains(err.Error(), "certificate"):
				s.ErrorCounts.OtherErrors["certificate related"]++
				s.logError(domain, errMsg, cipher.Name, file)
				s.Mutex.Unlock()
				return

			// Skip cipher suite causing timeout and move to next cipher
			case strings.Contains(err.Error(), "timeout"):
				s.ErrorCounts.OtherErrors["timeout related"]++
				s.logError(domain, errMsg, cipher.Name, file)
				s.Mutex.Unlock()
				continue

			// Not specific to the cipher suite but rather indicates a broader connectivity issue
			case strings.Contains(err.Error(), "connection refused"):
				s.ErrorCounts.OtherErrors["connection refused"]++
				s.logError(domain, errMsg, cipher.Name, file)
				s.Mutex.Unlock()
				return

			// Remote server forcibly closes the TCP connection. Attempting other connections
			// with different ciphers, is unlikely to resolve the issue.
			case strings.Contains(err.Error(), "connection reset"):
				s.ErrorCounts.OtherErrors["connection reset by peer"]++
				s.logError(domain, errMsg, cipher.Name, file)
				s.Mutex.Unlock()
				return

			// Fundamental issue on client-side.
			case strings.Contains(err.Error(), "permission denied"):
				s.ErrorCounts.OtherErrors["connect permission denied"]++
				s.logError(domain, errMsg, cipher.Name, file)
				s.Mutex.Unlock()
				return

			// Fundamental issue that indicates broader configuration problem
			case strings.Contains(err.Error(), "server misbehaving"):
				s.ErrorCounts.OtherErrors["server misbehaving"]++
				s.logError(domain, errMsg, cipher.Name, file)
				s.Mutex.Unlock()
				return

			default:
				errMsg := err.Error()
				if _, exists := s.ErrorCounts.OtherErrors[errMsg]; !exists {
					s.ErrorCounts.OtherErrors[errMsg] = 0 // if error message does not exist
				}
				s.ErrorCounts.OtherErrors[errMsg]++
				s.logError(domain, errMsg, cipher.Name, file)
			}
			s.Mutex.Unlock()
			fmt.Printf("\033[3m%s\033[0m: \033[1;31m %s \033[0m for %s\n", domain, err, cipher.Name)
		}

	}
	fmt.Printf("%s: \n %s\n", domain, strings.Join(supportedCiphers, ";"))
	// Outside of loop to prevent lock contention
	s.Mutex.Lock()
	s.ScannedCiphers = append(s.ScannedCiphers, domain+": "+strings.Join(supportedCiphers, ";"))
	s.Mutex.Unlock()
}

// Logs an error message for a given domain
func (s *Scanner) logError(domain, errMsg, cipherName string, file *os.File) {
	var logMsg string
	if strings.Contains(errMsg, "no such host") {
		// Exclude the cipher name from the log message for "no such host" errors
		logMsg = fmt.Sprintf("%s: %s\n", domain, errMsg)
	} else {
		// Include the cipher name in the log message for all other errors
		logMsg = fmt.Sprintf("%s: %s for %s\n", domain, errMsg, cipherName)
	}

	// Check if the file is not nil and write the log message to the file
	if file != nil {
		_, err := file.WriteString(logMsg)
		if err != nil {
			fmt.Printf("Error writing to file: %v\n", err)
		}
	}
}

// Sorts the content of the file specified by the given filename.
// It reads the file, sorts the lines in ascending order, and writes the sorted
// content back to the file.
func (s *Scanner) sortErrorFile(filename string) {
	content, err := os.ReadFile(filename)
	if err != nil {
		fmt.Printf("Error reading the file: %v\n", err)
		return
	}
	lines := strings.Split(string(content), "\n")

	sort.Strings(lines)
	sortedContent := strings.Join(lines, "\n")
	sortedContent = strings.ReplaceAll(sortedContent, "\n", "\n--------------------------------\n")
	err = os.WriteFile(filename, []byte(sortedContent), 0644)
	if err != nil {
		fmt.Printf("Error writing the sorted content back to the file: %v\n", err)
		return
	}
}

// Saves the scanned ciphers to a CSV file.
// It takes a filename as a parameter and creates a new file with the given name.
// If the file already exists, it overwrites the old content.
// The function locks the mutex to ensure thread safety while writing to the file.
func (s *Scanner) saveResultsToCSV(filename string) {

	s.Mutex.Lock()
	defer s.Mutex.Unlock()

	// Open the file for writing
	file, err := os.Create(filename)
	file.Truncate(0) // Overwrite the old content of output.csv

	if err != nil {
		fmt.Println("Error creating CSV file:", err)
		return
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	for _, cipher := range s.ScannedCiphers {
		parts := strings.Split(cipher, ":")
		writer.Write([]string{parts[0], parts[1]})
	}
}
