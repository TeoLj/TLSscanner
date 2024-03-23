package main

import (
	"crypto/tls"
	"encoding/csv"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
)

type Scanner struct {
	Domains        []string
	ScannedCiphers []string
	opts           *Options
	Mutex          *sync.Mutex // fine grained locking
	ErrorCounts ErrorCounter
}

type ErrorCounter struct {
	HandshakeFailures int
	InvalidDomainFormat int
	NoHostFound int
	OtherErrors map[string]int
}

func NewScanner(domains []string, opts *Options) *Scanner {
	return &Scanner{
		Domains:        domains,
		ScannedCiphers: make([]string, 0), // create slice of strings with 0 length
		opts:           opts,
		Mutex:          &sync.Mutex{}, //initialize the mutex; & creates a pointer to the mutex
		ErrorCounts: ErrorCounter{
			OtherErrors: make(map[string]int),
		},
	}
}

func (s *Scanner) StartScanner() {
	var wg sync.WaitGroup

	// create a buffered channel with a capacity of s.Concurrency
	// limit the number of goroutines that can run at the same time
	// channel defined as empty struct cos it takes no memory
	sem := make(chan struct{}, s.opts.Concurrency) //  limiting the number of goroutines that can actively perform work at the same time

	for _, domain := range s.Domains {
		wg.Add(1)                // new goroutine
		sem <- struct{}{}        // will block if the channel is full, routine sends struct to take slot in the channel
		go func(domain string) { // closure function
			defer wg.Done() // decrease the counter when the goroutine completes
			s.scanDomain(domain)
			<-sem // release a slot in the channel
		}(domain)
	}

	wg.Wait() // wait for all goroutines to complete
	fileName := strings.TrimSuffix(strings.TrimPrefix(s.opts.CSVFilePath, "./"), ".csv")

	
	if s.opts.ScanAndSaveDirectory != "" {
		// Create a folder called output to save the results if it doesn't exist
		os.Chdir(s.opts.ScanAndSaveDirectory)
	} else {
		// Create a folder called output to save the results if it doesn't exist
		if _, err := os.Stat("output"); err == nil {
			os.RemoveAll("output")
		}
		os.Mkdir("output", 0755)
	}

	if s.opts.CSVFilePath != "" {
		if s.opts.ScanAndSaveDirectory != "" {
			s.saveResultsToCSV(s.opts.ScanAndSaveDirectory + "/" + fileName + "_cipherScan.csv")
		} else {
			s.saveResultsToCSV("./output/" + fileName + "_cipherScan.csv")
		}
	}

	if s.opts.DomainsList != "" {
		if s.opts.ScanAndSaveDirectory != "" {
			s.saveResultsToCSV(s.opts.ScanAndSaveDirectory + "/cipherScan.csv")
		} else {
			s.saveResultsToCSV("./output/cipherScan.csv")
		}
	}

}


func (s *Scanner) AnalyzeResults() {
	if s.opts.ScanAndSaveDirectory != "" {
		analyzer := NewAnalyzer(*s)
		analyzer.Run()
	} else {
		analyzer := NewAnalyzer(*s)
		analyzer.Run()
	}
}



func (s *Scanner) scanDomain(domain string) {
	var supportedCiphers []string

	fmt.Printf("Scanning domain: %s \n", domain)

	for _, cipher := range tls.CipherSuites() {
		config := &tls.Config{
			CipherSuites: []uint16{cipher.ID},
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS13,
			// InsecureSkipVerify: true, optional
		}

		// establish a connection to the domain
		dialer := net.Dialer{Timeout: s.opts.Timeout}

		// 443 is the default port for HTTPS
		conn, err := tls.DialWithDialer(&dialer, "tcp", domain+":443", config)
		if err == nil {
			supportedCiphers = append(supportedCiphers, cipher.Name) // lock not put here due to performance overhead(release mutex for every cipher)
			conn.Close()
		} else {
			
		s.Mutex.Lock()
        // Error checking logic
        switch {
        case strings.Contains(err.Error(), "handshake failure"):
            s.ErrorCounts.HandshakeFailures++
        case strings.Contains(err.Error(), "no such host"):
            s.ErrorCounts.NoHostFound++
        case strings.Contains(err.Error(), "invalid domain format"):
            // change defined by myself
            s.ErrorCounts.InvalidDomainFormat++
        default:
            errMsg := err.Error()
            if _, exists := s.ErrorCounts.OtherErrors[errMsg]; !exists {
                s.ErrorCounts.OtherErrors[errMsg] = 0
            }
            s.ErrorCounts.OtherErrors[errMsg]++
        }
        s.Mutex.Unlock()
        fmt.Printf("\033[3m%s\033[0m: \033[1;31m %s \033[0m for %s\n", domain, err, cipher.Name)
    	}

	}
	
	fmt.Printf("%s: \n %s\n", domain, strings.Join(supportedCiphers, ";"))
	// outside of loop to prevent lock contention
	s.Mutex.Lock()
	s.ScannedCiphers = append(s.ScannedCiphers, domain+": "+strings.Join(supportedCiphers, ";"))
	s.Mutex.Unlock()
	
}



func (s *Scanner) saveResultsToCSV(filename string) {

	s.Mutex.Lock()
	defer s.Mutex.Unlock()

	// open the file for writing
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

