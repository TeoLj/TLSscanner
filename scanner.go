package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"
)

type Scanner struct {
	Domains     []string
	Concurrency int
	Timeout     time.Duration
	EntriesToScan int
	CSVFilePath string
}

func NewScanner(domains []string, concurrency int, timeout time.Duration, entries int, csvPath string) *Scanner {
	return &Scanner{
		Domains:     domains,
		Concurrency: concurrency,
		Timeout:     timeout,
		EntriesToScan: entries,
		CSVFilePath: csvPath,
	}
}

func (s *Scanner) StartScanner() {
	var wg sync.WaitGroup

	// create a buffered channel with a capacity of s.Concurrency
	// limit the number of goroutines that can run at the same time
	// channel defined as empty struct cos it takes no memory
	sem := make(chan struct{}, s.Concurrency) 

	for _, domain := range s.Domains {
		wg.Add(1) // new goroutine
		sem <- struct{}{} // will block if the channel is full, routine sends struct to take slot in the channel
		go func(domain string) { // closure function
			defer wg.Done() // decrease the counter when the goroutine completes
			s.scanDomain(domain)
			<-sem // release a slot in the channel
		}(domain) 
	}

	wg.Wait() // wait for all goroutines to complete
}

func (s *Scanner) scanDomain(domain string) {
	fmt.Printf("Scanning domain: %s\n", domain)
	for _, cipher := range tls.CipherSuites() {
		config := &tls.Config{
			CipherSuites: []uint16{cipher.ID},
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS13,
		}

		// establish a connection to the domain
		dialer := net.Dialer{Timeout: s.Timeout}
		// 443 is the default port for HTTPS
		conn, err := tls.DialWithDialer(&dialer, "tcp", domain+":443", config)
		if err == nil {
			fmt.Printf("%s: Cipher Suite Supported: %s\n", domain, cipher.Name)
			conn.Close()
		}
	}
}