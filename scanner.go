package main

import (
	"crypto/tls"
	"encoding/csv"
	"fmt"
	"net"
	"os"
	"sync"
	"strings"
	
	//"time"
)

type Scanner struct {
	Domains     []string
	ScannedCiphers []string
	opts *Options // pointer to the Options struct: TimeOut, Concurrency, SaveResults
	Mutex *sync.Mutex // check if the mutex is neeeded here
}

func NewScanner(domains []string,  opts *Options) *Scanner {
	return &Scanner{
		Domains:     domains,
		ScannedCiphers: make([]string, 0),
		opts: opts,
		Mutex: &sync.Mutex{}, //initialize the mutex
	}
}

func (s *Scanner) StartScanner() {
	var wg sync.WaitGroup

	// create a buffered channel with a capacity of s.Concurrency
	// limit the number of goroutines that can run at the same time
	// channel defined as empty struct cos it takes no memory
	sem := make(chan struct{}, s.opts.Concurrency) 

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
	if s.opts.SaveResults {
		s.saveResultsToCSV("scanned_ciphers.csv")
	}
}

func (s *Scanner) scanDomain(domain string) {
	var supportedCiphers []string

	fmt.Printf("Scanning domain: %s\n", domain)
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
			fmt.Printf("%s: Cipher Suite Supported: %s\n", domain, cipher.Name)
			supportedCiphers = append(supportedCiphers, cipher.Name)
			conn.Close()
		} else {
			fmt.Printf("%s: Connection error: %s\n", domain, err)
		}
	}


	s.Mutex.Lock()
	s.ScannedCiphers = append(s.ScannedCiphers, domain+": "+strings.Join(supportedCiphers, ";"))
	s.Mutex.Unlock()
}

// - method of Scanner struct through (s *Scanner), changes made to Scanner interface will be reflected in the struct
// - takes struct as function argument -> makes it possitble to filter the list of ciphers in a specific 
// way before writing to a file
func (s *Scanner) saveResultsToCSV(filename string) {

	s.Mutex.Lock()
	defer s.Mutex.Unlock()

	// open the file for writing
	file, err := os.Create(filename)
	if err != nil {
		fmt.Println("Error creating CSV file:", err)
		return
	}
	defer file.Close()

	writer:= csv.NewWriter(file)
	defer writer.Flush()

	for _,cipher:= range s.ScannedCiphers{
		parts:= strings.Split(cipher, ":")
		writer.Write([]string{parts[0], parts[1]})
	}

	
}