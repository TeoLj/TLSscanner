package main

import (
	"flag"
	"fmt"
	"strings"
	"time"
)

func main() {
	start := time.Now()
	fmt.Println("\033[1;35mStart:", start.Format("2006-01-02 15:04:05"), "\033[0m")

	opts := ParseFlags()

	flag.Parse() // execute the command-line parsing

	if opts.DomainsList == "" {
		println("Please specify a list of domains")
		return
	}

	domains := strings.Split(opts.DomainsList, ",")
	for i, domain := range domains {
		domains[i] = strings.TrimSpace(domain) // Trim spaces from each domain
	}

	scanner := NewScanner(domains, opts.Concurrency, opts.Timeout, opts.EntriesToScan, opts.CSVFilePath)
	scanner.StartScanner()

	end := time.Now()
	fmt.Println("\033[1;35mEnd:", end.Format("15:04:05"), "Duration:", end.Sub(start), "\033[0m")

}
