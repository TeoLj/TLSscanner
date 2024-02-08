package main

import (
	"flag"
	"fmt"
	"strings"
	"time"
)

func main() {
	start := time.Now()
	fmt.Println("Start:", start.Format("2006-01-02 15:04:05"))

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

	scanner := NewScanner(domains, opts.Concurrency, opts.Timeout)
	scanner.StartScanner()

	end := time.Now()
	fmt.Println("End: %, Duration: %", end.Format("15:04:05"), end.Sub(start))

}
