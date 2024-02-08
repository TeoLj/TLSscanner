package main

import (
	"flag"
	"strings"
	"sync"
)

func main() {
	// default value is empty string, third argument is the description of the flag
	domainsList := flag.String("domains", "", "A comma-separated list of domains to scan for TLS cipher suite support")
	flag.Parse()

	if *domainsList == "" {
		println("Please specify a list of domains")
		return
	}

	domains := strings.Split(*domainsList, ",")
	var wg sync.WaitGroup
	for _, d := range domains {
		domain := strings.TrimSpace(d) // Trim any whitespace from the domain
		if domain == "" {
			continue // Skip empty entries
		}
		wg.Add(1)
		go func(domain string) {
			defer wg.Done()
			ScanDomain(domain)
		}(domain)
	}
	wg.Wait()
}
