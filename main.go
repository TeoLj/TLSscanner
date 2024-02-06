package main

import (
	"flag"
	"sync"
)

func main() {
	domain := flag.String("domain", "", "Domain to scan for TLS cipher suite support")
	flag.Parse()

	if *domain == "" {
		println("Please specify a domain")
		return
	}

	domains := []string{*domain}

	var wg sync.WaitGroup
	for _, d := range domains {
		wg.Add(1)
		go func(domain string) {
			defer wg.Done()
			ScanDomain(domain)
		}(d)
	}
	wg.Wait()
}

// ### TO DO###
/*
1. Look up authenticate go.sum private repos
2. go.mod vs go.sum
3. Adapt chat to take into account private repository
*/
