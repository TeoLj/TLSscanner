package main 

import (
	"fmt"
	"strings"
)

type Analyzer struct {
	Scanner 
}
// uses Struct elements Domains[]string, ScannedCiphers []string to analyze occurence of ciphers

func NewAnalyzer(scanner Scanner) *Analyzer {
	return &Analyzer{
		Scanner: scanner,
	}
}

func (a *Analyzer) AnalyseCiphers() {
	   // Map to hold the count of each cipher suite
	   cipherCount := make(map[string]int)

	   // Iterate over the scanned ciphers, assuming each entry is a domain followed by a list of ciphers
	   for _, scanned := range a.ScannedCiphers { 
		   // Assuming each entry in ScannedCiphers is a string like "domain: cipher1;cipher2;cipher3" (specified in ScanDomain)
		   // Split the string into domain and ciphers part 
		   parts := strings.Split(scanned, ": ")
		   if len(parts) != 2 {
			   fmt.Println("Unexpected format in ScannedCiphers, skipping:", scanned)
			   continue
		   }
		   // Now parts[1] contains "cipher1;cipher2;cipher3", split these into individual ciphers
		   ciphers := strings.Split(parts[1], ";")

		   // Count each cipher occurrence
		   for _, cipher := range ciphers {
			   cipherCount[cipher]++
		   }
	   }
   
	   // Now print the count of each cipher suite
	fmt.Println("\n\033[1;33mCipher suite occurrences:\033[0m")
	   for cipher, count := range cipherCount {
		fmt.Printf("%s: \033[1;34m%d\033[0m\n", cipher, count)
	   }
}