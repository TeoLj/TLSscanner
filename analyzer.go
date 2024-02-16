package main

import (
	"fmt"
	"strings"
	"os"
	"encoding/csv"
	"sync"
	
)

type Analyzer struct {
	ScannedCiphers []string
	SaveResults bool
	SaveResultsDirectory string
	cipherCount    map[string]int
	Mutex		  *sync.Mutex // fine grained locking
}

// uses Struct elements Domains[]string, ScannedCiphers []string to analyze occurence of ciphers

func NewAnalyzer(scanner Scanner) *Analyzer {
	return &Analyzer{
		ScannedCiphers: scanner.ScannedCiphers,
		SaveResults: scanner.opts.SaveResults,
		SaveResultsDirectory: scanner.opts.SaveResultsDirectory,
		cipherCount:    make(map[string]int),
		Mutex:          &sync.Mutex{},
	}
}

func (a *Analyzer) Run(){

	a.AnalyzeCiphers()

	if a.SaveResults {
		if a.SaveResultsDirectory != "" {
			os.Chdir(a.SaveResultsDirectory)
			a.SaveCiphersCount(a.SaveResultsDirectory + "/cipherCounts.csv")
		} else {
			a.SaveCiphersCount("cipherCounts.csv")
		}
	}
}

func (a *Analyzer) AnalyzeCiphers() map[string]int {

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
			a.cipherCount[cipher]++
		}
	}

	// Now print the count of each cipher suite
	fmt.Println("\n\033[1;33mCipher suite occurrences:\033[0m")
	for cipher, count := range a.cipherCount {
		fmt.Printf("%s: \033[1;34m%d\033[0m\n", cipher, count)
	}
	return a.cipherCount
}

func (a *Analyzer) SaveCiphersCount(filename string) {

	a.Mutex.Lock()
	defer a.Mutex.Unlock()

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

	// Write the header
	writer.Write([]string{"Cipher", "Count"})
	for cipher, count := range a.cipherCount {
		writer.Write([]string{cipher, fmt.Sprintf("%d", count)})
	}
}