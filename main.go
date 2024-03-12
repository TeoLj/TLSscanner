package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

)

func main() {
	
	start := time.Now()
	fmt.Println("\033[1;35mStart:", start.Format("2006-01-02 15:04:05"), "\033[0m")

	opts := ParseFlags()

	flag.Parse() // execute the command-line parsing
	var domains []string

	if opts.CSVFilePath != "" {
		var err error
		domains, err = readCSV(opts.CSVFilePath, opts.EntriesToScan)

		if err != nil {
			fmt.Println("Error reading CSV file:", err)
			return
		}
	} else if opts.DomainsList != "" {
		domains = strings.Split(opts.DomainsList, ",")
	}

	scanner := NewScanner(domains, opts)
	scanner.StartScanner()

	end := time.Now()
	fmt.Println("\033[1;35mEnd:", end.Format("2006-01-02 15:04:05"), "| Duration:", end.Sub(start), "\033[0m")



}

func readCSV(filePath string, entriesToScan int) ([]string, error) {

	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var domains []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if entriesToScan > 0 && len(domains) >= entriesToScan {
			break
		}
		line := scanner.Text()
		record := strings.Split(line, ",")
		for _, field := range record {
			domain, err := extractDomain(field)
			if err != nil {
				fmt.Printf("\033[1;31mError for: %s %v\033[0m\n", field, err)
			}
			if err == nil && domain != "" {
				domains = append(domains, domain)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading CSV file:", err)
		return nil, err
	}

	return domains, nil
}

func extractDomain(field string) (string, error) {

	field = strings.TrimSpace(field)
	if strings.HasPrefix(field, "http://") || strings.HasPrefix(field, "https://") {
		u, err := url.Parse(field)
		if err != nil {
			return "", err
		}

		return u.Hostname(), nil
	} else if strings.HasPrefix(field, "www.") || strings.HasSuffix(field, ".com") {
		return field, nil
	}
	return "", fmt.Errorf("invalid domain format")
}
