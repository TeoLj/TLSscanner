package main

import (
	"bufio"
	"flag"
	"fmt"
	//"net/url"
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
			//fmt.Println("Error reading CSV file:", err)
			return
		}
	} else if opts.DomainsList != "" {
		domainsPrepared := strings.Split(opts.DomainsList, ",")
		domains = make([]string, 0, len(domainsPrepared)) // Initialize with capacity, not fixed length

		for _, domain := range domainsPrepared {
 		   domain = strings.TrimSpace(domain) // Trim whitespace
 		   extractedDomain := extractDomain(domain) // Extract the domain
   		   if extractedDomain != "" { // Ensure the domain is not empty
      		  domains = append(domains, extractedDomain) // Add to the list
  			}	
		}
	}

	scanner := newScanner(domains, opts)
	scanner.startScanner()
	scanner.analyzeResults()

	end := time.Now()

	duration := end.Sub(start)
	totalSeconds := int(duration.Seconds())

	// Calculate minutes and seconds
	minutes := totalSeconds / 60
	seconds := totalSeconds % 60

	// Print end time and formatted duration
	fmt.Printf("\033[1;35mEnd: %s | Duration: %02d:%02d\033[0m\n",
		end.Format("2006-01-02 15:04:05"), minutes, seconds)

}

// Reads a CSV file from the specified file path and extracts domains from the file.
// It returns a slice of strings containing the extracted domains.
// The function stops reading the file when the number of entries to scan is reached.
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
        
        // Assuming the format is always number,domain and the domain is the second element.
        if len(record) >= 2 { // Check if the line has at least two elements
            domain := record[1] // Directly access the domain part
            
            // Assuming extractDomain function validates or processes the domain further.
            validatedDomain:= extractDomain(domain)
           
            if validatedDomain != "" {
                domains = append(domains, validatedDomain)
            }
        }
    }
	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading CSV file:", err)
		return nil, err
	}

	return domains, nil
}

// Extracts the domain from a given field.
// The dial function is used to establish a lower-level TCP connection, 
// and it requires just the domain name (or IP address) and the port number, without the scheme (http or https).
func extractDomain(field string) (string) {

	field = strings.TrimSpace(field)
	domain := strings.TrimPrefix(field, "https://")
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "www.")

	return domain
}
