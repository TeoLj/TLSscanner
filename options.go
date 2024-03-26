package main 

import (
	"flag"
	"runtime"
	"time"
  
   
)

// Contains the command-line options
type Options struct {
	DomainsList string
	Concurrency int
	Timeout     time.Duration
    EntriesToScan int
	CSVFilePath string
    ScanAndSaveDirectory string
}

// Initializes and parses the flags, returning an Options struct.
func ParseFlags() *Options {
    opts := &Options{}
    flag.StringVar(&opts.DomainsList, "domains", "", "Comma-separated list of domains to scan")
    flag.StringVar(&opts.CSVFilePath, "csv", "", "Path to a CSV file containing domains to scan")
    flag.StringVar(&opts.ScanAndSaveDirectory, "ScanAndSave", "", "Directory to save the results")
    
    flag.IntVar(&opts.EntriesToScan, "entries", -1, "Number of entries from the CSV file to scan; -1 for all")
    flag.IntVar(&opts.Concurrency, "concurrency", runtime.GOMAXPROCS(0), "Number of concurrent connections")

    timeout := flag.Int("timeout", 3000, "Connection timeout in milliseconds")
    flag.Parse()

    opts.Timeout = time.Millisecond * time.Duration(*timeout)
   
    return opts
}
