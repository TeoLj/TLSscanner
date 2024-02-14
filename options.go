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
    SaveResults bool
}

// Initializes and parses the flags, returning an Options struct.
func ParseFlags() *Options {
    opts := &Options{}
    flag.StringVar(&opts.DomainsList, "domains", "", "Comma-separated list of domains to scan")
    flag.BoolVar(&opts.SaveResults, "save", false, "Save results to a csv file")
    flag.StringVar(&opts.CSVFilePath, "csv", "", "Path to a CSV file containing domains to scan")
    flag.IntVar(&opts.EntriesToScan, "entries", -1, "Number of entries from the CSV file to scan; -1 for all")
    opts.Concurrency = runtime.GOMAXPROCS(0) // Set concurrency to the number of CPUs
    timeout := flag.Int("timeout", 5000, "Connection timeout in milliseconds")
    flag.Parse()

    opts.Timeout = time.Millisecond * time.Duration(*timeout)
   
    return opts
}