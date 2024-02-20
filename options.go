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
    SaveResultsDirectory string
    AnalyseCipher bool 
    PlotResults bool 
}

// Initializes and parses the flags, returning an Options struct.
func ParseFlags() *Options {
    opts := &Options{}
    flag.StringVar(&opts.DomainsList, "domains", "", "Comma-separated list of domains to scan")
    flag.StringVar(&opts.CSVFilePath, "csv", "", "Path to a CSV file containing domains to scan")
    flag.StringVar(&opts.SaveResultsDirectory, "output", "", "Directory to save the results")

    flag.BoolVar(&opts.SaveResults, "save", false, "Save results to a csv file")
    flag.BoolVar(&opts.AnalyseCipher, "analyse", false, "Analyse the occurence of cipher suites")
    
    flag.IntVar(&opts.EntriesToScan, "entries", -1, "Number of entries from the CSV file to scan; -1 for all")
    flag.IntVar(&opts.Concurrency, "concurrency", runtime.GOMAXPROCS(0), "Number of concurrent connections")

    timeout := flag.Int("timeout", 9000, "Connection timeout in milliseconds")
    flag.Parse()

    opts.Timeout = time.Millisecond * time.Duration(*timeout)
   
    return opts
}