package main

import (
	"flag"
	"runtime"
	"time"
)

// Contains the command-line options
type Options struct {
	DomainsList string

	Timeout       time.Duration
	EntriesToScan int
	CSVFilePath   string
	SaveDir       string

	Naive       bool
	Concurrency int
	Parallel    bool
}

// Initializes and parses the flags, returning an Options struct.
func ParseFlags() *Options {
	opts := &Options{}
	flag.StringVar(&opts.DomainsList, "domains", "", "Comma-separated list of domains to scan")
	flag.StringVar(&opts.CSVFilePath, "csv", "", "Path to a CSV file containing domains to scan")
	flag.StringVar(&opts.SaveDir, "saveDir", "", "Directory to save the results")

	flag.IntVar(&opts.EntriesToScan, "entries", -1, "Number of entries from the CSV file to scan; -1 for all")
	flag.IntVar(&opts.Concurrency, "concurrency", runtime.GOMAXPROCS(0), "Number of concurrent connections")


	flag.BoolVar(&opts.Naive,"naive",false, "Use a naive scanner that scans sequentially")

	timeout := flag.Int("timeout", 3000, "Connection timeout in milliseconds")
	flag.Parse()

	opts.Timeout = time.Millisecond * time.Duration(*timeout)

	return opts
}
