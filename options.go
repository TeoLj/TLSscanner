package main 

import (
	"flag"
	"runtime"
	"time"
)

// Options contains the command-line options.
type Options struct {
	DomainsList string
	Concurrency int
	Timeout     time.Duration
}

// ParseFlags initializes and parses the flags, returning an Options struct.
func ParseFlags() *Options {
    opts := &Options{}
    flag.StringVar(&opts.DomainsList, "domains", "", "Comma-separated list of domains to scan")
    
    opts.Concurrency = runtime.GOMAXPROCS(0) // Set concurrency to the number of CPUs
    timeout := flag.Int("timeout", 5000, "Connection timeout in milliseconds")
    flag.Parse()

    opts.Timeout = time.Millisecond * time.Duration(*timeout)
    return opts
}