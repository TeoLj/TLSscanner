package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

func ScanDomain(domain string) {
	fmt.Printf("Scanning domain: %s\n", domain)
	for _, cipher := range tls.CipherSuites() {
		config := &tls.Config{
			CipherSuites: []uint16{cipher.ID},
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS13,
		}

		dialer := net.Dialer{Timeout: 5 * time.Second}
		conn, err := tls.DialWithDialer(&dialer, "tcp", domain+":443", config)
		if err == nil {
			fmt.Printf("%s: Cipher Suite Supported: %s\n", domain, cipher.Name)
			conn.Close()
		}
	}
}
