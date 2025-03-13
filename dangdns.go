package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
)

type DNSResult struct {
	Domain       string
	RecordType   string
	Value        string
	IsVulnerable bool
	ErrorMsg     string
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: dangdns <domains_file.txt>")
		fmt.Println("File should contain one domain per line")
		os.Exit(1)
	}

	domainsFile := os.Args[1]
	domains, err := readDomains(domainsFile)
	if err != nil {
		fmt.Printf("Error reading domains file: %v\n", err)
		os.Exit(1)
	}

	results := checkDomains(domains)
	printResults(results)
}

// Read domains from file
func readDomains(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var domains []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain != "" {
			domains = append(domains, domain)
		}
	}
	return domains, scanner.Err()
}

// Check all domains concurrently
func checkDomains(domains []string) []DNSResult {
	var wg sync.WaitGroup
	resultsChan := make(chan DNSResult, len(domains)*3) // Buffer for 3 record types per domain

	for _, domain := range domains {
		wg.Add(3) // For CNAME, A, and AAAA checks
		go checkCNAME(domain, resultsChan, &wg)
		go checkA(domain, resultsChan, &wg)
		go checkAAAA(domain, resultsChan, &wg)
	}

	// Close results channel when all checks are done
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	var results []DNSResult
	for result := range resultsChan {
		results = append(results, result)
	}
	return results
}

// Check CNAME records
func checkCNAME(domain string, ch chan<- DNSResult, wg *sync.WaitGroup) {
	defer wg.Done()

	cnames, err := net.LookupCNAME(domain)
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			return // No CNAME record exists
		}
		ch <- DNSResult{domain, "CNAME", "", true, fmt.Sprintf("Lookup error: %v", err)}
		return
	}

	// Verify the CNAME target exists
	_, err = net.LookupHost(cnames)
	if err != nil {
		ch <- DNSResult{domain, "CNAME", cnames, true, "Target doesn't resolve"}
	}
}

// Check A records
func checkA(domain string, ch chan<- DNSResult, wg *sync.WaitGroup) {
	defer wg.Done()

	ips, err := net.LookupIP(domain)
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			return // No A record exists
		}
		ch <- DNSResult{domain, "A", "", true, fmt.Sprintf("Lookup error: %v", err)}
		return
	}

	for _, ip := range ips {
		if ip.To4() != nil { // IPv4 address
			ch <- DNSResult{domain, "A", ip.String(), false, ""}
		}
	}
}

// Check AAAA records
func checkAAAA(domain string, ch chan<- DNSResult, wg *sync.WaitGroup) {
	defer wg.Done()

	ips, err := net.LookupIP(domain)
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			return // No AAAA record exists
		}
		ch <- DNSResult{domain, "AAAA", "", true, fmt.Sprintf("Lookup error: %v", err)}
		return
	}

	for _, ip := range ips {
		if ip.To4() == nil { // IPv6 address
			ch <- DNSResult{domain, "AAAA", ip.String(), false, ""}
		}
	}
}

// Print results in a formatted way
func printResults(results []DNSResult) {
	fmt.Println("\nDNS Vulnerability Check Results")
	fmt.Println("===============================")

	hasVulnerabilities := false
	for _, result := range results {
		if result.IsVulnerable {
			hasVulnerabilities = true
			fmt.Printf("[VULNERABLE] Domain: %s\n", result.Domain)
			fmt.Printf("  Type: %s\n", result.RecordType)
			fmt.Printf("  Value: %s\n", result.Value)
			fmt.Printf("  Issue: %s\n\n", result.ErrorMsg)
		} else if result.Value != "" {
			fmt.Printf("[OK] Domain: %s\n", result.Domain)
			fmt.Printf("  Type: %s\n", result.RecordType)
			fmt.Printf("  Value: %s\n\n", result.Value)
		}
	}

	if !hasVulnerabilities {
		fmt.Println("No vulnerabilities found in checked domains.")
	}
}
