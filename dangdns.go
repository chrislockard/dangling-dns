package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type DNSResult struct {
	Domain       string
	RecordType   string
	Value        string
	IsVulnerable bool
	ErrorMsg     string
}

func main() {
	delayMs := flag.Int("delay", 100, "Delay between DNS lookups in milliseconds")
	singleDomain := flag.String("domain", "", "Single domain to check (overrides domains file)")
	dnsServer := flag.String("dns", "8.8.8.8:53", "DNS server to use (format: host:port)")
	flag.Parse()

	var domains []string
	var err error

	if *singleDomain != "" {
		domains = []string{*singleDomain}
	} else if len(flag.Args()) < 1 {
		fmt.Println("Usage: dangdns [-delay ms] [-domain single.domain.com] [-dns host:port] [domains_file.txt]")
		fmt.Println("  -delay: milliseconds to wait between DNS lookups (default: 100)")
		fmt.Println("  -domain: check a single domain (optional)")
		fmt.Println("  -dns: DNS server to use (default: 8.8.8.8:53)")
		fmt.Println("  domains_file.txt: file with one domain per line (required if -domain not used)")
		os.Exit(1)
	} else {
		domainsFile := flag.Args()[0]
		domains, err = readDomains(domainsFile)
		if err != nil {
			fmt.Printf("Error reading domains file: %v\n", err)
			os.Exit(1)
		}
	}

	delay := time.Duration(*delayMs) * time.Millisecond
	results := checkDomains(domains, delay, *dnsServer)
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

// Check all domains with rate limiting
func checkDomains(domains []string, delay time.Duration, dnsServer string) []DNSResult {
	var wg sync.WaitGroup
	resultsChan := make(chan DNSResult, len(domains)*3)
	limiter := make(chan struct{}, 1) // Rate limiting channel

	// Initial token for rate limiter
	limiter <- struct{}{}

	for _, domain := range domains {
		wg.Add(3) // For CNAME, A, and AAAA checks

		// Launch checks with rate limiting
		go func(d string) {
			<-limiter // Wait for token
			checkCNAME(d, resultsChan, &wg, dnsServer)
			time.Sleep(delay)
			limiter <- struct{}{} // Release token
		}(domain)

		go func(d string) {
			<-limiter
			checkA(d, resultsChan, &wg)
			time.Sleep(delay)
			limiter <- struct{}{}
		}(domain)

		go func(d string) {
			<-limiter
			checkAAAA(d, resultsChan, &wg)
			time.Sleep(delay)
			limiter <- struct{}{}
		}(domain)
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

// Check CNAME records with chain following
func checkCNAME(domain string, ch chan<- DNSResult, wg *sync.WaitGroup, dnsServer string) {
	defer wg.Done()

	c := dns.Client{
		Timeout: 5 * time.Second, // Add timeout to prevent hanging
	}
	m := dns.Msg{}
	lastCname := domain

	// Follow CNAME chain
	for {
		m.SetQuestion(dns.Fqdn(lastCname), dns.TypeCNAME)
		r, _, err := c.Exchange(&m, dnsServer)
		if err != nil {
			ch <- DNSResult{domain, "CNAME", lastCname, true, fmt.Sprintf("Lookup error: %v", err)}
			return
		}
		if len(r.Answer) == 0 {
			break // No more CNAMEs in chain
		}

		// Get the last CNAME record
		record, ok := r.Answer[len(r.Answer)-1].(*dns.CNAME)
		if !ok {
			ch <- DNSResult{domain, "CNAME", lastCname, true, "Invalid CNAME response"}
			return
		}
		lastCname = record.Target
	}

	// Verify the final target exists
	_, err := net.LookupHost(lastCname)
	if err != nil {
		ch <- DNSResult{domain, "CNAME", lastCname, true, "Target doesn't resolve"}
	} else {
		ch <- DNSResult{domain, "CNAME", lastCname, false, ""}
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
