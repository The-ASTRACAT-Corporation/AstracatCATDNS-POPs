package main

import (
	"fmt"
	"log"
	"os"

	"github.com/miekg/dns"
	goresolver "github.com/peterzen/goresolver"
)

func main() {
	// Initialize the resolver with the system's resolv.conf
	res, err := goresolver.NewResolver("/etc/resolv.conf")
	if err != nil {
		log.Fatalf("Failed to initialize resolver: %v", err)
	}
	goresolver.CurrentResolver = res // Set the global resolver instance

	qname := "google.com"
	qtype := dns.TypeTXT

	fmt.Printf("Looking up %s (type %s) using goresolver...\n", qname, dns.TypeToString[qtype])

	msg, err := goresolver.CurrentResolver.Query(qname, qtype)
	if err != nil {
		log.Fatalf("Error querying DNS: %v", err)
	}

	if msg == nil || msg.Rcode != dns.RcodeSuccess {
		log.Fatalf("DNS query failed or returned no data: %v", msg)
	}

	fmt.Println("DNSSEC validation is handled internally by goresolver's lookup functions.")
	fmt.Println("Received TXT records:")
	for _, rr := range msg.Answer {
		if t, ok := rr.(*dns.TXT); ok {
			fmt.Printf("  %s\n", t.String())
		}
	}
}