package main

import (
	"context"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/miekg/dns"
	"github.com/nsmithuk/resolver"
)

func main() {
	// Override the default logging hook on resolver.
	// Query to print each outgoing query to stdout.
	// (So you can see what's happening.)
	resolver.Query = func(s string) {
		fmt.Println("Query: " + s)
	}

	r := resolver.NewResolver()

	// Prepare a new DNS message struct.
	msg := new(dns.Msg)
	
	// Set it up as a question for the A record of "test.qazz.uk." (Fqdn adds trailing dot).
	msg.SetQuestion(dns.Fqdn("test.qazz.uk"), dns.TypeA)

	// Add an OPT record to enable EDNS0 with a 4096‐byte UDP payload and DNSSEC OK bit.
	msg.SetEdns0(4096, true)

	// Perform the DNS query, using a background Context (no timeout/cancel).
	// Returns a resolver.Result, or error info embedded inside it.
	result := r.Exchange(context.Background(), msg)

	// Dump the full Result struct (including Response Msg, error, timings, etc.)
	// to stdout in a human-readable form.
	spew.Dump(result)
}