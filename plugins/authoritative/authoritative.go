package authoritative

import (
	"log"
	"os"

	"dns-resolver/internal/plugins"
	"github.com/miekg/dns"
)

type AuthoritativePlugin struct {
	zones map[string][]dns.RR
}

func (p *AuthoritativePlugin) Name() string {
	return "Authoritative"
}

func (p *AuthoritativePlugin) Execute(ctx *plugins.PluginContext, msg *dns.Msg) error {
	q := msg.Question[0]

	// Check if we are authoritative for the queried domain
	zone, ok := p.zones[q.Name]
	if !ok {
		// We are not authoritative, so let the recursive resolver handle it
		return nil
	}

	// We are authoritative, so we need to handle the query
	log.Printf("[%s] Handling authoritative query for: %s", p.Name(), q.Name)

	// Create a new response message
	res := &dns.Msg{}
	res.SetReply(msg)

	// Find the matching records in the zone
	// This is a simplified implementation and may not handle all cases
	for _, rr := range zone {
		if rr.Header().Name == q.Name && rr.Header().Rrtype == q.Qtype {
			res.Answer = append(res.Answer, rr)
		}
	}

	// Send the response back to the client
	ctx.ResponseWriter.WriteMsg(res)

	// Stop the plugin chain
	ctx.Stop = true
	return nil
}

func New() *AuthoritativePlugin {
	return &AuthoritativePlugin{
		zones: make(map[string][]dns.RR),
	}
}

func (p *AuthoritativePlugin) LoadZone(zoneFile string) error {
	file, err := os.Open(zoneFile)
	if err != nil {
		return err
	}
	defer file.Close()

	zoneParser := dns.NewZoneParser(file, "", zoneFile)
	for rr, ok := zoneParser.Next(); ok; rr, ok = zoneParser.Next() {
		if err := zoneParser.Err(); err != nil {
			return err
		}
		zoneName := rr.Header().Name
		p.zones[zoneName] = append(p.zones[zoneName], rr)
	}
	return nil
}
