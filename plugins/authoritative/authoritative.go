package authoritative

import (
	"fmt"
	"log"
	"os"

	"bufio"
	"dns-resolver/internal/plugins"
	"github.com/miekg/dns"
	"strings"
)

type Record struct {
	ID int
	RR dns.RR
}

type AuthoritativePlugin struct {
	zones        map[string][]Record
	nextRecordID int
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
	for _, record := range zone {
		if record.RR.Header().Name == q.Name && record.RR.Header().Rrtype == q.Qtype {
			res.Answer = append(res.Answer, record.RR)
		}
	}

	// Send the response back to the client
	ctx.ResponseWriter.WriteMsg(res)

	// Stop the plugin chain
	ctx.Stop = true
	return nil
}

func New() *AuthoritativePlugin {
	p := &AuthoritativePlugin{
		zones:        make(map[string][]Record),
		nextRecordID: 1,
	}
	// p.LoadZone("example.com.zone")
	return p
}

func (p *AuthoritativePlugin) LoadZone(zoneFile string) error {
	file, err := os.Open(zoneFile)
	if err != nil {
		return err
	}
	defer file.Close()

	var zoneName string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "$ORIGIN") {
			parts := strings.Fields(line)
			if len(parts) > 1 {
				zoneName = parts[1]
				break
			}
		}
	}

	if zoneName == "" {
		return fmt.Errorf("could not find $ORIGIN in zone file: %s", zoneFile)
	}

	// Reset the file reader to the beginning
	file.Seek(0, 0)

	zoneParser := dns.NewZoneParser(file, zoneName, zoneFile)
	for rr, ok := zoneParser.Next(); ok; rr, ok = zoneParser.Next() {
		if err := zoneParser.Err(); err != nil {
			return err
		}
		p.zones[zoneName] = append(p.zones[zoneName], Record{ID: p.nextRecordID, RR: rr})
		p.nextRecordID++
	}
	log.Printf("Loaded %d records for zone %s", len(p.zones[zoneName]), zoneName)
	return nil
}

func (p *AuthoritativePlugin) GetZoneRecords(zoneName string) ([]Record, error) {
	records, ok := p.zones[zoneName]
	if !ok {
		return nil, fmt.Errorf("zone not found: %s", zoneName)
	}
	return records, nil
}

func (p *AuthoritativePlugin) AddZoneRecord(zoneName string, rr dns.RR) error {
	if _, ok := p.zones[zoneName]; !ok {
		return fmt.Errorf("zone not found: %s", zoneName)
	}
	p.zones[zoneName] = append(p.zones[zoneName], Record{ID: p.nextRecordID, RR: rr})
	p.nextRecordID++
	return nil
}

func (p *AuthoritativePlugin) UpdateZoneRecord(zoneName string, recordId int, newRR dns.RR) error {
	records, ok := p.zones[zoneName]
	if !ok {
		return fmt.Errorf("zone not found: %s", zoneName)
	}

	for i, record := range records {
		if record.ID == recordId {
			records[i].RR = newRR
			p.zones[zoneName] = records
			return nil
		}
	}

	return fmt.Errorf("record not found")
}

func (p *AuthoritativePlugin) DeleteZoneRecord(zoneName string, recordId int) error {
	records, ok := p.zones[zoneName]
	if !ok {
		return fmt.Errorf("zone not found: %s", zoneName)
	}

	for i, record := range records {
		if record.ID == recordId {
			p.zones[zoneName] = append(records[:i], records[i+1:]...)
			return nil
		}
	}

	return fmt.Errorf("record not found")
}

func (p *AuthoritativePlugin) GetZoneNames() []string {
	var names []string
	for name := range p.zones {
		names = append(names, name)
	}
	return names
}

func (p *AuthoritativePlugin) DeleteZone(zoneName string) error {
	if _, ok := p.zones[zoneName]; !ok {
		return fmt.Errorf("zone not found: %s", zoneName)
	}
	delete(p.zones, zoneName)
	return nil
}
