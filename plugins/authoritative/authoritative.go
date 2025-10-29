package authoritative

// Production-ready authoritative plugin for a DNS resolver.
// - Longest-suffix zone matching
// - Thread-safe zone storage and CRUD
// - Proper AA/RA flags
// - NXDOMAIN/NODATA handling with SOA in Authority
// - Authority NS and Additional glue records
// - Zone file loader via github.com/miekg/dns NewZoneParser

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"dns-resolver/internal/plugins"
)

// Record wraps a dns.RR with an internal ID and keeps original TTL
type Record struct {
	ID  int
	RR  dns.RR
}

// Zone holds parsed records indexed for fast lookup
type Zone struct {
	Name string // FQDN (ends with dot)

	// index: owner name -> type(uint16) -> []Record
	records map[string]map[uint16][]Record
	// keep list of NS records for authority
	nsRecords []dns.RR
	// soa record if present
	soa dns.RR

	mu sync.RWMutex
}

// AuthoritativePlugin is thread-safe and intended for production use
type AuthoritativePlugin struct {
	zones        map[string]*Zone // key: FQDN zone name
	nextRecordID int
	mu           sync.RWMutex // protects zones map and nextRecordID
}

func New() *AuthoritativePlugin {
	return &AuthoritativePlugin{
		zones:        make(map[string]*Zone),
		nextRecordID: 1,
	}
}

func (p *AuthoritativePlugin) Name() string { return "Authoritative" }

// findZone implements longest-suffix match. qName must be FQDN
func (p *AuthoritativePlugin) findZone(qName string) (*Zone, bool) {
	q := dns.Fqdn(strings.ToLower(qName))
	p.mu.RLock()
	defer p.mu.RUnlock()

	// Collect candidate zone names and pick longest
	var best *Zone
	var bestLen int
	for _, z := range p.zones {
		// zone.Name is already FQDN lowercased
		if strings.HasSuffix(q, z.Name) {
			if len(z.Name) > bestLen {
				best = z
				bestLen = len(z.Name)
			}
		}
	}
	if best == nil {
		return nil, false
	}
	return best, true
}

// Execute handles incoming queries. It returns nil to allow the chain to continue
// when not authoritative for the qname. When authoritative it writes a reply
// and sets ctx.Stop = true to halt further processing.
func (p *AuthoritativePlugin) Execute(ctx *plugins.PluginContext, msg *dns.Msg) error {
	if len(msg.Question) == 0 {
		return nil
	}
	q := msg.Question[0]
	zone, ok := p.findZone(q.Name)
	if !ok {
		// not authoritative
		return nil
	}

	log.Printf("[%s] authoritative handling for %s (qtype=%d)", p.Name(), q.Name, q.Qtype)

	res := &dns.Msg{}
	res.SetReply(msg)
	res.Authoritative = true
	res.RecursionAvailable = false

	// lookup
	name := dns.Fqdn(strings.ToLower(q.Name))
	zone.mu.RLock()
	recordsForName, nameExists := zone.records[name]
	zone.mu.RUnlock()

	if nameExists {
		// check for requested type
		zone.mu.RLock()
		recs := recordsForName[q.Qtype]
		// If qtype is ANY (255) collect all types except OPT
		if q.Qtype == dns.TypeANY {
			for t, arr := range recordsForName {
				if t == dns.TypeOPT { // skip OPT
					continue
				}
				for _, r := range arr {
					res.Answer = append(res.Answer, r.RR)
				}
			}
		} else if len(recs) > 0 {
			for _, r := range recs {
				res.Answer = append(res.Answer, r.RR)
			}
		}
		zone.mu.RUnlock()

		if len(res.Answer) > 0 {
			// Successful answer. Add NS records to authority and glue to additional
			p.addAuthorityAndGlue(res, zone)
			ctx.ResponseWriter.WriteMsg(res)
			ctx.Stop = true
			return nil
		}
		// Name exists but no records of requested type => NODATA (NOERROR)
		res.Rcode = dns.RcodeSuccess
		p.addSOAAuthority(res, zone)
		ctx.ResponseWriter.WriteMsg(res)
		ctx.Stop = true
		return nil
	}

	// Name does not exist within the zone => NXDOMAIN. Include SOA in Authority.
	res.Rcode = dns.RcodeNameError
	p.addSOAAuthority(res, zone)
	ctx.ResponseWriter.WriteMsg(res)
	ctx.Stop = true
	return nil
}

// addAuthorityAndGlue populates Authority with NS records and Additional with glue A/AAAA if present
func (p *AuthoritativePlugin) addAuthorityAndGlue(res *dns.Msg, z *Zone) {
	z.mu.RLock()
	defer z.mu.RUnlock()
	if len(z.nsRecords) > 0 {
		for _, rr := range z.nsRecords {
			res.Ns = append(res.Ns, rr)
			// add glue if the NS is in-zone and we have A/AAAA
			if ns, ok := rr.(*dns.NS); ok {
				owner := dns.Fqdn(strings.ToLower(ns.Ns))
				if recs, found := z.records[owner]; found {
					// add A and AAAA
					for _, r := range recs[dns.TypeA] {
						res.Extra = append(res.Extra, r.RR)
					}
					for _, r := range recs[dns.TypeAAAA] {
						res.Extra = append(res.Extra, r.RR)
					}
				}
			}
		}
	}
}

// addSOAAuthority sets SOA in Authority (used for NXDOMAIN and NODATA)
func (p *AuthoritativePlugin) addSOAAuthority(res *dns.Msg, z *Zone) {
	z.mu.RLock()
	defer z.mu.RUnlock()
	if z.soa != nil {
		res.Ns = append(res.Ns, z.soa)
	} else if len(z.nsRecords) > 0 {
		for _, rr := range z.nsRecords {
			res.Ns = append(res.Ns, rr)
		}
	}
}

// LoadZone loads a zonefile into a new Zone. If zone already exists, it will be replaced.
func (p *AuthoritativePlugin) LoadZone(zoneFile string) error {
	f, err := os.Open(zoneFile)
	if err != nil {
		return err
	}
	defer f.Close()

	// Determine origin from $ORIGIN or from file metadata
	origin, err := detectOrigin(f)
	if err != nil {
		return err
	}
	origin = dns.Fqdn(strings.ToLower(origin))

	// Reset reader
	f.Seek(0, io.SeekStart)
	zp := dns.NewZoneParser(f, origin, zoneFile)

	z := &Zone{
		Name:    origin,
		records: make(map[string]map[uint16][]Record),
	}

	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if err := zp.Err(); err != nil {
			return err
		}
		name := dns.Fqdn(strings.ToLower(rr.Header().Name))
		// initialize map levels
		if _, ok := z.records[name]; !ok {
			z.records[name] = make(map[uint16][]Record)
		}

		p.mu.Lock()
		id := p.nextRecordID
		p.nextRecordID++
		p.mu.Unlock()

		z.records[name][rr.Header().Rrtype] = append(z.records[name][rr.Header().Rrtype], Record{ID: id, RR: rr})

		// collect soa and ns records separately
		switch v := rr.(type) {
		case *dns.SOA:
			z.soa = v
		case *dns.NS:
			z.nsRecords = append(z.nsRecords, v)
		}
	}

	// ensure deterministic ordering of zone names for future iteration — not strictly required
	// but helps testing and reproducibility
	// store zone
	p.mu.Lock()
	p.zones[origin] = z
	p.mu.Unlock()

	log.Printf("Loaded zone %s (%d owner names)", origin, len(z.records))
	return nil
}

// detectOrigin scans the beginning of a zone file for $ORIGIN; if not found, returns an error
func detectOrigin(r io.Reader) (string, error) {
	s := bufio.NewScanner(r)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if strings.HasPrefix(line, "$ORIGIN") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return parts[1], nil
			}
			return "", errors.New("malformed $ORIGIN line")
		}
		// skip comments and blank lines until we reach origin or records
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
	}
	if err := s.Err(); err != nil {
		return "", err
	}
	return "", errors.New("$ORIGIN not found in zone file")
}

// CRUD helpers — concurrency safe

func (p *AuthoritativePlugin) GetZoneNames() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	res := make([]string, 0, len(p.zones))
	for n := range p.zones {
		res = append(res, n)
	}
	sort.Strings(res)
	return res
}

func (p *AuthoritativePlugin) GetZoneRecords(zoneName string) ([]Record, error) {
	zn := dns.Fqdn(strings.ToLower(zoneName))
	p.mu.RLock()
	z, ok := p.zones[zn]
	p.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("zone not found: %s", zoneName)
	}

	z.mu.RLock()
	defer z.mu.RUnlock()
	var out []Record
	for _, typmap := range z.records {
		for _, arr := range typmap {
			out = append(out, arr...)
		}
	}
	return out, nil
}

func (p *AuthoritativePlugin) AddZone(zoneName string) error {
	zn := dns.Fqdn(strings.ToLower(zoneName))
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.zones[zn]; ok {
		return fmt.Errorf("zone already exists: %s", zoneName)
	}
	p.zones[zn] = &Zone{
		Name:    zn,
		records: make(map[string]map[uint16][]Record),
	}
	return nil
}

func (p *AuthoritativePlugin) DeleteZone(zoneName string) error {
	zn := dns.Fqdn(strings.ToLower(zoneName))
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.zones[zn]; !ok {
		return fmt.Errorf("zone not found: %s", zoneName)
	}
	delete(p.zones, zn)
	return nil
}

// AddZoneRecord inserts RR into an existing zone. RR owner name is used as key.
func (p *AuthoritativePlugin) AddZoneRecord(zoneName string, rr dns.RR) (int, error) {
	zn := dns.Fqdn(strings.ToLower(zoneName))
	p.mu.RLock()
	z, ok := p.zones[zn]
	p.mu.RUnlock()
	if !ok {
		return 0, fmt.Errorf("zone not found: %s", zoneName)
	}

	name := dns.Fqdn(strings.ToLower(rr.Header().Name))
	z.mu.Lock()
	defer z.mu.Unlock()
	if _, ok := z.records[name]; !ok {
		z.records[name] = make(map[uint16][]Record)
	}
	p.mu.Lock()
	id := p.nextRecordID
	p.nextRecordID++
	p.mu.Unlock()
	z.records[name][rr.Header().Rrtype] = append(z.records[name][rr.Header().Rrtype], Record{ID: id, RR: rr})
	// if NS or SOA update cached fields
	switch v := rr.(type) {
	case *dns.NS:
		z.nsRecords = append(z.nsRecords, v)
	case *dns.SOA:
		z.soa = v
	}
	return id, nil
}

func (p *AuthoritativePlugin) UpdateZoneRecord(zoneName string, recordId int, newRR dns.RR) error {
	zn := dns.Fqdn(strings.ToLower(zoneName))
	p.mu.RLock()
	z, ok := p.zones[zn]
	p.mu.RUnlock()
	if !ok {
		return fmt.Errorf("zone not found: %s", zoneName)
	}
	z.mu.Lock()
	defer z.mu.Unlock()
	for name, typmap := range z.records {
		for t, arr := range typmap {
			for i, r := range arr {
				if r.ID == recordId {
					z.records[name][t][i].RR = newRR
					// update special fields
					switch v := newRR.(type) {
					case *dns.NS:
						z.nsRecords = append(z.nsRecords, v)
					case *dns.SOA:
						z.soa = v
					}
					return nil
				}
			}
		}
	}
	return fmt.Errorf("record not found")
}

func (p *AuthoritativePlugin) DeleteZoneRecord(zoneName string, recordId int) error {
	zn := dns.Fqdn(strings.ToLower(zoneName))
	p.mu.RLock()
	z, ok := p.zones[zn]
	p.mu.RUnlock()
	if !ok {
		return fmt.Errorf("zone not found: %s", zoneName)
	}
	z.mu.Lock()
	defer z.mu.Unlock()
	for name, typmap := range z.records {
		for t, arr := range typmap {
			for i, r := range arr {
				if r.ID == recordId {
					z.records[name][t] = append(arr[:i], arr[i+1:]...)
					return nil
				}
			}
		}
	}
	return fmt.Errorf("record not found")
}
