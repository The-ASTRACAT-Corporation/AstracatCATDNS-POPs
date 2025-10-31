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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"dns-resolver/internal/plugins"
	"github.com/miekg/dns"
)

// Record wraps a dns.RR with an internal ID and keeps original TTL
type Record struct {
	ID int
	RR dns.RR
}

// RecordDTO is a serializable representation of a Record
type RecordDTO struct {
	ID   int    `json:"id"`
	Data string `json:"data"`
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

// ZoneDTO is a serializable representation of a Zone
type ZoneDTO struct {
	Name    string      `json:"name"`
	Records []RecordDTO `json:"records"`
}

// AuthoritativePlugin is thread-safe and intended for production use
type AuthoritativePlugin struct {
	zones        map[string]*Zone // key: FQDN zone name
	nextRecordID int
	mu           sync.RWMutex // protects zones map and nextRecordID
	filePath     string
	fileMu       sync.Mutex
}

func New(filePath string) *AuthoritativePlugin {
	p := &AuthoritativePlugin{
		zones:        make(map[string]*Zone),
		nextRecordID: 1,
		filePath:     filePath,
	}
	if err := p.loadFromFile(); err != nil {
		log.Printf("Could not load zones from file: %v", err)
	}
	return p
}

func (p *AuthoritativePlugin) saveToFile(zoneDTOs []ZoneDTO) error {
	if p.filePath == "" {
		return nil // No persistence for in-memory tests
	}
	log.Println("Attempting to save zones to file:", p.filePath)
	p.fileMu.Lock()
	defer p.fileMu.Unlock()

	data, err := json.MarshalIndent(zoneDTOs, "", "  ")
	if err != nil {
		log.Printf("Error marshalling zones to JSON: %v", err)
		return err
	}

	if err := os.WriteFile(p.filePath, data, 0644); err != nil {
		log.Printf("Error writing zones to file %s: %v", p.filePath, err)
		return err
	}
	log.Println("Zones successfully saved to file:", p.filePath)
	return nil
}

func (p *AuthoritativePlugin) loadFromFile() error {
	log.Println("Attempting to load zones from file:", p.filePath)
	p.fileMu.Lock()
	defer p.fileMu.Unlock()

	p.mu.Lock()
	defer p.mu.Unlock()

	data, err := os.ReadFile(p.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Println("Zone file does not exist, starting with empty zones.")
			return nil // File doesn't exist yet, which is fine
		}
		log.Printf("Error reading zone file %s: %v", p.filePath, err)
		return err
	}

	var zoneDTOs []ZoneDTO
	if err := json.Unmarshal(data, &zoneDTOs); err != nil {
		log.Printf("Error unmarshalling zones from JSON: %v", err)
		return err
	}

	p.zones = make(map[string]*Zone)
	maxID := 0
	for _, zd := range zoneDTOs {
		z := &Zone{
			Name:    zd.Name,
			records: make(map[string]map[uint16][]Record),
		}
		for _, rd := range zd.Records {
			rr, err := dns.NewRR(rd.Data)
			if err != nil {
				log.Printf("Error parsing record from file: %v", err)
				continue
			}
			name := dns.Fqdn(strings.ToLower(rr.Header().Name))
			if _, ok := z.records[name]; !ok {
				z.records[name] = make(map[uint16][]Record)
			}
			z.records[name][rr.Header().Rrtype] = append(z.records[name][rr.Header().Rrtype], Record{ID: rd.ID, RR: rr})
			if rd.ID > maxID {
				maxID = rd.ID
			}

			// collect soa and ns records separately
			switch v := rr.(type) {
			case *dns.SOA:
				z.soa = v
			case *dns.NS:
				z.nsRecords = append(z.nsRecords, v)
			}
		}
		p.zones[z.Name] = z
	}
	p.nextRecordID = maxID + 1
	log.Println("Zones successfully loaded from file:", p.filePath)
	return nil
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

	if q.Qtype == dns.TypeAXFR {
		p.handleAXFR(ctx, msg, zone)
		ctx.Stop = true
		return nil
	}

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
		} else {
			// If no direct match, check for CNAME and follow it.
			if cnameRecs, ok := recordsForName[dns.TypeCNAME]; ok && len(cnameRecs) > 0 {
				cnameRR := cnameRecs[0].RR
				res.Answer = append(res.Answer, cnameRR)

				if cname, isCNAME := cnameRR.(*dns.CNAME); isCNAME {
					// Follow CNAME within authoritative zones
					p.followCname(res, q, cname.Target, 0)
				}
			}
		}
		zone.mu.RUnlock()

		if len(res.Answer) > 0 {
			// Successful answer. Add NS records to authority and glue to additional
			p.addAuthorityAndGlue(res, zone)
			// Add extra records (e.g., A/AAAA for MX)
			p.addExtraRecords(res, zone)
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

const maxCnameFollows = 5

func (p *AuthoritativePlugin) followCname(res *dns.Msg, q dns.Question, name string, depth int) {
	if depth > maxCnameFollows {
		return // Protection against CNAME loops
	}

	targetZone, ok := p.findZone(name)
	if !ok {
		return // Target is not in an authoritative zone for this server
	}

	targetName := dns.Fqdn(strings.ToLower(name))
	targetZone.mu.RLock()
	defer targetZone.mu.RUnlock()

	recordsForTarget, nameExists := targetZone.records[targetName]
	if !nameExists {
		return
	}

	// Check for the originally requested type.
	if recs, ok := recordsForTarget[q.Qtype]; ok {
		for _, r := range recs {
			res.Answer = append(res.Answer, r.RR)
		}
		return // Found the final answer
	}

	// If the direct type is not found, check if the target is another CNAME.
	if cnameRecs, ok := recordsForTarget[dns.TypeCNAME]; ok && len(cnameRecs) > 0 {
		cnameRR := cnameRecs[0].RR
		res.Answer = append(res.Answer, cnameRR)
		if cname, isCNAME := cnameRR.(*dns.CNAME); isCNAME {
			p.followCname(res, q, cname.Target, depth+1)
		}
	}
}

// handleAXFR handles zone transfers. The implementation is now corrected to stream
// records one by one, which is the proper way to handle AXFR and avoids timeouts
// with large zones. It also creates deep copies of records under a read lock
// to prevent race conditions.
func (p *AuthoritativePlugin) handleAXFR(ctx *plugins.PluginContext, msg *dns.Msg, zone *Zone) {
	log.Println("Starting AXFR for zone:", zone.Name)
	tr := new(dns.Transfer)
	ch := make(chan *dns.Envelope)

	go func() {
		defer close(ch)
		zone.mu.RLock()
		defer zone.mu.RUnlock()

		var soa dns.RR
		var records []dns.RR

		// Find SOA and collect all other records
		for _, typeMap := range zone.records {
			for _, recordSlice := range typeMap {
				for _, rec := range recordSlice {
					// Deep copy each record to avoid race conditions
					rrCopy := dns.Copy(rec.RR)
					if rrCopy.Header().Rrtype == dns.TypeSOA {
						soa = rrCopy
					} else {
						records = append(records, rrCopy)
					}
				}
			}
		}

		if soa == nil {
			log.Printf("AXFR failed: SOA record not found for zone %s", zone.Name)
			return
		}

		// Sorting is not strictly required by RFC, but it's good practice
		// for consistency.
		sort.Slice(records, func(i, j int) bool {
			return records[i].Header().Name < records[j].Header().Name
		})

		// The AXFR protocol starts with the SOA record.
		ch <- &dns.Envelope{RR: []dns.RR{soa}}

		// Then, it sends all other records in the zone.
		// We send them one by one to stream the response.
		for _, r := range records {
			ch <- &dns.Envelope{RR: []dns.RR{r}}
		}

		// The AXFR protocol ends with the same SOA record.
		ch <- &dns.Envelope{RR: []dns.RR{soa}}
	}()

	if err := tr.Out(ctx.ResponseWriter, msg, ch); err != nil {
		log.Printf("AXFR transfer failed for zone %s: %v", zone.Name, err)
	}
	log.Println("AXFR handler finished for zone:", zone.Name)
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

// addExtraRecords adds A/AAAA records for MX and SRV records to the Extra section.
func (p *AuthoritativePlugin) addExtraRecords(res *dns.Msg, z *Zone) {
	z.mu.RLock()
	defer z.mu.RUnlock()

	for _, rr := range res.Answer {
		var target string
		if mx, ok := rr.(*dns.MX); ok {
			target = mx.Mx
		} else if srv, ok := rr.(*dns.SRV); ok {
			target = srv.Target
		}

		if target != "" {
			owner := dns.Fqdn(strings.ToLower(target))
			if recs, found := z.records[owner]; found {
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
	err = p.saveToFile(p.GetZoneDTOs())
	return err
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

// GetZoneDTOs creates a deep copy of the zones for safe serialization
func (p *AuthoritativePlugin) GetZoneDTOs() []ZoneDTO {
	p.mu.RLock()
	defer p.mu.RUnlock()

	zoneDTOs := make([]ZoneDTO, 0, len(p.zones))
	for _, zone := range p.zones {
		var recordDTOs []RecordDTO
		zone.mu.RLock()
		for _, typeMap := range zone.records {
			for _, records := range typeMap {
				for _, record := range records {
					recordDTOs = append(recordDTOs, RecordDTO{
						ID:   record.ID,
						Data: record.RR.String(),
					})
				}
			}
		}
		zone.mu.RUnlock()
		zoneDTOs = append(zoneDTOs, ZoneDTO{
			Name:    zone.Name,
			Records: recordDTOs,
		})
	}
	return zoneDTOs
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

	// Generate a default SOA record
	serial := uint32(time.Now().Unix())
	soaStr := fmt.Sprintf("%s 3600 IN SOA ns1.%s hostmaster.%s %d 7200 3600 1209600 3600", zn, zn, zn, serial)
	soaRR, err := dns.NewRR(soaStr)
	if err != nil {
		// This should not fail with the static format
		return fmt.Errorf("failed to create default SOA record: %w", err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if _, ok := p.zones[zn]; ok {
		return fmt.Errorf("zone already exists: %s", zoneName)
	}

	z := &Zone{
		Name:    zn,
		records: make(map[string]map[uint16][]Record),
	}

	// Add the SOA record to the new zone
	id := p.nextRecordID
	p.nextRecordID++
	name := dns.Fqdn(strings.ToLower(soaRR.Header().Name))
	if _, ok := z.records[name]; !ok {
		z.records[name] = make(map[uint16][]Record)
	}
	z.records[name][soaRR.Header().Rrtype] = append(z.records[name][soaRR.Header().Rrtype], Record{ID: id, RR: soaRR})
	z.soa = soaRR

	p.zones[zn] = z

	// Release lock before saving to file
	p.mu.Unlock()
	err = p.saveToFile(p.GetZoneDTOs())
	p.mu.Lock() // Re-acquire lock for the defer to work correctly

	return err
}

func (p *AuthoritativePlugin) DeleteZone(zoneName string) error {
	zn := dns.Fqdn(strings.ToLower(zoneName))
	p.mu.Lock()
	if _, ok := p.zones[zn]; !ok {
		p.mu.Unlock()
		return fmt.Errorf("zone not found: %s", zoneName)
	}
	delete(p.zones, zn)
	p.mu.Unlock()
	err := p.saveToFile(p.GetZoneDTOs())
	return err
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
	z.mu.Unlock()

	err := p.saveToFile(p.GetZoneDTOs())
	if err != nil {
		return 0, fmt.Errorf("failed to save zone to file: %w", err)
	}
	return id, nil
}

func (p *AuthoritativePlugin) UpdateZoneRecord(zoneName string, recordId int, newRR dns.RR) error {
	zn := dns.Fqdn(strings.ToLower(zoneName))
	var recordUpdated bool
	p.mu.RLock()
	z, ok := p.zones[zn]
	p.mu.RUnlock()
	if !ok {
		return fmt.Errorf("zone not found: %s", zoneName)
	}
	z.mu.Lock()
	for name, typmap := range z.records {
		for t, arr := range typmap {
			for i, r := range arr {
				if r.ID == recordId {
					oldRR := z.records[name][t][i].RR
					z.records[name][t][i].RR = newRR
					recordUpdated = true
					// update special fields
					switch v := newRR.(type) {
					case *dns.NS:
						// remove old ns record
						if oldNS, ok := oldRR.(*dns.NS); ok {
							for j, ns := range z.nsRecords {
								if ns.(*dns.NS).Ns == oldNS.Ns {
									z.nsRecords = append(z.nsRecords[:j], z.nsRecords[j+1:]...)
									break
								}
							}
						}
						z.nsRecords = append(z.nsRecords, v)
					case *dns.SOA:
						z.soa = v
					}
					break // break inner loop
				}
			}
			if recordUpdated {
				break // break middle loop
			}
		}
		if recordUpdated {
			break // break outer loop
		}
	}
	z.mu.Unlock()

	if !recordUpdated {
		return fmt.Errorf("record not found")
	}

	err := p.saveToFile(p.GetZoneDTOs())
	return err
}

func (p *AuthoritativePlugin) DeleteZoneRecord(zoneName string, recordId int) error {
	zn := dns.Fqdn(strings.ToLower(zoneName))
	var recordDeleted bool
	p.mu.RLock()
	z, ok := p.zones[zn]
	p.mu.RUnlock()
	if !ok {
		return fmt.Errorf("zone not found: %s", zoneName)
	}
	z.mu.Lock()
	for name, typmap := range z.records {
		for t, arr := range typmap {
			for i, r := range arr {
				if r.ID == recordId {
					// If it's an NS record, remove it from the special slice too
					if nsRecord, ok := r.RR.(*dns.NS); ok {
						for j, ns := range z.nsRecords {
							if ns.(*dns.NS).Ns == nsRecord.Ns {
								z.nsRecords = append(z.nsRecords[:j], z.nsRecords[j+1:]...)
								break
							}
						}
					}
					z.records[name][t] = append(arr[:i], arr[i+1:]...)
					recordDeleted = true
					break // break inner loop
				}
			}
			if recordDeleted {
				break // break middle loop
			}
		}
		if recordDeleted {
			break // break outer loop
		}
	}
	z.mu.Unlock()

	if !recordDeleted {
		return fmt.Errorf("record not found")
	}

	err := p.saveToFile(p.GetZoneDTOs())
	return err
}

func (p *AuthoritativePlugin) UpdateZone(oldZoneName, newZoneName string) error {
	oldZn := dns.Fqdn(strings.ToLower(oldZoneName))
	newZn := dns.Fqdn(strings.ToLower(newZoneName))

	p.mu.Lock()

	z, ok := p.zones[oldZn]
	if !ok {
		p.mu.Unlock()
		return fmt.Errorf("zone not found: %s", oldZoneName)
	}

	// Check if the new zone name already exists
	if _, ok := p.zones[newZn]; ok {
		p.mu.Unlock()
		return fmt.Errorf("zone with new name already exists: %s", newZoneName)
	}

	// Update the zone name
	z.Name = newZn
	p.zones[newZn] = z
	delete(p.zones, oldZn)

	// Update SOA and NS records to reflect the new zone name
	if z.soa != nil {
		if soa, ok := z.soa.(*dns.SOA); ok {
			soa.Hdr.Name = newZn
		}
	}
	for i := range z.nsRecords {
		if ns, ok := z.nsRecords[i].(*dns.NS); ok {
			ns.Hdr.Name = newZn
		}
	}
	p.mu.Unlock()

	// Update all records within the zone to reflect the new zone name
	// This is a more complex operation as it requires iterating through all records
	// and potentially modifying their headers if they are relative to the zone origin.
	// For simplicity, we'll assume records are stored with their full FQDN and only update the zone's internal name.
	// A more robust solution might involve re-parsing or re-creating records.

	err := p.saveToFile(p.GetZoneDTOs())
	if err != nil {
		return fmt.Errorf("failed to save zone to file after update: %w", err)
	}
	return nil
}


func (p *AuthoritativePlugin) ReplaceAllZones(zoneDTOs []ZoneDTO) error {
	log.Println("Replacing all zones...")
	newZones := make(map[string]*Zone)
	maxID := 0
	for _, zd := range zoneDTOs {
		z := &Zone{
			Name:    zd.Name,
			records: make(map[string]map[uint16][]Record),
		}
		for _, rd := range zd.Records {
			rr, err := dns.NewRR(rd.Data)
			if err != nil {
				log.Printf("Error parsing record from file: %v", err)
				continue
			}
			name := dns.Fqdn(strings.ToLower(rr.Header().Name))
			if _, ok := z.records[name]; !ok {
				z.records[name] = make(map[uint16][]Record)
			}
			z.records[name][rr.Header().Rrtype] = append(z.records[name][rr.Header().Rrtype], Record{ID: rd.ID, RR: rr})
			if rd.ID > maxID {
				maxID = rd.ID
			}
			switch v := rr.(type) {
			case *dns.SOA:
				z.soa = v
			case *dns.NS:
				z.nsRecords = append(z.nsRecords, v)
			}
		}
		newZones[z.Name] = z
	}

	p.mu.Lock()
	p.zones = newZones
	p.nextRecordID = maxID + 1
	p.mu.Unlock()

	log.Println("Zones successfully replaced")
	err := p.saveToFile(p.GetZoneDTOs())
	return err
}

func (p *AuthoritativePlugin) NotifyZoneSlaves(zoneName string) error {
	zn := dns.Fqdn(strings.ToLower(zoneName))
	p.mu.RLock()
	zone, ok := p.zones[zn]
	p.mu.RUnlock()
	if !ok {
		return fmt.Errorf("zone not found: %s", zoneName)
	}

	zone.mu.RLock()
	soa, haveSOA := zone.soa.(*dns.SOA)
	nsRecords := make([]*dns.NS, 0, len(zone.nsRecords))
	for _, rr := range zone.nsRecords {
		if ns, ok := rr.(*dns.NS); ok {
			nsRecords = append(nsRecords, ns)
		}
	}
	zone.mu.RUnlock()

	if !haveSOA {
		return fmt.Errorf("SOA record not found for zone %s, cannot determine master server", zoneName)
	}

	masterName := soa.Ns
	var slaves []string

	for _, ns := range nsRecords {
		// A nameserver is considered a slave if its name is not the same as the MNAME field of the SOA.
		if !strings.EqualFold(ns.Ns, masterName) {
			slaves = append(slaves, ns.Ns)
		}
	}

	if len(slaves) == 0 {
		log.Printf("No slave servers found for zone %s to notify.", zoneName)
		return nil
	}

	m := new(dns.Msg)
	m.SetNotify(zone.Name)
	client := new(dns.Client)

	log.Printf("Preparing to send NOTIFY for zone %s to slaves: %v", zone.Name, slaves)

	for _, slaveHost := range slaves {
		// Attempt to find glue records within the zone first.
		var addrs []string
		zone.mu.RLock()
		if recs, found := zone.records[dns.Fqdn(slaveHost)]; found {
			if aRecs, ok := recs[dns.TypeA]; ok {
				for _, r := range aRecs {
					if a, isA := r.RR.(*dns.A); isA {
						addrs = append(addrs, a.A.String())
					}
				}
			}
			if aaaaRecs, ok := recs[dns.TypeAAAA]; ok {
				for _, r := range aaaaRecs {
					if aaaa, isAAAA := r.RR.(*dns.AAAA); isAAAA {
						addrs = append(addrs, aaaa.AAAA.String())
					}
				}
			}
		}
		zone.mu.RUnlock()

		// If no in-zone glue is found, use the system's resolver.
		if len(addrs) == 0 {
			ips, err := net.LookupIP(slaveHost)
			if err != nil {
				log.Printf("Error resolving IP for slave %s: %v", slaveHost, err)
				continue
			}
			for _, ip := range ips {
				addrs = append(addrs, ip.String())
			}
		}

		for _, addr := range addrs {
			log.Printf("Sending NOTIFY for zone %s to slave %s at %s", zone.Name, slaveHost, addr)
			_, _, err := client.Exchange(m, net.JoinHostPort(addr, "53"))
			if err != nil {
				log.Printf("Failed to send NOTIFY to %s (%s): %v", slaveHost, addr, err)
			}
		}
	}

	return nil
}
