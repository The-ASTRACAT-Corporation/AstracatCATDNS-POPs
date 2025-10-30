package authoritative

import (
	"io/ioutil"
	"net"
	"os"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"dns-resolver/internal/plugins"
)

// completeMockResponseWriter is a mock that implements the full dns.ResponseWriter interface
// to prevent panics in tests that use dns.Transfer.
type completeMockResponseWriter struct {
	writtenMsgs []*dns.Msg
}

func (m *completeMockResponseWriter) LocalAddr() net.Addr {
	return &net.IPAddr{IP: net.ParseIP("127.0.0.1")}
}
func (m *completeMockResponseWriter) RemoteAddr() net.Addr {
	return &net.IPAddr{IP: net.ParseIP("127.0.0.1")}
}
func (m *completeMockResponseWriter) WriteMsg(msg *dns.Msg) error {
	m.writtenMsgs = append(m.writtenMsgs, msg)
	return nil
}
func (m *completeMockResponseWriter) Write(b []byte) (int, error) {
	// This is typically called by dns.Transfer for the raw message bytes.
	// We don't need to parse it back, as WriteMsg will be called with the structured data.
	return len(b), nil
}
func (m *completeMockResponseWriter) Close() error {
	return nil
}
func (m *completeMockResponseWriter) TsigStatus() error {
	return nil
}
func (m *completeMockResponseWriter) TsigTimersOnly(b bool) {}
func (m *completeMockResponseWriter) Hijack()               {}

func TestPersistence(t *testing.T) {
	tmpfile, err := ioutil.TempFile("", "test-zones.json")
	assert.NoError(t, err)
	defer os.Remove(tmpfile.Name())

	// Create a new plugin instance and add some data
	p1 := New(tmpfile.Name())
	p1.AddZone("example.com.")
	rr, _ := dns.NewRR("www.example.com. 300 IN A 1.2.3.4")
	p1.AddZoneRecord("example.com.", rr)

	// Create a second plugin instance and load from the same file
	p2 := New(tmpfile.Name())
	zones := p2.GetZoneNames()
	assert.Equal(t, 1, len(zones))
	assert.Equal(t, "example.com.", zones[0])

	records, err := p2.GetZoneRecords("example.com.")
	assert.NoError(t, err)
	assert.Equal(t, 1, len(records))
	assert.Equal(t, "www.example.com.\t300\tIN\tA\t1.2.3.4", records[0].RR.String())
}

func TestAXFR(t *testing.T) {
	p := New("") // In-memory plugin, no persistence
	p.AddZone("example.com.")

	// AXFR requires a SOA record to define the zone's properties.
	soaRR, err := dns.NewRR("example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2023010101 7200 3600 1209600 3600")
	assert.NoError(t, err)
	_, err = p.AddZoneRecord("example.com.", soaRR)
	assert.NoError(t, err)

	// Add a few other records to ensure they are transferred.
	aRR, err := dns.NewRR("www.example.com. 300 IN A 1.2.3.4")
	assert.NoError(t, err)
	_, err = p.AddZoneRecord("example.com.", aRR)
	assert.NoError(t, err)

	mxRR, err := dns.NewRR("example.com. 600 IN MX 10 mail.example.com.")
	assert.NoError(t, err)
	_, err = p.AddZoneRecord("example.com.", mxRR)
	assert.NoError(t, err)

	zone, ok := p.findZone("example.com.")
	assert.True(t, ok, "Failed to find the test zone")

	// Setup for handling the AXFR request.
	w := &completeMockResponseWriter{}
	req := &dns.Msg{}
	req.SetQuestion("example.com.", dns.TypeAXFR)
	ctx := &plugins.PluginContext{ResponseWriter: w}

	// Execute the handler.
	// We need to run this in a goroutine because the Out() call is blocking,
	// and the test needs to proceed to check the results.
	go p.handleAXFR(ctx, req, zone)

	// Allow some time for the goroutine to execute.
	// This is a common pattern in testing concurrent code.
	time.Sleep(100 * time.Millisecond)


	// --- Verification ---
	var allRecords []dns.RR
	for _, msg := range w.writtenMsgs {
		allRecords = append(allRecords, msg.Answer...)
	}

	assert.GreaterOrEqual(t, len(allRecords), 3, "Expected at least 3 records for a minimal AXFR")

	_, isSOAFrist := allRecords[0].(*dns.SOA)
	assert.True(t, isSOAFrist, "The first record of an AXFR transfer must be a SOA record")

	_, isSOALast := allRecords[len(allRecords)-1].(*dns.SOA)
	assert.True(t, isSOALast, "The last record of an AXFR transfer must be a SOA record")

	var foundA, foundMX bool
	for _, rr := range allRecords[1 : len(allRecords)-1] {
		switch rr.Header().Rrtype {
		case dns.TypeA:
			foundA = true
		case dns.TypeMX:
			foundMX = true
		}
	}
	assert.True(t, foundA, "The A record was not found in the AXFR transfer")
	assert.True(t, foundMX, "The MX record was not found in the AXFR transfer")
}

func TestUpdateRecord(t *testing.T) {
	tmpfile, err := ioutil.TempFile("", "test-zones-update.json")
	assert.NoError(t, err)
	defer os.Remove(tmpfile.Name())

	p := New(tmpfile.Name())
	p.AddZone("example.com.")

	// Add two records
	rr1, _ := dns.NewRR("www.example.com. 300 IN A 1.1.1.1")
	rr2, _ := dns.NewRR("mail.example.com. 300 IN A 2.2.2.2")
	id1, err := p.AddZoneRecord("example.com.", rr1)
	assert.NoError(t, err)
	_, err = p.AddZoneRecord("example.com.", rr2)
	assert.NoError(t, err)

	// Verify they are there
	records, err := p.GetZoneRecords("example.com.")
	assert.NoError(t, err)
	assert.Equal(t, 2, len(records), "Should have two records before update")

	// Update the first record
	updatedRR, _ := dns.NewRR("www.example.com. 600 IN A 3.3.3.3")
	err = p.UpdateZoneRecord("example.com.", id1, updatedRR)
	assert.NoError(t, err)

	// Verify the update from a new instance (to check persistence)
	p2 := New(tmpfile.Name())
	recordsAfterUpdate, err := p2.GetZoneRecords("example.com.")
	assert.NoError(t, err)
	assert.Equal(t, 2, len(recordsAfterUpdate), "Should still have two records after update")

	// Check that the correct record was updated and the other was not
	var updatedFound, otherFound bool
	for _, r := range recordsAfterUpdate {
		if r.ID == id1 {
			assert.Equal(t, "www.example.com.\t600\tIN\tA\t3.3.3.3", r.RR.String())
			updatedFound = true
		} else {
			assert.Equal(t, "mail.example.com.\t300\tIN\tA\t2.2.2.2", r.RR.String())
			otherFound = true
		}
	}
	assert.True(t, updatedFound, "Updated record not found")
	assert.True(t, otherFound, "Unchanged record not found")
}

func TestUpdateNSRecord(t *testing.T) {
	p := New("") // No file needed for this test

	p.AddZone("example.com.")

	// Add two NS records
	ns1, _ := dns.NewRR("example.com. 3600 IN NS ns1.example.com.")
	ns2, _ := dns.NewRR("example.com. 3600 IN NS ns2.example.com.")
	id1, _ := p.AddZoneRecord("example.com.", ns1)
	id2, _ := p.AddZoneRecord("example.com.", ns2)

	zone, _ := p.findZone("example.com.")
	assert.Equal(t, 2, len(zone.nsRecords), "Should have two NS records")

	// Update one NS record
	newNS, _ := dns.NewRR("example.com. 3600 IN NS new-ns.example.com.")
	p.UpdateZoneRecord("example.com.", id1, newNS)

	assert.Equal(t, 2, len(zone.nsRecords), "Should still have two NS records after update")
	var foundNew, foundOld bool
	for _, ns := range zone.nsRecords {
		if ns.(*dns.NS).Ns == "new-ns.example.com." {
			foundNew = true
		}
		if ns.(*dns.NS).Ns == "ns2.example.com." {
			foundOld = true
		}
	}
	assert.True(t, foundNew, "New NS record not found")
	assert.True(t, foundOld, "Unchanged NS record not found")

	// Delete the other NS record
	p.DeleteZoneRecord("example.com.", id2)
	assert.Equal(t, 1, len(zone.nsRecords), "Should have one NS record after delete")
	assert.Equal(t, "new-ns.example.com.", zone.nsRecords[0].(*dns.NS).Ns)
}
