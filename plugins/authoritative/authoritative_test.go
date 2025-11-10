package authoritative

import (
	"io"
	"io/ioutil"
	"net"
	"os"
	"sync"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"dns-resolver/internal/plugins"
)

// completeMockResponseWriter is a mock that implements the full dns.ResponseWriter interface
// to prevent panics in tests that use dns.Transfer.
type completeMockResponseWriter struct {
	conn        net.Conn
	writtenMsgs []*dns.Msg
}

func (m *completeMockResponseWriter) LocalAddr() net.Addr {
	if m.conn != nil {
		return m.conn.LocalAddr()
	}
	return &net.IPAddr{IP: net.ParseIP("127.0.0.1")}
}
func (m *completeMockResponseWriter) RemoteAddr() net.Addr {
	if m.conn != nil {
		return m.conn.RemoteAddr()
	}
	return &net.IPAddr{IP: net.ParseIP("127.0.0.1")}
}
func (m *completeMockResponseWriter) WriteMsg(msg *dns.Msg) error {
	m.writtenMsgs = append(m.writtenMsgs, msg)
	if m.conn != nil {
		out, err := msg.Pack()
		if err != nil {
			return err
		}
		// Write the 2-byte length prefix
		lenBuf := []byte{byte(len(out) >> 8), byte(len(out))}
		if _, err := m.conn.Write(lenBuf); err != nil {
			return err
		}
		// Write the actual message
		if _, err := m.conn.Write(out); err != nil {
			return err
		}
	}
	return nil
}
func (m *completeMockResponseWriter) Write(b []byte) (int, error) {
	// This is the raw write, used by dns.Transfer.Out.
	// For AXFR over TCP, each message is prefixed with its length.
	if m.conn != nil {
		lenBuf := []byte{byte(len(b) >> 8), byte(len(b))}
		if _, err := m.conn.Write(lenBuf); err != nil {
			return 0, err
		}
		return m.conn.Write(b)
	}
	return len(b), nil
}
func (m *completeMockResponseWriter) Close() error {
	if m.conn != nil {
		return m.conn.Close()
	}
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
	p1.AddZone("example.com.") // This now auto-creates a SOA record
	rr, _ := dns.NewRR("www.example.com. 300 IN A 1.2.3.4")
	p1.AddZoneRecord("example.com.", rr)

	// Create a second plugin instance and load from the same file
	p2 := New(tmpfile.Name())
	zones := p2.GetZoneNames()
	assert.Equal(t, 1, len(zones))
	assert.Equal(t, "example.com.", zones[0])

	records, err := p2.GetZoneRecords("example.com.")
	assert.NoError(t, err)
	assert.Equal(t, 2, len(records)) // Expect 2 records: the auto SOA and the manual A record

	// Find the A record to verify it's correct
	var foundA bool
	for _, r := range records {
		if a, ok := r.RR.(*dns.A); ok {
			assert.Equal(t, "www.example.com.\t300\tIN\tA\t1.2.3.4", a.String())
			foundA = true
		}
	}
	assert.True(t, foundA, "A record not found in persisted zone")
}

func TestAXFR(t *testing.T) {
	p := New("") // In-memory plugin, no persistence
	p.AddZone("example.com.")

	soaRR, err := dns.NewRR("example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2023010101 7200 3600 1209600 3600")
	assert.NoError(t, err)
	p.AddZoneRecord("example.com.", soaRR)
	aRR, err := dns.NewRR("www.example.com. 300 IN A 1.2.3.4")
	assert.NoError(t, err)
	p.AddZoneRecord("example.com.", aRR)
	mxRR, err := dns.NewRR("example.com. 600 IN MX 10 mail.example.com.")
	assert.NoError(t, err)
	p.AddZoneRecord("example.com.", mxRR)

	zone, ok := p.findZone("example.com.")
	assert.True(t, ok, "Failed to find the test zone")

	// Use net.Pipe to create an in-memory full-duplex network connection.
	clientConn, serverConn := net.Pipe()

	w := &completeMockResponseWriter{conn: serverConn}
	req := &dns.Msg{}
	req.SetQuestion("example.com.", dns.TypeAXFR)
	ctx := &plugins.PluginContext{ResponseWriter: w}

	var receivedRecords []dns.RR
	var wg sync.WaitGroup
	wg.Add(2)

	// Goroutine for the server side (our plugin)
	go func() {
		defer wg.Done()
		defer serverConn.Close()
		p.handleAXFR(ctx, req, zone)
	}()

	// Goroutine for the client side (our verification)
	go func() {
		defer wg.Done()
		defer clientConn.Close()

		for {
			lenBuf := make([]byte, 2)
			_, err := io.ReadFull(clientConn, lenBuf)
			if err == io.EOF {
				break // Connection closed by server
			}
			assert.NoError(t, err, "Client failed to read message length")

			msgLen := int(lenBuf[0])<<8 | int(lenBuf[1])
			msgBuf := make([]byte, msgLen)
			_, err = io.ReadFull(clientConn, msgBuf)
			assert.NoError(t, err, "Client failed to read message body")

			msg := &dns.Msg{}
			err = msg.Unpack(msgBuf)
			assert.NoError(t, err, "Client failed to unpack message")

			// For AXFR, each message contains records in the Answer section
			receivedRecords = append(receivedRecords, msg.Answer...)
		}
	}()

	wg.Wait()

	// --- Verification ---
	assert.Equal(t, 4, len(receivedRecords), "Expected 4 records in total (SOA, A, MX, SOA)")
	if len(receivedRecords) < 4 {
		t.FailNow()
	}

	_, isSOAFrist := receivedRecords[0].(*dns.SOA)
	assert.True(t, isSOAFrist, "The first record of an AXFR transfer must be a SOA record")

	_, isSOALast := receivedRecords[3].(*dns.SOA)
	assert.True(t, isSOALast, "The last record of an AXFR transfer must be a SOA record")

	var foundA, foundMX bool
	for _, rr := range receivedRecords[1:3] {
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

	// AddZone now adds a SOA, so we expect 3 records total.
	rr1, _ := dns.NewRR("www.example.com. 300 IN A 1.1.1.1")
	rr2, _ := dns.NewRR("mail.example.com. 300 IN A 2.2.2.2")
	id1, err := p.AddZoneRecord("example.com.", rr1)
	assert.NoError(t, err)
	_, err = p.AddZoneRecord("example.com.", rr2)
	assert.NoError(t, err)

	// Verify they are there
	records, err := p.GetZoneRecords("example.com.")
	assert.NoError(t, err)
	assert.Equal(t, 3, len(records), "Should have three records before update (SOA, A, A)")

	// Update the first record
	updatedRR, _ := dns.NewRR("www.example.com. 600 IN A 3.3.3.3")
	err = p.UpdateZoneRecord("example.com.", id1, updatedRR)
	assert.NoError(t, err)

	// Verify the update from a new instance (to check persistence)
	p2 := New(tmpfile.Name())
	recordsAfterUpdate, err := p2.GetZoneRecords("example.com.")
	assert.NoError(t, err)
	assert.Equal(t, 3, len(recordsAfterUpdate), "Should still have three records after update")

	// Check that the correct record was updated and the other was not
	var updatedFound, otherFound, soaFound bool
	for _, r := range recordsAfterUpdate {
		if r.ID == id1 {
			assert.Equal(t, "www.example.com.\t600\tIN\tA\t3.3.3.3", r.RR.String())
			updatedFound = true
		} else if _, ok := r.RR.(*dns.A); ok {
			assert.Equal(t, "mail.example.com.\t300\tIN\tA\t2.2.2.2", r.RR.String())
			otherFound = true
		} else if _, ok := r.RR.(*dns.SOA); ok {
			soaFound = true
		}
	}
	assert.True(t, updatedFound, "Updated record not found")
	assert.True(t, otherFound, "Unchanged record not found")
	assert.True(t, soaFound, "SOA record not found")
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
	for _, rec := range zone.nsRecords {
		if ns, ok := rec.RR.(*dns.NS); ok {
			if ns.Ns == "new-ns.example.com." {
				foundNew = true
			}
			if ns.Ns == "ns2.example.com." {
				foundOld = true
			}
		}
	}
	assert.True(t, foundNew, "New NS record not found")
	assert.True(t, foundOld, "Unchanged NS record not found")

	// Delete the other NS record
	p.DeleteZoneRecord("example.com.", id2)
	assert.Equal(t, 1, len(zone.nsRecords), "Should have one NS record after delete")
	assert.Equal(t, "new-ns.example.com.", zone.nsRecords[0].RR.(*dns.NS).Ns)
}

func TestCNAMEAliasResponse(t *testing.T) {
	p := New("") // In-memory
	p.AddZone("example.com.")
	p.AddZone("real.com.") // CNAME target zone
	cnameRR, err := dns.NewRR("www.example.com. 300 IN CNAME www.real.com.")
	assert.NoError(t, err)
	aRR, err := dns.NewRR("www.real.com. 300 IN A 1.2.3.4")
	assert.NoError(t, err)

	_, err = p.AddZoneRecord("example.com.", cnameRR)
	assert.NoError(t, err)
	// Add the A record to its correct zone
	_, err = p.AddZoneRecord("real.com.", aRR)
	assert.NoError(t, err)

	w := &completeMockResponseWriter{}
	req := &dns.Msg{}
	req.SetQuestion("www.example.com.", dns.TypeA)
	ctx := &plugins.PluginContext{ResponseWriter: w}

	// Execute the plugin logic
	err = p.Execute(ctx, req)
	assert.NoError(t, err)

	// --- Verification ---
	assert.True(t, ctx.Stop, "Handler should have stopped the chain")
	assert.Equal(t, 1, len(w.writtenMsgs), "Expected exactly one message to be written")
	res := w.writtenMsgs[0]

	assert.Equal(t, dns.RcodeSuccess, res.Rcode, "Rcode should be NOERROR")
	assert.Equal(t, 2, len(res.Answer), "Answer should contain CNAME and A record")

	if len(res.Answer) == 2 {
		cname, ok := res.Answer[0].(*dns.CNAME)
		assert.True(t, ok, "First record should be CNAME")
		assert.Equal(t, "www.example.com.", cname.Hdr.Name)
		assert.Equal(t, "www.real.com.", cname.Target)

		a, ok := res.Answer[1].(*dns.A)
		assert.True(t, ok, "Second record should be A")
		assert.Equal(t, "www.real.com.", a.Hdr.Name)
		assert.Equal(t, "1.2.3.4", a.A.String())
	}
}

func TestNSApexQuery(t *testing.T) {
	p := New("") // In-memory
	p.AddZone("example.com.")

	// Add NS records and their corresponding A records (glue)
	ns1RR, err := dns.NewRR("example.com. 3600 IN NS ns1.example.com.")
	assert.NoError(t, err)
	ns2RR, err := dns.NewRR("example.com. 3600 IN NS ns2.example.com.")
	assert.NoError(t, err)
	ns1aRR, err := dns.NewRR("ns1.example.com. 3600 IN A 1.1.1.1")
	assert.NoError(t, err)
	ns2aRR, err := dns.NewRR("ns2.example.com. 3600 IN A 2.2.2.2")
	assert.NoError(t, err)

	_, err = p.AddZoneRecord("example.com.", ns1RR)
	assert.NoError(t, err)
	_, err = p.AddZoneRecord("example.com.", ns2RR)
	assert.NoError(t, err)
	_, err = p.AddZoneRecord("example.com.", ns1aRR)
	assert.NoError(t, err)
	_, err = p.AddZoneRecord("example.com.", ns2aRR)
	assert.NoError(t, err)

	w := &completeMockResponseWriter{}
	req := &dns.Msg{}
	req.SetQuestion("example.com.", dns.TypeNS)
	ctx := &plugins.PluginContext{ResponseWriter: w}

	// Execute the plugin logic
	err = p.Execute(ctx, req)
	assert.NoError(t, err)

	// --- Verification ---
	assert.True(t, ctx.Stop, "Handler should have stopped the chain")
	assert.Equal(t, 1, len(w.writtenMsgs), "Expected exactly one message to be written")
	res := w.writtenMsgs[0]

	assert.Equal(t, dns.RcodeSuccess, res.Rcode, "Rcode should be NOERROR")
	assert.Equal(t, 2, len(res.Answer), "Answer section should contain 2 NS records")
	assert.Equal(t, 2, len(res.Ns), "Authority section should contain 2 NS records")
	assert.Equal(t, 2, len(res.Extra), "Extra section should contain 2 glue A records")

	// Check Answer section
	var ns1Found, ns2Found bool
	for _, rr := range res.Answer {
		if ns, ok := rr.(*dns.NS); ok {
			if ns.Ns == "ns1.example.com." {
				ns1Found = true
			}
			if ns.Ns == "ns2.example.com." {
				ns2Found = true
			}
		}
	}
	assert.True(t, ns1Found, "ns1.example.com. not found in Answer section")
	assert.True(t, ns2Found, "ns2.example.com. not found in Answer section")

	// Check Extra section
	var a1Found, a2Found bool
	for _, rr := range res.Extra {
		if a, ok := rr.(*dns.A); ok {
			if a.Hdr.Name == "ns1.example.com." && a.A.Equal(net.ParseIP("1.1.1.1")) {
				a1Found = true
			}
			if a.Hdr.Name == "ns2.example.com." && a.A.Equal(net.ParseIP("2.2.2.2")) {
				a2Found = true
			}
		}
	}
	assert.True(t, a1Found, "Glue record for ns1.example.com. not found in Extra section")
	assert.True(t, a2Found, "Glue record for ns2.example.com. not found in Extra section")
}

func TestAddMultipleNSRecords(t *testing.T) {
	p := New("") // In-memory
	p.AddZone("example.com.")

	// Add four NS records
	ns1RR, err := dns.NewRR("example.com. 3600 IN NS ns1.example.com.")
	assert.NoError(t, err)
	ns2RR, err := dns.NewRR("example.com. 3600 IN NS ns2.example.com.")
	assert.NoError(t, err)
	ns3RR, err := dns.NewRR("example.com. 3600 IN NS ns3.example.com.")
	assert.NoError(t, err)
	ns4RR, err := dns.NewRR("example.com. 3600 IN NS ns4.example.com.")
	assert.NoError(t, err)

	_, err = p.AddZoneRecord("example.com.", ns1RR)
	assert.NoError(t, err)
	_, err = p.AddZoneRecord("example.com.", ns2RR)
	assert.NoError(t, err)
	_, err = p.AddZoneRecord("example.com.", ns3RR)
	assert.NoError(t, err)
	_, err = p.AddZoneRecord("example.com.", ns4RR)
	assert.NoError(t, err)

	// Verification
	zone, ok := p.findZone("example.com.")
	assert.True(t, ok, "Failed to find the test zone")
	assert.Equal(t, 4, len(zone.nsRecords), "Should have four NS records")

	// Check that all records are there
	var found [4]bool
	for _, rec := range zone.nsRecords {
		if ns, ok := rec.RR.(*dns.NS); ok {
			switch ns.Ns {
			case "ns1.example.com.":
				found[0] = true
			case "ns2.example.com.":
				found[1] = true
			case "ns3.example.com.":
				found[2] = true
			case "ns4.example.com.":
				found[3] = true
			}
		}
	}
	assert.True(t, found[0], "ns1.example.com. not found")
	assert.True(t, found[1], "ns2.example.com. not found")
	assert.True(t, found[2], "ns3.example.com. not found")
	assert.True(t, found[3], "ns4.example.com. not found")
}

func TestMXRecordResponse(t *testing.T) {
	p := New("") // In-memory
	p.AddZone("example.com.")
	mxRR, err := dns.NewRR("example.com. 300 IN MX 10 mail.example.com.")
	assert.NoError(t, err)
	aRR, err := dns.NewRR("mail.example.com. 300 IN A 1.2.3.4")
	assert.NoError(t, err)

	_, err = p.AddZoneRecord("example.com.", mxRR)
	assert.NoError(t, err)
	_, err = p.AddZoneRecord("example.com.", aRR)
	assert.NoError(t, err)

	w := &completeMockResponseWriter{}
	req := &dns.Msg{}
	req.SetQuestion("example.com.", dns.TypeMX)
	ctx := &plugins.PluginContext{ResponseWriter: w}

	// Execute the plugin logic
	err = p.Execute(ctx, req)
	assert.NoError(t, err)

	// --- Verification ---
	assert.True(t, ctx.Stop, "Handler should have stopped the chain")
	assert.Equal(t, 1, len(w.writtenMsgs), "Expected exactly one message to be written")
	res := w.writtenMsgs[0]

	assert.Equal(t, dns.RcodeSuccess, res.Rcode, "Rcode should be NOERROR")
	assert.Equal(t, 1, len(res.Answer), "Answer section should contain 1 record (the MX record)")
	assert.Equal(t, 1, len(res.Extra), "Extra section should contain 1 record (the A record for the mail server)")

	if len(res.Answer) == 1 && len(res.Extra) == 1 {
		mx, ok := res.Answer[0].(*dns.MX)
		assert.True(t, ok, "The returned record should be an MX")
		assert.Equal(t, "example.com.", mx.Hdr.Name)
		assert.Equal(t, "mail.example.com.", mx.Mx)

		a, ok := res.Extra[0].(*dns.A)
		assert.True(t, ok, "The extra record should be an A")
		assert.Equal(t, "mail.example.com.", a.Hdr.Name)
		assert.Equal(t, "1.2.3.4", a.A.String())
	}
}
