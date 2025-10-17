package query_coalescer

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"dns-resolver/internal/plugins"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

// mockResponseWriter - это фиктивный ResponseWriter для тестов.
type mockResponseWriter struct {
	dns.ResponseWriter
	writtenMsg *dns.Msg
	mu         sync.Mutex
	failed     bool
}

func (m *mockResponseWriter) WriteMsg(msg *dns.Msg) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.writtenMsg = msg
	return nil
}

func (m *mockResponseWriter) msg() *dns.Msg {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.writtenMsg
}

func (m *mockResponseWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}
}

func (m *mockResponseWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
}

func (m *mockResponseWriter) Write(b []byte) (int, error) {
	// Not needed for these tests
	return len(b), nil
}

func (m *mockResponseWriter) Hijack() {
	// Not needed for these tests
}

func (m *mockResponseWriter) Close() error {
	return nil
}

func (m *mockResponseWriter) TsigStatus() error {
	return nil
}

func (m *mockResponseWriter) TsigTimersOnly(b bool) {
	// Not needed for these tests
}

func (m *mockResponseWriter) setFailed() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failed = true
}

func (m *mockResponseWriter) isFailed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.failed
}

func TestQueryCoalescerPlugin(t *testing.T) {
	p := New()
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	ctx1 := plugins.NewPluginContext()
	w1 := &mockResponseWriter{}
	ctx1.ResponseWriter = w1

	ctx2 := plugins.NewPluginContext()
	w2 := &mockResponseWriter{}
	ctx2.ResponseWriter = w2

	// Первый запрос
	err := p.Execute(ctx1, msg)
	assert.NoError(t, err)
	assert.False(t, ctx1.RequestHandled)

	key, ok := ctx1.Get("coalescer_key")
	assert.True(t, ok)

	var wg sync.WaitGroup
	wg.Add(1)

	// Второй (объединенный) запрос
	go func() {
		defer wg.Done()
		err := p.Execute(ctx2, msg)
		assert.NoError(t, err)
		assert.True(t, ctx2.RequestHandled)
	}()

	// Имитируем задержку перед ответом
	time.Sleep(100 * time.Millisecond)

	// Отправляем ответ
	response := new(dns.Msg)
	response.SetReply(msg)
	response.Rcode = dns.RcodeSuccess
	p.Response(key.(string), response, nil)

	wg.Wait()

	// Проверяем, что второй запрос получил ответ
	assert.NotNil(t, w2.msg())
	assert.Equal(t, dns.RcodeSuccess, w2.msg().Rcode)
}

func TestQueryCoalescerPlugin_Error(t *testing.T) {
	p := New()
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	ctx1 := plugins.NewPluginContext()
	w1 := &mockResponseWriter{}
	ctx1.ResponseWriter = w1

	ctx2 := plugins.NewPluginContext()
	w2 := &mockResponseWriter{}
	ctx2.ResponseWriter = w2

	// Подменяем handleFailed
	origHandleFailed := handleFailed
	handleFailed = func(w dns.ResponseWriter, r *dns.Msg) {
		w.(*mockResponseWriter).setFailed()
	}
	defer func() { handleFailed = origHandleFailed }()

	// Первый запрос
	err := p.Execute(ctx1, msg)
	assert.NoError(t, err)

	key, ok := ctx1.Get("coalescer_key")
	assert.True(t, ok)

	var wg sync.WaitGroup
	wg.Add(1)

	// Второй (объединенный) запрос
	go func() {
		defer wg.Done()
		err := p.Execute(ctx2, msg)
		assert.NoError(t, err)
		assert.True(t, ctx2.RequestHandled)
	}()

	time.Sleep(100 * time.Millisecond)

	// Отправляем ошибку
	p.Response(key.(string), nil, errors.New("resolve error"))

	wg.Wait()

	// Проверяем, что для второго запроса была вызвана обработка ошибки
	assert.True(t, w2.isFailed())
}