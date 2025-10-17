package query_coalescer

import (
	"fmt"
	"log"
	"sync"

	"dns-resolver/internal/plugins"
	"github.com/miekg/dns"
)

var (
	handleFailed = dns.HandleFailed
)

// request представляет собой находящийся в обработке DNS-запрос, ответа на который могут ожидать другие запросы.
type inFlightRequest struct {
	waiters []*waiter
	response *dns.Msg
	err      error
	doneCh   chan struct{}
}

// waiter представляет ожидающего клиента.
type waiter struct {
	writer dns.ResponseWriter
	msg    *dns.Msg
}

// QueryCoalescerPlugin предотвращает отправку дублирующихся DNS-запросов на вышестоящий сервер.
type QueryCoalescerPlugin struct {
	mu       sync.Mutex
	inFlight map[string]*inFlightRequest
}

// New создает новый QueryCoalescerPlugin.
func New() *QueryCoalescerPlugin {
	return &QueryCoalescerPlugin{
		inFlight: make(map[string]*inFlightRequest),
	}
}

// Name возвращает имя плагина.
func (p *QueryCoalescerPlugin) Name() string {
	return "QueryCoalescer"
}

// getRequestKey генерирует уникальный ключ для DNS-запроса.
func getRequestKey(msg *dns.Msg) string {
	if len(msg.Question) == 0 {
		return ""
	}
	q := msg.Question[0]
	return fmt.Sprintf("%s:%d:%d", q.Name, q.Qtype, q.Qclass)
}

// Execute — основная логика плагина.
func (p *QueryCoalescerPlugin) Execute(ctx *plugins.PluginContext, msg *dns.Msg) error {
	key := getRequestKey(msg)
	if key == "" {
		return nil // Не можем обработать этот запрос.
	}

	p.mu.Lock()
	// Проверяем, находится ли запрос с таким ключом уже в обработке.
	if req, ok := p.inFlight[key]; ok {
		log.Printf("[%s] Объединение запроса для %s", p.Name(), key)
		// Запрос уже в обработке. Добавляем текущего клиента в список ожидания.
		req.waiters = append(req.waiters, &waiter{writer: ctx.ResponseWriter, msg: msg})
		p.mu.Unlock()

		// Ждем завершения исходного запроса.
		<-req.doneCh

		// Исходный запрос завершен. Мы можем отправить общий ответ.
		// Ответ уже был отправлен обработчиком исходного запроса.
		// Нам просто нужно пометить этот запрос как обработанный.
		ctx.RequestHandled = true
		return nil
	}

	// Это первый запрос с таким ключом.
	log.Printf("[%s] Первый запрос для %s, разрешается.", p.Name(), key)
	req := &inFlightRequest{
		doneCh: make(chan struct{}),
	}
	p.inFlight[key] = req
	p.mu.Unlock()

	// После того как запрос будет разрешен сервером, нам нужно будет
	// уведомить всех ожидающих. Мы сохраняем ключ в контексте,
	// чтобы сервер мог вызвать наш колбэк `Response`.
	ctx.Set("coalescer_key", key)

	return nil
}

// Response обрабатывает ответ и рассылает его всем ожидающим.
func (p *QueryCoalescerPlugin) Response(key string, response *dns.Msg, err error) {
	p.mu.Lock()
	req, ok := p.inFlight[key]
	if !ok {
		p.mu.Unlock()
		return
	}
	// Сохраняем ответ и ошибку
	req.response = response
	req.err = err

	// Удаляем запрос из карты обрабатываемых, чтобы новые запросы пошли в обработку.
	delete(p.inFlight, key)
	p.mu.Unlock()

	// Рассылаем ответ всем ожидающим клиентам.
	for _, w := range req.waiters {
		if err != nil {
			handleFailed(w.writer, w.msg)
			continue
		}
		// Копируем сообщение и устанавливаем правильный ID транзакции.
		responseMsg := response.Copy()
		responseMsg.Id = w.msg.Id
		if writeErr := w.writer.WriteMsg(responseMsg); writeErr != nil {
			log.Printf("[%s] Не удалось записать объединенный ответ: %v", p.Name(), writeErr)
		}
	}

	// Закрываем канал, чтобы разблокировать все ожидающие горутины.
	close(req.doneCh)
}