package main

import (
	"context"
	"dns-resolver/internal/resolver" // Используем наш новый внутренний резолвер
	"github.com/miekg/dns"
	"log"
	"time"
)

const (
	port          = ":5053"
	defaultShards = 32 // Пример: 32 шарда
)

type DnsJob struct {
	w            dns.ResponseWriter
	req          *dns.Msg
	shardedCache *ShardedCache
	r            *resolver.Resolver // Используем наш новый резолвер
}

func (j *DnsJob) Execute() {
	// Генерируем ключ кэша из DNS-запроса
	cacheKey := j.req.Question[0].Name + ":" + dns.TypeToString[j.req.Question[0].Qtype]

	// Пытаемся получить ответ из кэша
	if cachedMsg, found, isNegative, _ := j.shardedCache.Get(cacheKey); found {
		if isNegative {
			log.Printf("Cache HIT (negative) for %s", cacheKey)
			m := new(dns.Msg)
			m.SetRcode(j.req, dns.RcodeServerFailure) // Или соответствующий отрицательный ответ
			j.w.WriteMsg(m)
			return
		} else {
			log.Printf("Cache HIT (positive) for %s", cacheKey)
			cachedMsg.Id = j.req.Id // Устанавливаем ID, чтобы он соответствовал ID запроса
			j.w.WriteMsg(cachedMsg)
			return
		}
	}
	log.Printf("Cache MISS for %s", cacheKey)

	// Создаем новое сообщение для передачи резолверу
	msg := new(dns.Msg)
	msg.SetQuestion(j.req.Question[0].Name, j.req.Question[0].Qtype)
	msg.SetEdns0(4096, true) // Включаем EDNS0 с флагом DNSSEC OK

	// Используем наш новый резолвер
	result := j.r.Exchange(context.Background(), msg)
	if result.Err != nil {
		log.Printf("Error exchanging DNS query: %v", result.Err)
		m := new(dns.Msg)
		m.SetRcode(j.req, dns.RcodeServerFailure)
		j.w.WriteMsg(m)
		// Кэшируем SERVFAIL с коротким TTL
		j.shardedCache.Set(cacheKey, m, 30*time.Second, true, false) // Предполагаем, что при ошибке валидация не пройдена
		return
	}

	// Устанавливаем флаг Recursion Available (RA)
	result.Msg.RecursionAvailable = true
	result.Msg.Id = j.req.Id

	// Определяем TTL для кэширования.
	ttl := 60 * time.Second // TTL по умолчанию
	if len(result.Msg.Answer) > 0 {
		minTTL := result.Msg.Answer[0].Header().Ttl
		for _, rr := range result.Msg.Answer {
			if rr.Header().Ttl < minTTL {
				minTTL = rr.Header().Ttl
			}
		}
		ttl = time.Duration(minTTL) * time.Second
	}

	// Определяем статус DNSSEC-валидации по флагу AD
	dnssecValidated := result.Msg.AuthenticatedData

	// Если DNSSEC не валидирован, используем очень короткий TTL для повторной проверки
	if !dnssecValidated {
		ttl = 5 * time.Second // Очень короткий TTL для невалидированных записей
	}

	// Кэшируем положительный ответ
	j.shardedCache.Set(cacheKey, result.Msg, ttl, false, dnssecValidated)

	j.w.WriteMsg(result.Msg)
}

func main() {
	// Нам больше не нужен хук логирования из старого резолвера

	// Инициализируем шард-кэш
	shardedCache := NewShardedCache(defaultShards, 1*time.Minute)
	defer shardedCache.Stop()

	// Инициализируем пул воркеров
	workerPool := NewWorkerPool(100, 1000) // 100 воркеров, размер очереди 1000
	workerPool.Start()
	defer workerPool.Stop()

	// Инициализируем наш новый резолвер
	r := resolver.NewResolver()

	dns.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		job := &DnsJob{
			w:            w,
			req:          req,
			shardedCache: shardedCache,
			r:            r,
		}
		workerPool.Submit(job)
	})

	server := &dns.Server{
		Addr:    port,
		Net:     "udp",
		UDPSize: 65535, // Устанавливаем максимальный UDPSize для EDNS0
	}

	log.Printf("Starting DNS resolver on %s", port)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}