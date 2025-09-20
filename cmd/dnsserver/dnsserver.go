package main

import (
	"context"
	"dns-resolver/internal/cache"
	"dns-resolver/internal/resolver"
	"github.com/davecgh/go-spew/spew"
	"github.com/miekg/dns"
	"time"
)

// Resolver - ваша обертка вокруг библиотечного резолвера
type Resolver struct {
	r *resolver.Resolver
}

// NewResolver создает новый экземпляр резолвера
func NewResolver() *Resolver {
	return &Resolver{
		// NOTE: This is a simple test client, DNSSEC is hardcoded to true here.
		// The main server in main.go uses a command-line flag.
		r: resolver.NewResolver(cache.NewShardedCache(1, 1*time.Minute, cache.CacheConfig{}), true),
	}
}

// ResolveA разрешает A-записи
func (r *Resolver) ResolveA(name string) *resolver.Result {
	// Подготавливаем DNS-сообщение (как в вашем коде)
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), dns.TypeA)
	
	// Включаем EDNS0 с DNSSEC (как в вашем коде)
	msg.SetEdns0(4096, true)
	
	// Выполняем запрос (как в вашем коде)
	result := r.r.Exchange(context.Background(), msg)
	
	return result
}

// ResolveAAAA разрешает AAAA-записи
func (r *Resolver) ResolveAAAA(name string) *resolver.Result {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), dns.TypeAAAA)
	msg.SetEdns0(4096, true)
	
	result := r.r.Exchange(context.Background(), msg)
	
	return result
}

// Resolve выполняет общий DNS-запрос
func (r *Resolver) Resolve(name string, qtype uint16) *resolver.Result {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	msg.SetEdns0(4096, true)
	
	result := r.r.Exchange(context.Background(), msg)
	
	return result
}

func main() {
	// Создаем резолвер (как в вашем коде)
	r := NewResolver()

	// Выполняем запрос (как в вашем коде)
	result := r.ResolveA("test.qazz.uk")

	// Выводим результат (как в вашем коде)
	spew.Dump(result)
}