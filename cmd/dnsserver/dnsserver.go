package main

import (
	"context"
	"dns-resolver/internal/resolver"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/miekg/dns"
)

func main() {
	// Создаем наш новый резолвер
	r := resolver.NewResolver()

	// Подготавливаем DNS-сообщение
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("verisign.com"), dns.TypeA)
	msg.SetEdns0(4096, true)

	// Выполняем запрос
	result := r.Exchange(context.Background(), msg)

	// Выводим результат
	fmt.Println("--- DNS Response ---")
	spew.Dump(result.Msg)
	if result.Err != nil {
		fmt.Println("--- Error ---")
		spew.Dump(result.Err)
	}
}
