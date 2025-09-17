// Package goresolver предоставляет функции для итеративного разрешения DNS-запросов
// с использованием библиотеки github.com/miekg/dns.
package goresolver

import (
	"errors"
	"log"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Определение ошибок
var (
	ErrNoData                = errors.New("no data for this record")
	ErrNoResult              = errors.New("requested RR not found")
	ErrNsNotAvailable        = errors.New("no name server to answer the question")
	ErrInvalidQuery          = errors.New("invalid query input")
	ErrDNSSECValidationFailed = errors.New("DNSSEC validation failed")
	ErrNoTrustAnchor         = errors.New("no trust anchor found")
	ErrMaxIterations         = errors.New("maximum iterations exceeded")
)

// Константы
const (
	// DefaultTimeout - стандартный таймаут для DNS-запросов.
	DefaultTimeout = 2 * time.Second
	
	// RootHints - список корневых серверов (A-записи).
	RootHints = `;       A.ROOT-SERVERS.NET.      3600000      A     198.41.0.4
;       B.ROOT-SERVERS.NET.      3600000      A     199.9.14.201
;       C.ROOT-SERVERS.NET.      3600000      A     192.33.4.12
;       D.ROOT-SERVERS.NET.      3600000      A     199.7.91.13
;       E.ROOT-SERVERS.NET.      3600000      A     192.203.230.10
;       F.ROOT-SERVERS.NET.      3600000      A     192.5.5.241
;       G.ROOT-SERVERS.NET.      3600000      A     192.112.36.4
;       H.ROOT-SERVERS.NET.      3600000      A     198.97.190.53
;       I.ROOT-SERVERS.NET.      3600000      A     192.36.148.17
;       J.ROOT-SERVERS.NET.      3600000      A     192.58.128.30
;       K.ROOT-SERVERS.NET.      3600000      A     193.0.14.129
;       L.ROOT-SERVERS.NET.      3600000      A     199.7.83.42
;       M.ROOT-SERVERS.NET.      3600000      A     202.12.27.33`
)

// Resolver содержит конфигурацию клиента и адреса вышестоящих DNS-серверов.
type Resolver struct {
	dnsClient    *dns.Client
	rootServers  []string
	trustAnchors map[string][]*dns.DNSKEY // Для будущей реализации DNSSEC
}

// DNSResult представляет результат DNS-запроса.
type DNSResult struct {
	Msg    *dns.Msg
	Err    error
	AuthNS []*dns.NS // Авторитетные NS для зоны
	Glue   []dns.RR  // Glue-записи (A/AAAA для NS)
}

// NewDNSMessage создает и инициализирует объект dns.Msg с включенным EDNS0 и флагом DO.
// RecursionDesired установлен в false для итеративного разрешения.
func NewDNSMessage(qname string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(qname), qtype)
	m.RecursionDesired = false // Важно: отключаем рекурсию
	m.SetEdns0(4096, true)     // Включаем EDNS0 с буфером 4096 и флагом DO
	return m
}

// Query выполняет итеративное разрешение DNS-запроса.
func (r *Resolver) Query(name string, qtype uint16) (*dns.Msg, error) {
	if name == "" {
		return nil, ErrInvalidQuery
	}

	log.Printf("Запуск итеративного разрешения для %s (тип %s)", name, dns.TypeToString[qtype])
	
	// Начинаем итеративное разрешение с корня
	result, err := r.iterativeResolve(name, qtype, true) // dnssec=true для будущего использования
	if err != nil {
		log.Printf("Ошибка итеративного разрешения: %v", err)
		return nil, err
	}
	
	// Возвращаем результат или ошибку из DNSResult
	if result.Err != nil {
		log.Printf("DNS-запрос завершился с ошибкой: %v", result.Err)
		return result.Msg, result.Err // Может быть nil или частичный ответ
	}

	log.Printf("Итеративное разрешение успешно завершено")
	return result.Msg, nil
}

// iterativeResolve выполняет основную логику итеративного разрешения.
// name - целевое имя для разрешения.
// qtype - тип запрашиваемой записи.
// dnssec - флаг для включения DNSSEC (пока не используется полностью).
func (r *Resolver) iterativeResolve(name string, qtype uint16, dnssec bool) (*DNSResult, error) {
	name = dns.Fqdn(name) // Убедимся, что имя в формате FQDN

	// Начинаем с корневых серверов
	currentServers := r.rootServers
	// Начинаем с корневой зоны
	currentZone := "."

	// Ограничение на количество итераций для предотвращения зацикливания
	maxIterations := 20
	iterations := 0

	log.Printf("Начинаем итеративное разрешение для %s (тип %s)", name, dns.TypeToString[qtype])

	for iterations < maxIterations {
		iterations++
		log.Printf("Итерация %d: Текущая зона: %s", iterations, currentZone)

		// Запрашиваем у текущих серверов информацию о целевом имени или текущей зоне
		// Сначала пробуем запросить целевое имя, если оно находится в текущей или дочерней зоне
		queryName := name
		if !dns.IsSubDomain(currentZone, name) {
			// Если имя не находится в текущей зоне, запрашиваем саму зону для получения NS
			queryName = currentZone
			log.Printf("Запрашиваем NS для зоны %s вместо %s", currentZone, name)
		}

		result := r.queryAuthoritativeServers(currentServers, queryName, qtype, dnssec)

		// Если получили ответ (успех или NXDOMAIN), проверяем, является ли он окончательным
		if result.Msg != nil {
			if result.Msg.Rcode == dns.RcodeSuccess || result.Msg.Rcode == dns.RcodeNameError {
				// Проверяем, является ли это ответом на наш исходный запрос
				if queryName == name {
					log.Printf("Получен окончательный ответ на запрос %s на итерации %d", name, iterations)
					return result, nil // Это наш окончательный ответ
				}
				// Если это ответ на запрос зоны (для получения NS), продолжаем обработку ниже
			}
		}

		// Обрабатываем referral или информацию о NS
		if result.Msg != nil && len(result.Msg.Ns) > 0 {
			var nsRecords []*dns.NS
			var glueRecords []dns.RR

			// Извлекаем NS записи из Authority секции
			for _, rr := range result.Msg.Ns {
				if ns, ok := rr.(*dns.NS); ok {
					nsRecords = append(nsRecords, ns)
				}
			}

			// Извлекаем glue записи (A/AAAA) из Additional секции
			for _, rr := range result.Msg.Extra {
				if a, ok := rr.(*dns.A); ok {
					glueRecords = append(glueRecords, a)
				} else if aaaa, ok := rr.(*dns.AAAA); ok {
					glueRecords = append(glueRecords, aaaa)
				}
			}

			// Если NS записи найдены, обновляем список серверов
			if len(nsRecords) > 0 {
				log.Printf("Найдено %d NS записей для зоны %s", len(nsRecords), queryName)

				// Получаем IP адреса для NS серверов
				var newServers []string

				// Сначала используем glue записи
				for _, ns := range nsRecords {
					foundGlue := false
					// Ищем glue для этого NS в Additional секции
					for _, glue := range glueRecords {
						// Сравниваем имя владельца glue записи с именем NS сервера
						if dns.Fqdn(glue.Header().Name) == dns.Fqdn(ns.Ns) {
							if a, ok := glue.(*dns.A); ok {
								newServers = append(newServers, a.A.String())
								foundGlue = true
								log.Printf("Используем glue A запись для %s: %s", ns.Ns, a.A.String())
							} else if aaaa, ok := glue.(*dns.AAAA); ok {
								newServers = append(newServers, aaaa.AAAA.String())
								foundGlue = true
								log.Printf("Используем glue AAAA запись для %s: %s", ns.Ns, aaaa.AAAA.String())
							}
						}
					}

					// Если glue не найден, необходимо разрешить имя NS сервера итеративно
					if !foundGlue {
						log.Printf("Glue запись для NS %s не найдена, начинаем итеративное разрешение", ns.Ns)
						// Рекурсивный вызов для разрешения имени NS сервера (например, ns.example.com)
						nsResolver := &Resolver{
							dnsClient:    r.dnsClient,
							rootServers:  r.rootServers, // Используем те же корневые серверы
							trustAnchors: r.trustAnchors,
						}
						nsResult, err := nsResolver.iterativeResolve(trimDot(ns.Ns), dns.TypeA, dnssec)
						if err == nil && nsResult.Msg != nil && nsResult.Msg.Rcode == dns.RcodeSuccess {
							for _, rr := range nsResult.Msg.Answer {
								if a, ok := rr.(*dns.A); ok {
									newServers = append(newServers, a.A.String())
									log.Printf("Разрешен NS %s в IP %s", ns.Ns, a.A.String())
								} else if aaaa, ok := rr.(*dns.AAAA); ok {
									newServers = append(newServers, aaaa.AAAA.String())
									log.Printf("Разрешен NS %s в IP %s", ns.Ns, aaaa.AAAA.String())
								}
							}
						} else {
							log.Printf("Не удалось разрешить имя NS сервера %s: %v", ns.Ns, err)
							// Можно продолжить с другими NS или вернуть ошибку, если все NS недоступны
						}
					}
				}

				// Если удалось получить IP адреса новых серверов, обновляем список
				if len(newServers) > 0 {
					currentServers = newServers
					// Определяем новую текущую зону (для которой эти NS авторитетны)
					// Это имя из Authority секции или имя, для которого запрашивались NS
					// В большинстве случаев это будет queryName
					if queryName != "." { // Не обновляем зону, если запрашивали корень
						currentZone = queryName
						log.Printf("Обновлена текущая зона до %s", currentZone)
					}
				} else {
					log.Printf("Не удалось получить IP адреса для NS серверов, используем предыдущие")
					// Если не удалось получить новые серверы, возвращаем ошибку или используем старые
					// В данном случае, мы просто продолжим с текущими серверами, что может привести к зацикливанию
					// Лучше вернуть ошибку
					return &DNSResult{Msg: nil, Err: ErrNsNotAvailable}, nil
				}
				continue // Переходим к следующей итерации с новыми серверами
			}
		}

		// Если мы дошли до этой точки, значит либо ответа не было, либо NS не найдены
		// Это может указывать на проблему или конец цепочки
		log.Printf("Не получено NS записей или ответа от серверов на итерации %d", iterations)
		// Проверяем, достигли ли мы максимального количества итераций
		if iterations >= maxIterations {
			log.Printf("Превышено максимальное количество итераций (%d)", maxIterations)
			return &DNSResult{Msg: nil, Err: ErrMaxIterations}, nil
		}
		
		// Если сервер вернул ошибку или не дал нужной информации, пробуем следующую зону
		// или возвращаем ошибку, если не знаем, что делать дальше
		// В текущей логике, если NS не найдены, мы возвращаем ошибку выше
		// Если нужно продолжить, можно добавить логику здесь, но это сложнее
		// Для простоты, если мы не получили NS, считаем это ошибкой
		if result.Err != nil {
			return result, nil // Возвращаем ошибку из queryAuthoritativeServers
		}
		// Если Msg есть, но NS нет, и это не финальный ответ, это странно
		// Возвращаем то, что есть, или специфичную ошибку
		log.Printf("Неожиданный ответ: есть Msg, но нет NS и не финальный ответ")
		return result, nil
		
	}

	// Если цикл завершился без возврата результата
	log.Printf("Цикл итераций завершен без получения результата")
	return &DNSResult{Msg: nil, Err: ErrMaxIterations}, nil
}


// queryAuthoritativeServers отправляет DNS-запрос набору авторитетных серверов.
func (r *Resolver) queryAuthoritativeServers(servers []string, name string, qtype uint16, dnssec bool) *DNSResult {
	result := &DNSResult{}
	
	log.Printf("Отправка запроса к серверам %v для %s (тип %s)", servers, name, dns.TypeToString[qtype])
	
	// Пробуем каждый сервер из списка
	for _, server := range servers {
		addr := net.JoinHostPort(server, "53")
		msg := NewDNSMessage(name, qtype)
		
		log.Printf("Отправка запроса на %s", addr)
		response, rtt, err := r.dnsClient.Exchange(msg, addr)
		if err == nil && response != nil {
			log.Printf("Получен ответ от %s, Rcode: %s, RTT: %v", addr, dns.RcodeToString[response.Rcode], rtt)
			
			// Заполняем результат
			result.Msg = response
			
			// Собираем NS записи из Authority секции
			for _, rr := range response.Ns {
				if ns, ok := rr.(*dns.NS); ok {
					result.AuthNS = append(result.AuthNS, ns)
				}
			}
			
			// Собираем glue записи из Additional секции
			result.Glue = append(result.Glue, response.Extra...)
			
			// Если получен определенный ответ (успех или NXDOMAIN), возвращаем его
			if response.Rcode == dns.RcodeSuccess || response.Rcode == dns.RcodeNameError {
				log.Printf("Получен определенный ответ от %s", addr)
				return result // Возвращаем успешный или NXDOMAIN ответ
			}
			// Если Rcode другой (например, SERVFAIL), продолжаем опрос других серверов
			log.Printf("Получен ответ с кодом %s от %s, пробуем следующий сервер", dns.RcodeToString[response.Rcode], addr)
		} else if err != nil {
			log.Printf("Ошибка при запросе к %s: %v", addr, err)
			// Продолжаем опрос других серверов
		} else {
			// response == nil, но err == nil - маловероятно, но возможно
			log.Printf("Получен nil ответ от %s без ошибки", addr)
		}
	}
	
	// Если ни один сервер не дал определенного ответа
	result.Err = ErrNsNotAvailable
	log.Printf("Ни один из серверов не дал определенного ответа")
	return result
}


// trimDot удаляет завершающую точку из имени домена.
func trimDot(name string) string {
	return strings.TrimSuffix(name, ".")
}

// NewResolver инициализирует экземпляр Resolver.
func NewResolver(resolvConf string) (res *Resolver, err error) {
	resolver := &Resolver{}
	resolver.dnsClient = &dns.Client{
		ReadTimeout: DefaultTimeout,
		// Можно добавить WriteTimeout, UDPSize и другие параметры при необходимости
	}
	
	// Парсим корневые подсказки
	resolver.rootServers = parseRootHints(RootHints)
	
	// Инициализируем доверенные привязки (trust anchors) - упрощенная версия
	// Для полноценной работы DNSSEC нужно реализовать загрузку DS/DNSKEY корневой зоны
	resolver.trustAnchors = make(map[string][]*dns.DNSKEY)
	// Пример добавления корневого ключа (необходимо обновлять регулярно!)
	// Это упрощенный пример, в реальности нужно парсить ключ из официального источника
	// resolver.trustAnchors["."] = append(resolver.trustAnchors["."], rootDNSKEY)
	
	log.Printf("Инициализирован Resolver с %d корневыми серверами", len(resolver.rootServers))
	
	return resolver, nil
}

// parseRootHints парсит список корневых серверов из строки.
func parseRootHints(hints string) []string {
	var servers []string
	lines := strings.Split(hints, "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		
		// Парсим строку, извлекая IP адрес
		parts := strings.Fields(line)
		// Ожидаемый формат: <имя> <TTL> <тип> <данные>
		// Например: "A.ROOT-SERVERS.NET. 3600000 A 198.41.0.4"
		if len(parts) >= 4 && (parts[2] == "A" || parts[2] == "AAAA") {
			ip := parts[3]
			// Проверяем, является ли это валидным IP адресом (опционально)
			if net.ParseIP(ip) != nil {
				servers = append(servers, ip)
			} else {
				log.Printf("Некорректный IP адрес в root hints: %s", ip)
			}
		} else {
			log.Printf("Некорректная строка в root hints: %s", line)
		}
	}
	
	return servers
}

// --- Методы-обертки для удобства ---

// Resolve - общий метод для разрешения DNS записей.
func (r *Resolver) Resolve(name string, qtype uint16) (*dns.Msg, error) {
	return r.Query(name, qtype)
}

// ResolveA разрешает A записи.
func (r *Resolver) ResolveA(name string) (*dns.Msg, error) {
	return r.Query(name, dns.TypeA)
}

// ResolveAAAA разрешает AAAA записи.
func (r *Resolver) ResolveAAAA(name string) (*dns.Msg, error) {
	return r.Query(name, dns.TypeAAAA)
}

// ResolveMX разрешает MX записи.
func (r *Resolver) ResolveMX(name string) (*dns.Msg, error) {
	return r.Query(name, dns.TypeMX)
}

// ResolveTXT разрешает TXT записи.
func (r *Resolver) ResolveTXT(name string) (*dns.Msg, error) {
	return r.Query(name, dns.TypeTXT)
}

// ResolveNS разрешает NS записи.
func (r *Resolver) ResolveNS(name string) (*dns.Msg, error) {
	return r.Query(name, dns.TypeNS)
}

// ResolveCNAME разрешает CNAME записи.
func (r *Resolver) ResolveCNAME(name string) (*dns.Msg, error) {
	return r.Query(name, dns.TypeCNAME)
}

// ResolvePTR разрешает PTR записи.
func (r *Resolver) ResolvePTR(name string) (*dns.Msg, error) {
	return r.Query(name, dns.TypePTR)
}
