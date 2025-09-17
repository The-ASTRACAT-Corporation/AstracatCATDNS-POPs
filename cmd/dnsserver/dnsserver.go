// Package goresolver предоставляет функции для итеративного разрешения DNS-запросов
// с использованием библиотеки github.com/miekg/dns и поддержкой DNSSEC.
package goresolver

import (
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"fmt"
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
	ErrNoRRSIG               = errors.New("no RRSIG for record")
	ErrNoDNSKEY              = errors.New("no DNSKEY for zone")
	ErrKeyNotFound           = errors.New("DNSKEY not found for RRSIG")
	ErrSignatureVerificationFailed = errors.New("signature verification failed")
	ErrDSVerificationFailed  = errors.New("DS verification failed")
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
	
	// Корневой доверенный ключ (KSK) - необходимо регулярно обновлять!
	// Это упрощенный пример. В реальном приложении нужно использовать механизм автоматического обновления.
	RootTrustAnchor = `.; IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D`
)

// SecurityStatus представляет статус безопасности ответа DNS
type SecurityStatus int

const (
	SecurityStatusUnspecified SecurityStatus = iota
	SecurityStatusSecure
	SecurityStatusInsecure
	SecurityStatusBogus
)

// String возвращает строковое представление статуса безопасности
func (s SecurityStatus) String() string {
	switch s {
	case SecurityStatusSecure:
		return "Secure"
	case SecurityStatusInsecure:
		return "Insecure"
	case SecurityStatusBogus:
		return "Bogus"
	default:
		return "Unspecified"
	}
}

// Resolver содержит конфигурацию клиента и адреса вышестоящих DNS-серверов.
type Resolver struct {
	dnsClient    *dns.Client
	rootServers  []string
	trustAnchors map[string][]*dns.DS // Храним DS записи как trust anchors
}

// DNSResult представляет результат DNS-запроса.
type DNSResult struct {
	Msg           *dns.Msg
	Err           error
	AuthNS        []*dns.NS  // Авторитетные NS для зоны
	Glue          []dns.RR   // Glue-записи (A/AAAA для NS)
	SecurityStatus SecurityStatus // Статус безопасности ответа
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

// Query выполняет итеративное разрешение DNS-запроса с DNSSEC-валидацией.
func (r *Resolver) Query(name string, qtype uint16) (*dns.Msg, error) {
	if name == "" {
		return nil, ErrInvalidQuery
	}

	log.Printf("Запуск итеративного разрешения для %s (тип %s)", name, dns.TypeToString[qtype])
	
	// Начинаем итеративное разрешение с корня
	result, err := r.iterativeResolve(name, qtype, true) // dnssec=true для включения валидации
	if err != nil {
		log.Printf("Ошибка итеративного разрешения: %v", err)
		return nil, err
	}
	
	// Возвращаем результат или ошибку из DNSResult
	if result.Err != nil {
		log.Printf("DNS-запрос завершился с ошибкой: %v", result.Err)
		return result.Msg, result.Err // Может быть nil или частичный ответ
	}

	log.Printf("Итеративное разрешение успешно завершено. Статус безопасности: %s", result.SecurityStatus)
	
	// Если включена DNSSEC и статус Bogus, возвращаем ошибку
	if result.SecurityStatus == SecurityStatusBogus {
		return result.Msg, ErrDNSSECValidationFailed
	}
	
	return result.Msg, nil
}

// iterativeResolve выполняет основную логику итеративного разрешения с DNSSEC-валидацией.
// name - целевое имя для разрешения.
// qtype - тип запрашиваемой записи.
// dnssec - флаг для включения DNSSEC.
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
					// Выполняем DNSSEC-валидацию финального ответа, если включена
					if dnssec {
						securityStatus, err := r.validateDNSSEC(name, qtype, result.Msg, currentZone)
						if err != nil {
							log.Printf("Ошибка DNSSEC-валидации финального ответа: %v", err)
							result.SecurityStatus = SecurityStatusBogus
							result.Err = err
							return result, nil
						}
						result.SecurityStatus = securityStatus
						log.Printf("Статус безопасности финального ответа: %s", securityStatus)
					}
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

				// Выполняем DNSSEC-валидацию referral'а, если включена
				if dnssec {
					securityStatus, err := r.validateDNSSEC(queryName, dns.TypeNS, result.Msg, currentZone)
					if err != nil {
						log.Printf("Ошибка DNSSEC-валидации referral'а: %v", err)
						result.SecurityStatus = SecurityStatusBogus
						result.Err = err
						return result, nil
					}
					result.SecurityStatus = securityStatus
					log.Printf("Статус безопасности referral'а: %s", securityStatus)
					
					// Если referral bogus, прекращаем разрешение
					if securityStatus == SecurityStatusBogus {
						return result, nil
					}
				}

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

// validateDNSSEC выполняет базовую DNSSEC-валидацию ответа.
func (r *Resolver) validateDNSSEC(name string, qtype uint16, msg *dns.Msg, zone string) (SecurityStatus, error) {
	log.Printf("Начинаем DNSSEC-валидацию для %s (тип %s) в зоне %s", name, dns.TypeToString[qtype], zone)
	
	// 1. Проверяем, есть ли RRSIG записи в ответе
	hasRRSIG := false
	for _, rr := range msg.Answer {
		if _, ok := rr.(*dns.RRSIG); ok {
			hasRRSIG = true
			break
		}
	}
	for _, rr := range msg.Ns {
		if _, ok := rr.(*dns.RRSIG); ok {
			hasRRSIG = true
			break
		}
	}
	for _, rr := range msg.Extra {
		if _, ok := rr.(*dns.RRSIG); ok {
			hasRRSIG = true
			break
		}
	}
	
	if !hasRRSIG {
		log.Printf("Ответ не содержит RRSIG записей, считаем insecure")
		return SecurityStatusInsecure, nil
	}
	
	// 2. Получаем DNSKEY для зоны
	dnskeyResult, err := r.getDNSKEYForZone(zone)
	if err != nil {
		log.Printf("Не удалось получить DNSKEY для зоны %s: %v", zone, err)
		return SecurityStatusBogus, err
	}
	
	if dnskeyResult.Msg == nil || len(dnskeyResult.Msg.Answer) == 0 {
		log.Printf("DNSKEY для зоны %s не найден", zone)
		return SecurityStatusBogus, ErrNoDNSKEY
	}
	
	var dnskeys []*dns.DNSKEY
	for _, rr := range dnskeyResult.Msg.Answer {
		if dnskey, ok := rr.(*dns.DNSKEY); ok {
			dnskeys = append(dnskeys, dnskey)
		}
	}
	
	if len(dnskeys) == 0 {
		log.Printf("DNSKEY для зоны %s не найден", zone)
		return SecurityStatusBogus, ErrNoDNSKEY
	}
	
	// 3. Валидируем RRSIG записи в основном ответе
	// Проверяем Answer секцию
	for _, rr := range msg.Answer {
		if rrsig, ok := rr.(*dns.RRSIG); ok {
			err := r.verifyRRSIG(rrsig, msg.Answer, dnskeys)
			if err != nil {
				log.Printf("Ошибка проверки RRSIG для Answer: %v", err)
				return SecurityStatusBogus, ErrSignatureVerificationFailed
			}
		}
	}
	
	// Проверяем Authority секцию
	for _, rr := range msg.Ns {
		if rrsig, ok := rr.(*dns.RRSIG); ok {
			err := r.verifyRRSIG(rrsig, msg.Ns, dnskeys)
			if err != nil {
				log.Printf("Ошибка проверки RRSIG для Authority: %v", err)
				return SecurityStatusBogus, ErrSignatureVerificationFailed
			}
		}
	}
	
	// Проверяем Additional секцию
	for _, rr := range msg.Extra {
		if rrsig, ok := rr.(*dns.RRSIG); ok {
			err := r.verifyRRSIG(rrsig, msg.Extra, dnskeys)
			if err != nil {
				log.Printf("Ошибка проверки RRSIG для Additional: %v", err)
				return SecurityStatusBogus, ErrSignatureVerificationFailed
			}
		}
	}
	
	log.Printf("DNSSEC-валидация для %s в зоне %s успешна", name, zone)
	return SecurityStatusSecure, nil
}

// getDNSKEYForZone получает DNSKEY записи для заданной зоны.
func (r *Resolver) getDNSKEYForZone(zone string) (*DNSResult, error) {
	log.Printf("Получаем DNSKEY для зоны %s", zone)
	
	// Используем тот же процесс итеративного разрешения
	return r.iterativeResolve(zone, dns.TypeDNSKEY, true)
}

// verifyRRSIG проверяет подпись RRSIG для набора записей RRset.
func (r *Resolver) verifyRRSIG(rrsig *dns.RRSIG, rrset []dns.RR, keys []*dns.DNSKEY) error {
	log.Printf("Проверка RRSIG для типа %s в зоне %s", dns.TypeToString[rrsig.TypeCovered], rrsig.SignerName)
	
	// Находим соответствующий DNSKEY
	var key *dns.DNSKEY
	for _, k := range keys {
		if k.KeyTag() == rrsig.KeyTag && k.Algorithm == rrsig.Algorithm && k.Header().Name == rrsig.SignerName {
			key = k
			break
		}
	}
	
	if key == nil {
		log.Printf("DNSKEY для RRSIG не найден (KeyTag: %d, Algorithm: %d, SignerName: %s)", rrsig.KeyTag, rrsig.Algorithm, rrsig.SignerName)
		return ErrKeyNotFound
	}
	
	// Проверяем подпись
	err := rrsig.Verify(key, rrset)
	if err != nil {
		log.Printf("Ошибка проверки подписи RRSIG: %v", err)
		return ErrSignatureVerificationFailed
	}
	
	log.Printf("Подпись RRSIG проверена успешно")
	return nil
}

// verifyDS проверяет DS запись против DNSKEY.
func (r *Resolver) verifyDS(ds *dns.DS, dnskey *dns.DNSKEY) error {
	log.Printf("Проверка DS записи для DNSKEY (KeyTag: %d, Algorithm: %d)", dnskey.KeyTag(), dnskey.Algorithm)
	
	// Вычисляем хэш DNSKEY
	var hash []byte
	switch ds.DigestType {
	case dns.SHA1:
		// Конвертируем string в []byte
		digestBytes := []byte(ds.Digest)
		h := sha1.Sum(digestBytes)
		hash = h[:]
	case dns.SHA256:
		// Конвертируем string в []byte
		digestBytes := []byte(ds.Digest)
		h := sha256.Sum256(digestBytes)
		hash = h[:]
	default:
		return fmt.Errorf("неподдерживаемый тип хэша DS: %d", ds.DigestType)
	}
	
	// Сравниваем хэши
	// ds.Digest уже является строкой хэша, полученного от сервера
	// Мы должны вычислить хэш DNSKEY и сравнить его с ds.Digest
	// Для этого используем dnskey.ToDS()
	computedDS := dnskey.ToDS(ds.DigestType)
	if computedDS == nil {
		return fmt.Errorf("не удалось вычислить DS для DNSKEY")
	}
	
	if computedDS.Digest != ds.Digest {
		log.Printf("Хэш DS не совпадает с хэшем DNSKEY")
		return ErrDSVerificationFailed
	}
	
	log.Printf("DS запись проверена успешно")
	return nil
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
	
	// Инициализируем доверенные привязки (trust anchors)
	resolver.trustAnchors = make(map[string][]*dns.DS)
	
	// Парсим корневой доверенный ключ
	if err := resolver.parseTrustAnchors(RootTrustAnchor); err != nil {
		return nil, fmt.Errorf("ошибка парсинга trust anchor: %v", err)
	}
	
	log.Printf("Инициализирован Resolver с %d корневыми серверами", len(resolver.rootServers))
	
	return resolver, nil
}

// parseTrustAnchors парсит trust anchors из строки.
func (r *Resolver) parseTrustAnchors(anchorStr string) error {
	rr, err := dns.NewRR(anchorStr)
	if err != nil {
		return fmt.Errorf("ошибка парсинга trust anchor: %v", err)
	}
	
	if ds, ok := rr.(*dns.DS); ok {
		// DS запись добавляется как trust anchor для зоны
		zone := strings.ToLower(ds.Header().Name)
		r.trustAnchors[zone] = append(r.trustAnchors[zone], ds)
		log.Printf("Добавлен trust anchor (DS) для зоны %s", zone)
	}
	
	return nil
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
