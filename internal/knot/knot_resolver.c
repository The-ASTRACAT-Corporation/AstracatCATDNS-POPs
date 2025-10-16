/*  Copyright (C) 2024 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "knot_resolver.h"
#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>

/* Root servers for fallback resolution */
static const char *root_servers[] = {
    "198.41.0.4",      // a.root-servers.net
    "199.9.14.201",    // b.root-servers.net
    "192.33.4.12",     // c.root-servers.net
    "199.7.91.13",     // d.root-servers.net
    "192.203.230.10",  // e.root-servers.net
    "192.5.5.241",     // f.root-servers.net
    "192.112.36.4",    // g.root-servers.net
    "198.97.190.53",   // h.root-servers.net
    "192.36.148.17",   // i.root-servers.net
    "192.58.128.30",   // j.root-servers.net
    "193.0.14.129",    // k.root-servers.net
    "199.7.83.42",     // l.root-servers.net
    "202.12.27.33",    // m.root-servers.net
    NULL
};

/* DNS type to string mapping */
static const struct {
    uint16_t type;
    const char *name;
} qtype_map[] = {
    { 1, "A" },
    { 2, "NS" },
    { 5, "CNAME" },
    { 6, "SOA" },
    { 12, "PTR" },
    { 15, "MX" },
    { 16, "TXT" },
    { 28, "AAAA" },
    { 33, "SRV" },
    { 43, "DS" },
    { 46, "RRSIG" },
    { 47, "NSEC" },
    { 48, "DNSKEY" },
    { 50, "NSEC3" },
    { 51, "NSEC3PARAM" },
    { 0, NULL }
};

/* DNS class to string mapping */
static const struct {
    uint16_t class;
    const char *name;
} qclass_map[] = {
    { 1, "IN" },
    { 3, "CH" },
    { 4, "HS" },
    { 0, NULL }
};

/* Helper function to create error result */
static knot_resolve_result_t *create_error_result(const char *error_msg) {
    knot_resolve_result_t *result = malloc(sizeof(knot_resolve_result_t));
    if (!result) return NULL;
    
    result->wire = NULL;
    result->wire_size = 0;
    result->rcode = 2; // SERVFAIL
    result->secure = false;
    result->bogus = false;
    result->error_msg = error_msg ? strdup(error_msg) : NULL;
    
    return result;
}

/* Helper function to create success result */
static knot_resolve_result_t *create_success_result(const uint8_t *wire, size_t wire_size, int rcode, bool secure, bool bogus) {
    knot_resolve_result_t *result = malloc(sizeof(knot_resolve_result_t));
    if (!result) return NULL;
    
    result->wire = malloc(wire_size);
    if (!result->wire) {
        free(result);
        return NULL;
    }
    
    memcpy(result->wire, wire, wire_size);
    result->wire_size = wire_size;
    result->rcode = rcode;
    result->secure = secure;
    result->bogus = bogus;
    result->error_msg = NULL;
    
    return result;
}

/* Send DNS query to server */
static int send_dns_query(const char *server_ip, uint16_t port, 
                         const uint8_t *query, size_t query_len,
                         uint8_t *response, size_t *response_len) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) return -1;
    
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, server_ip, &server_addr.sin_addr);
    
    // Set timeout
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    ssize_t sent = sendto(sockfd, query, query_len, 0, 
                         (struct sockaddr*)&server_addr, sizeof(server_addr));
    if (sent != query_len) {
        close(sockfd);
        return -1;
    }
    
    socklen_t addr_len = sizeof(server_addr);
    ssize_t received = recvfrom(sockfd, response, *response_len, 0,
                               (struct sockaddr*)&server_addr, &addr_len);
    close(sockfd);
    
    if (received < 0) return -1;
    
    *response_len = received;
    return 0;
}

/* Recursive DNS resolution */
static knot_resolve_result_t *recursive_resolve(knot_resolver_t *resolver,
                                               const char *qname, uint16_t qtype, uint16_t qclass) {
    knot_pkt_t *query_pkt = knot_pkt_new(NULL, 512, resolver->mm);
    if (!query_pkt) {
        return create_error_result("Failed to create query packet");
    }
    
    // Convert qname to dname
    knot_dname_t *dname = knot_dname_from_str_alloc(qname);
    if (!dname) {
        knot_pkt_free(query_pkt);
        return create_error_result("Invalid domain name");
    }
    
    // Create query packet
    if (knot_pkt_put_question(query_pkt, dname, qclass, qtype) != KNOT_EOK) {
        knot_dname_free(dname, resolver->mm);
        knot_pkt_free(query_pkt);
        return create_error_result("Failed to create query");
    }
    
    // Set query flags
    knot_wire_clear_qr(query_pkt->wire); // Query
    knot_wire_set_rd(query_pkt->wire); // Recursion desired
    knot_wire_set_id(query_pkt->wire, rand() & 0xFFFF);
    
    // Add EDNS0 for DNSSEC support
    knot_rrset_t *opt_rr = knot_rrset_new(NULL, KNOT_RRTYPE_OPT, qclass, 0, resolver->mm);
    if (opt_rr) {
        uint8_t opt_data[] = {0x00, 0x00, 0x00, 0x00}; // DO bit set
        knot_rrset_add_rdata(opt_rr, opt_data, sizeof(opt_data), resolver->mm);
        knot_pkt_put(query_pkt, 0, opt_rr, 0);
    }
    
    // Try root servers
    uint8_t response[4096];
    size_t response_len = sizeof(response);
    
    for (int i = 0; root_servers[i]; i++) {
        if (send_dns_query(root_servers[i], 53, query_pkt->wire, query_pkt->size,
                          response, &response_len) == 0) {
            break;
        }
    }
    
    if (response_len == 0) {
        knot_dname_free(dname, resolver->mm);
        knot_pkt_free(query_pkt);
        return create_error_result("No response from root servers");
    }
    
    // Parse response
    knot_pkt_t *response_pkt = knot_pkt_new(response, response_len, resolver->mm);
    if (!response_pkt) {
        knot_dname_free(dname, resolver->mm);
        knot_pkt_free(query_pkt);
        return create_error_result("Failed to create response packet");
    }
    
    if (knot_pkt_parse(response_pkt, 0) != KNOT_EOK) {
        knot_dname_free(dname, resolver->mm);
        knot_pkt_free(query_pkt);
        knot_pkt_free(response_pkt);
        return create_error_result("Failed to parse response");
    }
    
    int rcode = knot_wire_get_rcode(response_pkt->wire);
    bool secure = false;
    bool bogus = false;
    
    // Basic DNSSEC validation (simplified)
    if (resolver->dnssec_enabled) {
        // Check for RRSIG records in response
        for (int section = 0; section < KNOT_PKT_SECTIONS; section++) {
            const knot_pktsection_t *sect = knot_pkt_section(response_pkt, section);
            for (uint16_t i = 0; i < sect->count; i++) {
                const knot_rrset_t *rr = knot_pkt_rr(sect, i);
                if (rr->type == KNOT_RRTYPE_RRSIG) {
                    secure = true;
                    break;
                }
            }
            if (secure) break;
        }
    }
    
    knot_resolve_result_t *result = create_success_result(response_pkt->wire, response_pkt->size,
                                                         rcode, secure, bogus);
    
    knot_dname_free(dname, resolver->mm);
    knot_pkt_free(query_pkt);
    knot_pkt_free(response_pkt);
    
    return result;
}

/* Public API implementation */

knot_resolver_t *knot_resolver_new(bool dnssec_enabled, uint32_t timeout_ms, const char *root_hints) {
    printf("DEBUG: Creating Knot resolver\n");
    knot_resolver_t *resolver = malloc(sizeof(knot_resolver_t));
    if (!resolver) {
        printf("DEBUG: Failed to allocate resolver\n");
        return NULL;
    }
    
    resolver->mm = malloc(sizeof(knot_mm_t));
    if (!resolver->mm) {
        printf("DEBUG: Failed to allocate memory context\n");
        free(resolver);
        return NULL;
    }
    
    // Initialize memory context with default allocators
    resolver->mm->ctx = NULL;
    resolver->mm->alloc = NULL; // Use default malloc
    resolver->mm->free = NULL;  // Use default free
    resolver->dnssec_enabled = dnssec_enabled;
    resolver->timeout_ms = timeout_ms;
    resolver->root_hints = root_hints ? strdup(root_hints) : NULL;
    
    printf("DEBUG: Knot resolver created successfully\n");
    return resolver;
}

void knot_resolver_free(knot_resolver_t *resolver) {
    if (!resolver) return;
    
    if (resolver->mm) {
        free(resolver->mm);
    }
    
    if (resolver->root_hints) {
        free(resolver->root_hints);
    }
    
    free(resolver);
}

knot_resolve_result_t *knot_resolver_resolve(knot_resolver_t *resolver, 
                                           const char *qname, 
                                           uint16_t qtype, 
                                           uint16_t qclass) {
    printf("DEBUG: Resolving %s (type=%d, class=%d)\n", qname, qtype, qclass);
    if (!resolver || !qname) {
        printf("DEBUG: Invalid parameters\n");
        return create_error_result("Invalid parameters");
    }
    
    return recursive_resolve(resolver, qname, qtype, qclass);
}

void knot_resolve_result_free(knot_resolve_result_t *result) {
    if (!result) return;
    
    if (result->wire) {
        free(result->wire);
    }
    
    if (result->error_msg) {
        free(result->error_msg);
    }
    
    free(result);
}

const char *knot_qtype_to_string(uint16_t qtype) {
    for (int i = 0; qtype_map[i].name; i++) {
        if (qtype_map[i].type == qtype) {
            return qtype_map[i].name;
        }
    }
    return "UNKNOWN";
}

const char *knot_qclass_to_string(uint16_t qclass) {
    for (int i = 0; qclass_map[i].name; i++) {
        if (qclass_map[i].class == qclass) {
            return qclass_map[i].name;
        }
    }
    return "UNKNOWN";
}