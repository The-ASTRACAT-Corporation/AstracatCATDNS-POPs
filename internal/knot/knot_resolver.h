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

/*!
 * \file
 *
 * \brief Go CGO bindings for Knot DNS resolver.
 *
 * This file provides CGO bindings for integrating libknot with Go.
 * It implements a recursive DNS resolver with DNSSEC validation support.
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <libknot/libknot.h>
#include <libknot/packet/pkt.h>
#include <libknot/rrset.h>
#include <libknot/dname.h>
#include <libknot/wire.h>
#include <libknot/consts.h>
#include <libknot/errcode.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \brief DNS resolution result structure.
 */
typedef struct {
    uint8_t *wire;          /*!< Wire format response */
    size_t wire_size;       /*!< Size of wire format response */
    int rcode;              /*!< DNS response code */
    bool secure;            /*!< DNSSEC validation result */
    bool bogus;             /*!< DNSSEC validation failed */
    char *error_msg;        /*!< Error message if any */
} knot_resolve_result_t;

/*!
 * \brief Knot resolver context.
 */
typedef struct {
    knot_mm_t *mm;          /*!< Memory context */
    bool dnssec_enabled;    /*!< DNSSEC validation enabled */
    uint32_t timeout_ms;    /*!< Resolution timeout in milliseconds */
    char *root_hints;       /*!< Root hints file path */
} knot_resolver_t;

/*!
 * \brief Initialize Knot resolver context.
 *
 * \param dnssec_enabled Enable DNSSEC validation
 * \param timeout_ms Resolution timeout in milliseconds
 * \param root_hints Root hints file path (can be NULL)
 * \return New resolver context or NULL on error
 */
knot_resolver_t *knot_resolver_new(bool dnssec_enabled, uint32_t timeout_ms, const char *root_hints);

/*!
 * \brief Free Knot resolver context.
 *
 * \param resolver Resolver context to free
 */
void knot_resolver_free(knot_resolver_t *resolver);

/*!
 * \brief Resolve DNS query using Knot resolver.
 *
 * \param resolver Resolver context
 * \param qname Query name (NULL-terminated string)
 * \param qtype Query type (e.g., A, AAAA, MX, etc.)
 * \param qclass Query class (usually IN)
 * \return Resolution result (caller must free with knot_resolve_result_free)
 */
knot_resolve_result_t *knot_resolver_resolve(knot_resolver_t *resolver, 
                                           const char *qname, 
                                           uint16_t qtype, 
                                           uint16_t qclass);

/*!
 * \brief Free resolution result.
 *
 * \param result Result to free
 */
void knot_resolve_result_free(knot_resolve_result_t *result);

/*!
 * \brief Convert DNS type to string.
 *
 * \param qtype Query type
 * \return Type string or "UNKNOWN"
 */
const char *knot_qtype_to_string(uint16_t qtype);

/*!
 * \brief Convert DNS class to string.
 *
 * \param qclass Query class
 * \return Class string or "UNKNOWN"
 */
const char *knot_qclass_to_string(uint16_t qclass);

#ifdef __cplusplus
}
#endif