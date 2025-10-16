// Package knot provides Go bindings for Knot DNS resolver.
package knot

/*
#cgo pkg-config: libknot
#cgo LDFLAGS: -lknot -ldnssec -lgnutls -lm
#include "knot_resolver.h"
#include <stdlib.h>
*/
import "C"
import (
	"context"
	"errors"
	"time"
	"unsafe"
)

// Resolver represents a Knot DNS resolver instance.
type Resolver struct {
	ptr *C.knot_resolver_t
}

// ResolveResult represents the result of a DNS resolution.
type ResolveResult struct {
	Wire      []byte
	Rcode     int
	Secure    bool
	Bogus     bool
	ErrorMsg  string
}

// NewResolver creates a new Knot resolver instance.
func NewResolver(dnssecEnabled bool, timeout time.Duration, rootHints string) (*Resolver, error) {
	var rootHintsC *C.char
	if rootHints != "" {
		rootHintsC = C.CString(rootHints)
		defer C.free(unsafe.Pointer(rootHintsC))
	}

	timeoutMs := C.uint32_t(timeout.Milliseconds())
	dnssecC := C.bool(dnssecEnabled)

	ptr := C.knot_resolver_new(dnssecC, timeoutMs, rootHintsC)
	if ptr == nil {
		return nil, errors.New("failed to create Knot resolver")
	}

	return &Resolver{ptr: ptr}, nil
}

// Close frees the resolver resources.
func (r *Resolver) Close() {
	if r.ptr != nil {
		C.knot_resolver_free(r.ptr)
		r.ptr = nil
	}
}

// Resolve performs a DNS resolution.
func (r *Resolver) Resolve(ctx context.Context, qname string, qtype, qclass uint16) (*ResolveResult, error) {
	if r.ptr == nil {
		return nil, errors.New("resolver is closed")
	}

	// Check context cancellation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	qnameC := C.CString(qname)
	defer C.free(unsafe.Pointer(qnameC))

	qtypeC := C.uint16_t(qtype)
	qclassC := C.uint16_t(qclass)

	result := C.knot_resolver_resolve(r.ptr, qnameC, qtypeC, qclassC)
	if result == nil {
		return nil, errors.New("resolution failed")
	}
	defer C.knot_resolve_result_free(result)

	// Convert C result to Go result
	res := &ResolveResult{
		Rcode:    int(result.rcode),
		Secure:   bool(result.secure),
		Bogus:    bool(result.bogus),
	}

	// Copy wire data
	if result.wire_size > 0 {
		res.Wire = C.GoBytes(unsafe.Pointer(result.wire), C.int(result.wire_size))
	}

	// Copy error message
	if result.error_msg != nil {
		res.ErrorMsg = C.GoString(result.error_msg)
	}

	// Check for errors
	if res.ErrorMsg != "" {
		return res, errors.New(res.ErrorMsg)
	}

	return res, nil
}

// QTypeToString converts a DNS query type to string.
func QTypeToString(qtype uint16) string {
	qtypeC := C.uint16_t(qtype)
	return C.GoString(C.knot_qtype_to_string(qtypeC))
}

// QClassToString converts a DNS query class to string.
func QClassToString(qclass uint16) string {
	qclassC := C.uint16_t(qclass)
	return C.GoString(C.knot_qclass_to_string(qclassC))
}

// Ensure Resolver implements the resolver interface
var _ ResolverInterface = (*Resolver)(nil)

// ResolverInterface defines the interface for DNS resolvers.
type ResolverInterface interface {
	Resolve(ctx context.Context, qname string, qtype, qclass uint16) (*ResolveResult, error)
	Close()
}