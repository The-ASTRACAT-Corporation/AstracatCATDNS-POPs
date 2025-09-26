module dns-resolver

go 1.24.0

toolchain go1.24.3

require (
	github.com/davecgh/go-spew v1.1.1
	github.com/miekg/dns v1.1.68
	github.com/nsmithuk/resolver v0.0.0-20250623062907-a1d51ff98c12
	golang.org/x/sync v0.17.0
)

require (
	github.com/google/uuid v1.6.0 // indirect
	github.com/nsmithuk/dnssec-root-anchors-go v1.2.0 // indirect
	golang.org/x/mod v0.28.0 // indirect
	golang.org/x/net v0.44.0 // indirect
	golang.org/x/sys v0.36.0 // indirect
	golang.org/x/tools v0.37.0 // indirect
)

replace github.com/nsmithuk/resolver => github.com/ASTRACAT2022/resolver v0.0.0-20250926081852-636e9e1ad13c
