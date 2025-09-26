// go.mod
module dns-resolver

go 1.24.0

toolchain go1.24.3

require (
	github.com/davecgh/go-spew v1.1.1
	github.com/miekg/dns v1.1.68
	github.com/nsmithuk/resolver v0.0.0-20250623062907-a1d51ff98c12
	golang.org/x/sync v0.17.0
)

replace github.com/nsmithuk/resolver => github.com/ASTRACAT2022/resolver v0.0.0-20250926081852-636e9e1ad13c