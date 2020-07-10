package guard

import "time"

type GuardOption interface {
	apply(g *Guard) error
}

type secureOption bool

func (o secureOption) apply(g *Guard) error {
	g.secure = bool(o)
	return nil
}

func WithSecure(flag bool) GuardOption {
	return secureOption(flag)
}

type accessCookieOption string

func (o accessCookieOption) apply(g *Guard) error {
	g.accessCookieName = string(o)
	return nil
}

func WithAccessCookieName(name string) GuardOption {
	return accessCookieOption(name)
}

type csrfCookieOption string

func (o csrfCookieOption) apply(g *Guard) error {
	g.csrfCookieName = string(o)
	return nil
}

func WithCSRFCookieName(name string) GuardOption {
	return csrfCookieOption(name)
}

type pathOption string

func (o pathOption) apply(g *Guard) error {
	g.path = string(o)
	return nil
}

func WithPath(path string) GuardOption {
	return pathOption(path)
}

type issuerOption string

func (o issuerOption) apply(g *Guard) error {
	g.issuer = string(o)
	return nil
}

func WithIssuer(name string) GuardOption {
	return issuerOption(name)
}

type domainOption string

func (o domainOption) apply(g *Guard) error {
	g.domain = string(o)
	return nil
}

func WithDomain(name string) GuardOption {
	return domainOption(name)
}

type ttlOption time.Duration

func (o ttlOption) apply(g *Guard) error {
	g.ttl = time.Duration(o)
	return nil
}

func WithTTL(ttl time.Duration) GuardOption {
	return ttlOption(ttl)
}
