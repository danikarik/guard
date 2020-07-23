package guard

import (
	"errors"
	"strings"
	"time"
)

var (
	// ErrEmptyCookieName raises if WithAccessCookieName or WithCSRFCookieName gets empty cookie name.
	ErrEmptyCookieName = errors.New("guard: cookie name cannot be blank")
	// ErrEmptyHeaderName raises if WithCSRFHeaderName gets empty header name.
	ErrEmptyHeaderName = errors.New("guard: header name cannot be blank")
	// ErrInvalidCookiePath raises if WithPath gets invalid cookie path.
	ErrInvalidCookiePath = errors.New("guard: invalid cookie path")
	// ErrInvalidCookieTTL raises if WithTTL gets zero cookie expiration duration.
	ErrInvalidCookieTTL = errors.New("guard: cookie expiration cannot be zero")
)

// Option configures a Guard.
type Option interface {
	apply(g *Guard) error
}

type secureOption bool

func (o secureOption) apply(g *Guard) error {
	g.secure = bool(o)
	return nil
}

// WithSecure sets cookie secure flag.
func WithSecure(flag bool) Option {
	return secureOption(flag)
}

type accessCookieOption string

func (o accessCookieOption) apply(g *Guard) error {
	val := string(o)
	if val == "" {
		return ErrEmptyCookieName
	}
	g.accessCookieName = val
	return nil
}

// WithAccessCookieName sets access cookie name.
func WithAccessCookieName(name string) Option {
	return accessCookieOption(name)
}

type csrfCookieOption string

func (o csrfCookieOption) apply(g *Guard) error {
	val := string(o)
	if val == "" {
		return ErrEmptyCookieName
	}
	g.csrfCookieName = val
	return nil
}

// WithCSRFCookieName sets csrf cookie name.
func WithCSRFCookieName(name string) Option {
	return csrfCookieOption(name)
}

type csrfHeaderOption string

func (o csrfHeaderOption) apply(g *Guard) error {
	val := string(o)
	if val == "" {
		return ErrEmptyHeaderName
	}
	g.csrfHeaderName = val
	return nil
}

// WithCSRFHeaderName sets csrf header name.
func WithCSRFHeaderName(name string) Option {
	return csrfHeaderOption(name)
}

type pathOption string

func (o pathOption) apply(g *Guard) error {
	val := string(o)
	if val == "" || !strings.HasPrefix(val, "/") {
		return ErrInvalidCookiePath
	}
	g.path = val
	return nil
}

// WithPath sets cookie path.
func WithPath(path string) Option {
	return pathOption(path)
}

type issuerOption string

func (o issuerOption) apply(g *Guard) error {
	g.issuer = string(o)
	return nil
}

// WithIssuer sets jwt token issuer.
func WithIssuer(name string) Option {
	return issuerOption(name)
}

type domainOption string

func (o domainOption) apply(g *Guard) error {
	g.domain = string(o)
	return nil
}

// WithDomain sets cookie domain.
func WithDomain(name string) Option {
	return domainOption(name)
}

type ttlOption time.Duration

func (o ttlOption) apply(g *Guard) error {
	val := time.Duration(o)
	if val == 0 {
		return ErrInvalidCookieTTL
	}
	g.ttl = val
	return nil
}

// WithTTL sets cookie expiration time.
func WithTTL(ttl time.Duration) Option {
	return ttlOption(ttl)
}
