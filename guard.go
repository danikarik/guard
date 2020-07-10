package guard

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	uuid "github.com/satori/go.uuid"
)

var (
	ErrEmptySecret  = errors.New("guard: empty signing secret")
	ErrEmptySubject = errors.New("guard: empty subject")
)

const (
	_defaultAccessCookieName = "guard_token"
	_defaultCSRFCookieName   = "XSRF-TOKEN"
	_defaultCookiePath       = "/"
	_defaultCookieTime       = 7 * 24 * time.Hour
)

type Guard struct {
	secret []byte
	secure bool

	accessCookieName string
	csrfCookieName   string

	issuer string
	path   string
	domain string
	ttl    time.Duration
}

func NewGuard(secret []byte, opts ...GuardOption) (*Guard, error) {
	if len(secret) == 0 {
		return nil, ErrEmptySecret
	}

	// Set default.
	guard := &Guard{
		secret:           secret,
		secure:           true,
		accessCookieName: _defaultAccessCookieName,
		csrfCookieName:   _defaultCSRFCookieName,
		path:             _defaultCookiePath,
		ttl:              _defaultCookieTime,
	}

	// Apply options.
	for _, opt := range opts {
		if err := opt.apply(guard); err != nil {
			return nil, err
		}
	}

	return guard, nil
}

func (g *Guard) saveCookies(w http.ResponseWriter, cookies ...*http.Cookie) error {
	for _, cookie := range cookies {
		http.SetCookie(w, cookie)
	}
	return nil
}

func (g *Guard) Authenticate(w http.ResponseWriter, subject string) error {
	if subject == "" {
		return ErrEmptySubject
	}

	claims := &UserClaims{
		StandardClaims: &jwt.StandardClaims{
			Subject:   subject,
			Issuer:    g.issuer,
			ExpiresAt: jwt.TimeFunc().UTC().Add(g.ttl).Unix(),
		},
		CSRFToken: base64.RawURLEncoding.EncodeToString(uuid.NewV4().Bytes()),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(g.secret)
	if err != nil {
		return fmt.Errorf("guard: signing token %w", err)
	}

	return g.saveCookies(w,
		&http.Cookie{
			Name:     g.accessCookieName,
			Value:    signed,
			Path:     g.path,
			Domain:   g.domain,
			Expires:  time.Now().UTC().Add(g.ttl),
			Secure:   g.secure,
			HttpOnly: true,
		},
		&http.Cookie{
			Name:     g.csrfCookieName,
			Value:    claims.CSRFToken,
			Path:     g.path,
			Domain:   g.domain,
			Expires:  time.Now().UTC().Add(g.ttl),
			Secure:   g.secure,
			HttpOnly: false,
		},
	)
}
