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

const (
	_defaultAccessCookieName = "guard_token"
	_defaultCSRFCookieName   = "XSRF-TOKEN"
	_defaultCSRFHeaderName   = "X-XSRF-TOKEN"
	_defaultCookiePath       = "/"
	_defaultCookieTime       = 7 * 24 * time.Hour
)

var (
	// ErrEmptySecret when NewGuard takes empty secret.
	ErrEmptySecret = errors.New("guard: empty signing secret")
	// ErrEmptySubject when Authenticate takes empty subject.
	ErrEmptySubject = errors.New("guard: empty subject")
	// ErrInvalidAccessToken when Validate cannot get access token cookie.
	ErrInvalidAccessToken = errors.New("guard: missing or malformed access token")
	// ErrInvalidCSRFToken when Validate cannot get csrf token or token mismatches with original.
	ErrInvalidCSRFToken = errors.New("guard: missing or invalid csrf token")
	// ErrUnexpectedSigningMethod when signing method differs from default.
	ErrUnexpectedSigningMethod = errors.New("guard: unexpected signing method")
)

// Guard is used to authenticate response and validate request.
type Guard struct {
	secret           []byte
	secure           bool
	accessCookieName string
	csrfCookieName   string
	csrfHeaderName   string
	issuer           string
	path             string
	domain           string
	ttl              time.Duration
}

// NewGuard returns a new instance of Guard.
func NewGuard(secret []byte, opts ...Option) (*Guard, error) {
	if len(secret) == 0 {
		return nil, ErrEmptySecret
	}

	// Set default.
	guard := &Guard{
		secret:           secret,
		secure:           true,
		accessCookieName: _defaultAccessCookieName,
		csrfCookieName:   _defaultCSRFCookieName,
		csrfHeaderName:   _defaultCSRFHeaderName,
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

func (g *Guard) getSigningSecret(token *jwt.Token) (interface{}, error) {
	if token.Method != jwt.SigningMethodHS256 {
		return nil, ErrUnexpectedSigningMethod
	}
	return g.secret, nil
}

// Authenticate saves subject into access token cookie with csrf token.
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

	// Response with CSRF token in header.
	w.Header().Set(g.csrfHeaderName, claims.CSRFToken)

	// Save access token and CSRF cookies.
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

// Validate incoming request and returns extracted subject.
func (g *Guard) Validate(r *http.Request) (string, error) {
	cookie, err := r.Cookie(g.accessCookieName)
	if errors.Is(err, http.ErrNoCookie) {
		return "", ErrInvalidAccessToken
	}
	if err != nil {
		return "", err
	}
	if cookie.Value == "" {
		return "", ErrInvalidAccessToken
	}

	claims := &UserClaims{}
	token, err := jwt.ParseWithClaims(cookie.Value, claims, g.getSigningSecret)
	if err != nil {
		return "", ErrInvalidAccessToken
	}
	if err := token.Claims.Valid(); err != nil {
		return "", ErrInvalidAccessToken
	}

	header := r.Header.Get(g.csrfHeaderName)
	if header == "" || header != claims.CSRFToken {
		return "", ErrInvalidCSRFToken
	}

	return claims.Subject, nil
}
