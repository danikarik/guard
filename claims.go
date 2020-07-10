package guard

import (
	"errors"

	"github.com/dgrijalva/jwt-go"
)

var (
	ErrNilStandardClaims = errors.New("guard: standard claims cannot be nil")
	ErrEmptyCSRFToken    = errors.New("guard: empty CSRF token")
)

type UserClaims struct {
	*jwt.StandardClaims

	CSRFToken string `json:"csrfToken"`
}

func (c *UserClaims) Valid() error {
	if c.StandardClaims == nil {
		return ErrNilStandardClaims
	}
	if c.CSRFToken == "" {
		return ErrEmptyCSRFToken
	}
	return nil
}
