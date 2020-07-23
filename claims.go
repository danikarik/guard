package guard

import (
	"errors"

	"github.com/dgrijalva/jwt-go"
)

var (
	// ErrNilStandardClaims returned by UserClaims.Valid if there is no standard claims found.
	ErrNilStandardClaims = errors.New("guard: standard claims cannot be nil")
	// ErrEmptyCSRFToken returned by UserClaims.Valid if csrf token is empty.
	ErrEmptyCSRFToken = errors.New("guard: empty CSRF token")
)

// UserClaims holds default jwt claims and csrf token.
type UserClaims struct {
	*jwt.StandardClaims

	CSRFToken string `json:"csrfToken"`
}

// Valid checks whether claims are valid or not.
func (c *UserClaims) Valid() error {
	if c.StandardClaims == nil {
		return ErrNilStandardClaims
	}
	if c.CSRFToken == "" {
		return ErrEmptyCSRFToken
	}
	return nil
}
