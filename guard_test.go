package guard_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/danikarik/guard"
	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/require"
)

func TestAuthenticate(t *testing.T) {
	testCases := []struct {
		Name             string
		Secure           bool
		AccessCookieName string
		CSRFCookieName   string
		Path             string
		Domain           string
		TTL              time.Duration
	}{
		{
			Name:   "WithSecure",
			Secure: true,
		},
		{
			Name:             "WithAccessCookieName",
			AccessCookieName: "access_token",
		},
		{
			Name:             "WithCSRFCookieName",
			AccessCookieName: "CSRF-TOKEN",
		},
		{
			Name: "WithPath",
			Path: "/main",
		},
		{
			Name:   "WithDomain",
			Domain: "guard.net",
		},
		{
			Name: "WithTTL",
			TTL:  24 * 1 * time.Hour,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			r := require.New(t)

			opts := []guard.GuardOption{}
			if tc.Secure {
				opts = append(opts, guard.WithSecure(true))
			}
			if tc.AccessCookieName != "" {
				opts = append(opts, guard.WithAccessCookieName(tc.AccessCookieName))
			}
			if tc.CSRFCookieName != "" {
				opts = append(opts, guard.WithCSRFCookieName(tc.CSRFCookieName))
			}
			if tc.Path != "" {
				opts = append(opts, guard.WithPath(tc.Path))
			}
			if tc.Domain != "" {
				opts = append(opts, guard.WithDomain(tc.Domain))
			}
			if tc.TTL > 0 {
				opts = append(opts, guard.WithTTL(tc.TTL))
			}

			guarder, err := guard.NewGuard([]byte("test"), opts...)
			r.NoError(err)

			w := httptest.NewRecorder()
			err = guarder.Authenticate(w, "user_id")
			r.NoError(err)

			resp := w.Result()
			r.Len(resp.Cookies(), 2)

			var (
				accessCookie *http.Cookie
				csrfCookie   *http.Cookie
			)

			for _, cookie := range resp.Cookies() {
				switch {
				case tc.AccessCookieName != "" && cookie.Name == tc.AccessCookieName:
					accessCookie = cookie
				case cookie.Name == "guard_token":
					accessCookie = cookie
				case tc.CSRFCookieName != "" && cookie.Name == tc.CSRFCookieName:
					csrfCookie = cookie
				case cookie.Name == "XSRF-TOKEN":
					csrfCookie = cookie
				}
			}

			r.NotNil(accessCookie)
			r.NotNil(csrfCookie)

			var claims guard.UserClaims
			_, err = jwt.ParseWithClaims(accessCookie.Value, &claims, func(t *jwt.Token) (interface{}, error) {
				return []byte("test"), nil
			})
			r.NoError(err)

			r.True(accessCookie.HttpOnly)
			r.False(csrfCookie.HttpOnly)

			if tc.Secure {
				r.True(accessCookie.Secure)
				r.True(csrfCookie.Secure)
			}

			if tc.AccessCookieName != "" {
				r.Equal(tc.AccessCookieName, accessCookie.Name)
				r.NotEmpty(accessCookie.Value)
			}

			if tc.CSRFCookieName != "" {
				r.Equal(tc.CSRFCookieName, csrfCookie.Name)
				r.NotEmpty(csrfCookie.Value)
			}

			if tc.Path != "" {
				r.Equal(tc.Path, accessCookie.Path)
				r.Equal(tc.Path, csrfCookie.Path)
			} else {
				r.Equal("/", accessCookie.Path)
				r.Equal("/", csrfCookie.Path)
			}

			if tc.Domain != "" {
				r.Equal(tc.Domain, accessCookie.Domain)
				r.Equal(tc.Domain, csrfCookie.Domain)
			}

			if tc.TTL > 0 {
				now := time.Now().UTC()
				r.True(accessCookie.Expires.Before(now.Add(tc.TTL)))
				r.True(csrfCookie.Expires.Before(now.Add(tc.TTL)))
			}
		})
	}
}
