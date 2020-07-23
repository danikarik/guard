package guard_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/danikarik/guard"
)

// Example is a package-level documentation example.
func Example() {
	var (
		secret           = []byte("9ae55e7ad6c6d3a78312567840588eff0ece5a9be9e2d6e36a6e5b5547361ecb")
		userID           = "user_id"
		accessCookieName = "access_token"
		csrfCookieName   = "csrf_token"
		csrfHeaderName   = "X-CSRF-TOKEN"
	)

	// Create a new guard instance with unsecured cookie for testing purpose.
	grd, _ := guard.NewGuard(secret,
		guard.WithAccessCookieName(accessCookieName),
		guard.WithCSRFCookieName(csrfCookieName),
		guard.WithCSRFHeaderName(csrfHeaderName),
		guard.WithSecure(false),
	)

	// mainHandler responds 200
	var mainHandler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	// loginHandler sets auth cookie.
	var loginHandler = func(w http.ResponseWriter, r *http.Request) {
		if err := grd.Authenticate(w, userID); err != nil {
			http.Error(w, "cannot set cookie", http.StatusBadRequest)
			return
		}
	}

	// protected responds 200 if cookie is set
	var protectedHandler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	// auth middleware checks cookie with guard instance.
	var authRequired = func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/protected" {
				next.ServeHTTP(w, r)
				return
			}

			sub, err := grd.Validate(r)
			if err != nil {
				switch err {
				case guard.ErrInvalidAccessToken:
					http.Error(w, "invalid access token", http.StatusUnauthorized)
					return
				case guard.ErrInvalidCSRFToken:
					http.Error(w, "invalid csrf token", http.StatusBadRequest)
					return
				default:
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
			}

			// Lookup subject
			if sub != userID {
				http.Error(w, "invalid user id", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}

	// Create a new router.
	mux := http.NewServeMux()
	mux.HandleFunc("/", mainHandler)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/protected", protectedHandler)

	// Insert our middleware before the router
	handlerChain := authRequired(mux)

	// Request public endpoint
	req, _ := http.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	handlerChain.ServeHTTP(rr, req)

	fmt.Println(rr.Code)

	// Request protected endpoint without cookie
	req, _ = http.NewRequest("GET", "/protected", nil)
	rr = httptest.NewRecorder()
	handlerChain.ServeHTTP(rr, req)

	fmt.Println(rr.Code)

	// Request login endpoint
	req, _ = http.NewRequest("GET", "/login", nil)
	rr = httptest.NewRecorder()
	handlerChain.ServeHTTP(rr, req)

	// Set access and csrf cookie and repeat request
	req, _ = http.NewRequest("GET", "/protected", nil)
	for _, cookie := range rr.Result().Cookies() {
		if cookie.Name == csrfCookieName {
			// Set csrf cookie value into header
			req.Header.Set(csrfHeaderName, cookie.Value)
		} else {
			// Save access token cookie
			req.AddCookie(cookie)
		}
	}
	rr = httptest.NewRecorder()
	handlerChain.ServeHTTP(rr, req)

	fmt.Println(rr.Code)

	// Output: 200
	// 401
	// 200
}
