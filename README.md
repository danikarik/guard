# Guard

Guard provides a mechanism for authentication.

## Usage

```go
// main.go
package main

import (
        "net/http"
        "time"

        "github.com/danikarik/guard"
)

func main() {
    grd, _ := guard.NewGuard([]byte("some secret")

    var mainHandler = func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
    }

    var loginHandler = func(w http.ResponseWriter, r *http.Request) {
        if err := grd.Authenticate(w, "user_id"); err != nil {
            http.Error(w, "cannot set cookie", http.StatusBadRequest)
            return
        }
    }

    var protectedHandler = func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
    }

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
            if sub != "user_id" {
                http.Error(w, "invalid user id", http.StatusUnauthorized)
                return
            }

            next.ServeHTTP(w, r)
        })
    }

    mux := http.NewServeMux()
    mux.HandleFunc("/", mainHandler)
    mux.HandleFunc("/login", loginHandler)
    mux.HandleFunc("/protected", protectedHandler)

    http.ListenAndServe(":8000", authRequired(mux))
}
```

## Maintainers

[@danikarik](https://github.com/danikarik)

## License

This project is licensed under the [MIT License](LICENSE).
