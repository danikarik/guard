package guard_test

import (
	"errors"
	"testing"

	"github.com/danikarik/guard"
	"github.com/stretchr/testify/require"
)

func TestGuardOptions(t *testing.T) {
	testCases := []struct {
		Name   string
		Option guard.GuardOption
		Err    error
	}{
		{
			Name:   "WithEmptyAccessCookieName",
			Option: guard.WithAccessCookieName(""),
			Err:    guard.ErrEmptyCookieName,
		},
		{
			Name:   "WithEmptyCSRFCookieName",
			Option: guard.WithCSRFCookieName(""),
			Err:    guard.ErrEmptyCookieName,
		},
		{
			Name:   "WithEmptyCSRFHeaderName",
			Option: guard.WithCSRFHeaderName(""),
			Err:    guard.ErrEmptyHeaderName,
		},
		{
			Name:   "WithEmptyPath",
			Option: guard.WithPath(""),
			Err:    guard.ErrInvalidCookiePath,
		},
		{
			Name:   "WithInvalidPath",
			Option: guard.WithPath("root"),
			Err:    guard.ErrInvalidCookiePath,
		},
		{
			Name:   "WithZeroTTL",
			Option: guard.WithTTL(0),
			Err:    guard.ErrInvalidCookieTTL,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			r := require.New(t)

			_, err := guard.NewGuard([]byte("test"), tc.Option)
			if tc.Err != nil {
				r.Error(err)
				r.True(errors.Is(tc.Err, err))
			} else {
				r.NoError(err)
			}
		})
	}
}
