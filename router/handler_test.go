/*
Package router : authorize and authenticate HTTP Request using HTTP Header.

	license: Apache license 2.0
	copyright: Nobuyuki Matsui <nobuyuki.matsui@gmail.com>
*/
package router

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	"github.com/tech-sketch/fiware-bearer-auth/token"
)

var METHODS = [...]string{"GET", "POST", "PUT", "PATHC", "DELETE", "HEAD"}

func setUp(t *testing.T) (func(string, string, string) (*http.Response, error), func()) {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)

	var ts *httptest.Server
	c := http.DefaultClient
	doRequest := func(method string, path string, authHeader string) (*http.Response, error) {
		handler := NewHandler()
		ts = httptest.NewServer(handler.Engine)
		r, err := http.NewRequest(method, ts.URL+path, nil)
		if err != nil {
			t.Errorf("NewRequest Error. %v", err)
		}
		if len(authHeader) != 0 {
			r.Header.Add("Authorization", authHeader)
		}
		return c.Do(r)
	}
	tearDown := func() {
		os.Unsetenv(token.AuthTokens)
		ts.Close()
	}
	return doRequest, tearDown
}

func TestNewHandlerWithValidTokens(t *testing.T) {
	assert := assert.New(t)
	doRequest, tearDown := setUp(t)
	defer tearDown()

	json := `
	{
		"TOKEN1": ["^/foo/\\d+/*", "^/bar/*"],
		"TOKEN2": ["^/bar/*"],
		"TOKEN3": []
	}
	`
	os.Setenv(token.AuthTokens, json)

	t.Run("without Header", func(t *testing.T) {
		cases := []struct {
			path       string
			statusCode int
			desc       string
		}{
			{path: "/", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
			{path: "/some", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
			{path: "/foo/1/", statusCode: http.StatusUnauthorized, desc: "return 401 when when Authorization header is not set"},
			{path: "/foo/a/", statusCode: http.StatusUnauthorized, desc: "return 401 when when Authorization header is not set"},
			{path: "/bar/1/", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
			{path: "/bar/a/", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
		}

		for _, method := range METHODS {
			for _, c := range cases {
				t.Run(fmt.Sprintf("?method=%v&path=%v", method, c.path), func(t *testing.T) {
					r, err := doRequest(method, c.path, "")
					assert.Nil(err, "Get has no error")
					assert.Equal(r.StatusCode, c.statusCode, c.desc)
				})
			}
		}
	})

	t.Run("with TOKEN1", func(t *testing.T) {
		cases := []struct {
			path       string
			statusCode int
			desc       string
		}{
			{path: "/", statusCode: http.StatusForbidden, desc: `returns 403 because "/" is not allowed`},
			{path: "/some", statusCode: http.StatusForbidden, desc: `returns 403 because "/some" is not allowed`},
			{path: "/foo/1/", statusCode: http.StatusOK, desc: "return 200"},
			{path: "/foo/a/", statusCode: http.StatusForbidden, desc: `returns 403 because "/foo/a/" is not allowed`},
			{path: "/bar/1/", statusCode: http.StatusOK, desc: "return 200"},
			{path: "/bar/a/", statusCode: http.StatusOK, desc: "return 200"},
		}

		for _, method := range METHODS {
			for _, c := range cases {
				t.Run(fmt.Sprintf("?method=%v&path=%v", method, c.path), func(t *testing.T) {
					r, err := doRequest(method, c.path, "bearer TOKEN1")
					assert.Nil(err, "Get has no error")
					assert.Equal(r.StatusCode, c.statusCode, c.desc)
				})
			}
		}
	})

	t.Run("with TOKEN2", func(t *testing.T) {
		cases := []struct {
			path       string
			statusCode int
			desc       string
		}{
			{path: "/", statusCode: http.StatusForbidden, desc: `returns 403 because "/" is not allowed`},
			{path: "/some", statusCode: http.StatusForbidden, desc: `returns 403 because "/some" is not allowed`},
			{path: "/foo/1/", statusCode: http.StatusForbidden, desc: `returns 403 because "/foo/a/" is not allowed`},
			{path: "/foo/a/", statusCode: http.StatusForbidden, desc: `returns 403 because "/foo/a/" is not allowed`},
			{path: "/bar/1/", statusCode: http.StatusOK, desc: "return 200"},
			{path: "/bar/a/", statusCode: http.StatusOK, desc: "return 200"},
		}

		for _, method := range METHODS {
			for _, c := range cases {
				t.Run(fmt.Sprintf("?method=%v&path=%v", method, c.path), func(t *testing.T) {
					r, err := doRequest(method, c.path, "bearer TOKEN2")
					assert.Nil(err, "Get has no error")
					assert.Equal(r.StatusCode, c.statusCode, c.desc)
				})
			}
		}
	})

	t.Run("with TOKEN3", func(t *testing.T) {
		cases := []struct {
			path       string
			statusCode int
			desc       string
		}{
			{path: "/", statusCode: http.StatusForbidden, desc: `returns 403 because "/" is not allowed`},
			{path: "/some", statusCode: http.StatusForbidden, desc: `returns 403 because "/some" is not allowed`},
			{path: "/foo/1/", statusCode: http.StatusForbidden, desc: `returns 403 because "/foo/a/" is not allowed`},
			{path: "/foo/a/", statusCode: http.StatusForbidden, desc: `returns 403 because "/foo/a/" is not allowed`},
			{path: "/bar/1/", statusCode: http.StatusForbidden, desc: `returns 403 because "/bar/a/" is not allowed`},
			{path: "/bar/a/", statusCode: http.StatusForbidden, desc: `returns 403 because "/bar/a/" is not allowed`},
		}

		for _, method := range METHODS {
			for _, c := range cases {
				t.Run(fmt.Sprintf("?method=%v&path=%v", method, c.path), func(t *testing.T) {
					r, err := doRequest(method, c.path, "bearer TOKEN3")
					assert.Nil(err, "Get has no error")
					assert.Equal(r.StatusCode, c.statusCode, c.desc)
				})
			}
		}
	})

	t.Run("with not existing token", func(t *testing.T) {
		cases := []struct {
			path       string
			statusCode int
			desc       string
		}{
			{path: "/", statusCode: http.StatusUnauthorized, desc: "return 401 when not existing token is set"},
			{path: "/some", statusCode: http.StatusUnauthorized, desc: "return 401 when not existing token is set"},
			{path: "/foo/1/", statusCode: http.StatusUnauthorized, desc: "return 401 when not existing token is set"},
			{path: "/foo/a/", statusCode: http.StatusUnauthorized, desc: "return 401 when not existing token is set"},
			{path: "/bar/1/", statusCode: http.StatusUnauthorized, desc: "return 401 when not existing token is set"},
			{path: "/bar/a/", statusCode: http.StatusUnauthorized, desc: "return 401 when not existing token is set"},
		}

		for _, method := range METHODS {
			for _, c := range cases {
				t.Run(fmt.Sprintf("?method=%v&path=%v", method, c.path), func(t *testing.T) {
					r, err := doRequest(method, c.path, "bearer TOKEN4")
					assert.Nil(err, "Get has no error")
					assert.Equal(r.StatusCode, c.statusCode, c.desc)
				})
			}
		}
	})

	t.Run(`without "bearer" keyword`, func(t *testing.T) {
		cases := []struct {
			path       string
			statusCode int
			desc       string
		}{
			{path: "/", statusCode: http.StatusUnauthorized, desc: `return 401 when "bearer" keyword is missing`},
			{path: "/some", statusCode: http.StatusUnauthorized, desc: `return 401 when "bearer" keyword is missing`},
			{path: "/foo/1/", statusCode: http.StatusUnauthorized, desc: `return 401 when "bearer" keyword is missing`},
			{path: "/foo/a/", statusCode: http.StatusUnauthorized, desc: `return 401 when "bearer" keyword is missing`},
			{path: "/bar/1/", statusCode: http.StatusUnauthorized, desc: `return 401 when "bearer" keyword is missing`},
			{path: "/bar/a/", statusCode: http.StatusUnauthorized, desc: `return 401 when "bearer" keyword is missing`},
		}

		for _, method := range METHODS {
			for _, c := range cases {
				t.Run(fmt.Sprintf("?method=%v&path=%v", method, c.path), func(t *testing.T) {
					r, err := doRequest(method, c.path, "TOKEN1")
					assert.Nil(err, "Get has no error")
					assert.Equal(r.StatusCode, c.statusCode, c.desc)
				})
			}
		}
	})

}

func TestNewHandlerNoEnv(t *testing.T) {
	assert := assert.New(t)
	doRequest, tearDown := setUp(t)
	defer tearDown()

	t.Run("without Header", func(t *testing.T) {
		cases := []struct {
			path       string
			statusCode int
			desc       string
		}{
			{path: "/", statusCode: http.StatusUnauthorized, desc: "Get returns 401 when AUTH_TOKENS is not set"},
			{path: "/some", statusCode: http.StatusUnauthorized, desc: "Get returns 401 when AUTH_TOKENS is not set"},
			{path: "/foo/1/", statusCode: http.StatusUnauthorized, desc: "Get returns 401 when AUTH_TOKENS is not set"},
			{path: "/foo/a/", statusCode: http.StatusUnauthorized, desc: "Get returns 401 when AUTH_TOKENS is not set"},
			{path: "/bar/1/", statusCode: http.StatusUnauthorized, desc: "Get returns 401 when AUTH_TOKENS is not set"},
		}

		for _, method := range METHODS {
			for _, c := range cases {
				t.Run(fmt.Sprintf("?method=%v&path=%v", method, c.path), func(t *testing.T) {
					r, err := doRequest(method, c.path, "")
					assert.Nil(err, "Get has no error")
					assert.Equal(r.StatusCode, c.statusCode, c.desc)
				})
			}
		}
	})

	t.Run("with TOKEN1", func(t *testing.T) {
		cases := []struct {
			path       string
			statusCode int
			desc       string
		}{
			{path: "/", statusCode: http.StatusUnauthorized, desc: "Get returns 401 when AUTH_TOKENS is not set"},
			{path: "/some", statusCode: http.StatusUnauthorized, desc: "Get returns 401 when AUTH_TOKENS is not set"},
			{path: "/foo/1/", statusCode: http.StatusUnauthorized, desc: "Get returns 401 when AUTH_TOKENS is not set"},
			{path: "/foo/a/", statusCode: http.StatusUnauthorized, desc: "Get returns 401 when AUTH_TOKENS is not set"},
			{path: "/bar/1/", statusCode: http.StatusUnauthorized, desc: "Get returns 401 when AUTH_TOKENS is not set"},
		}

		for _, method := range METHODS {
			for _, c := range cases {
				t.Run(fmt.Sprintf("?method=%v&path=%v", method, c.path), func(t *testing.T) {
					r, err := doRequest(method, c.path, "bearer TOKEN1")
					assert.Nil(err, "Get has no error")
					assert.Equal(r.StatusCode, c.statusCode, c.desc)
				})
			}
		}
	})
}
