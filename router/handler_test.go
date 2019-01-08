/*
Package router : authorize and authenticate HTTP Request using HTTP Header.

	license: Apache license 2.0
	copyright: Nobuyuki Matsui <nobuyuki.matsui@gmail.com>
*/
package router

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	"github.com/tech-sketch/fiware-ambassador-auth/token"
)

var METHODS = [...]string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"}

func getBasicAuthHeader(username string, password string) string {
	auth := username + ":" + password
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
}

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

	json := `[
		{
			"host": "127\\.0\\.0\\.1:.*",
			"settings": {
				"bearer_tokens": [
					{
						"token": "TOKEN1",
						"allowed_paths": ["^/foo/\\d+/*", "^/bar/*"]
					}, {
						"token": "TOKEN2",
						"allowed_paths": ["^/bar/*"]
					}, {
						"token": "TOKEN3",
						"allowed_paths": []
					}
				],
				"basic_auths": [
					{
						"username": "user1",
						"password": "password1",
						"allowed_paths": ["^/piyo/.+/.*", "/hoge/hoge", "^/huga/[hf].+$"]
					}, {
						"username": "user2",
						"password": "password2",
						"allowed_paths": ["/piyo/piyo/"]
					}, {
						"username": "user3",
						"password": "password3",
						"allowed_paths": []
					}
				],
				"no_auths": {
					"allowed_paths": ["^.*/static/.*$"]
				}
			}
		},
		{
			"host": "other\\.domain\\..*",
			"settings": {
				"bearer_tokens": [
					{
						"token": "TOKEN1",
						"allowed_paths": ["^/some"]
					}
				],
				"basic_auths": [
					{
						"username": "user1",
						"password": "password1",
						"allowed_paths": ["/zap"]
					}
				],
				"no_auths": {
					"allowed_paths": ["/sss/"]
				}
			}
		}
	]`
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
			{path: "/piyo/piyo/", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
			{path: "/hoge/hoge", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
			{path: "/huga/huga", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
			{path: "/zap", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
			{path: "/static", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
			{path: "/static/", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/static/foo", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/static/foo/bar.js", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/piyo/static", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
			{path: "/piyo/static/", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/piyo/static/foo", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/piyo/static/foo/bar.js", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/sss/", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
		}

		for _, method := range METHODS {
			for _, c := range cases {
				t.Run(fmt.Sprintf("?method=%v&path=%v", method, c.path), func(t *testing.T) {
					r, err := doRequest(method, c.path, "")
					assert.Nil(err, fmt.Sprintf("%s has no error", method))
					assert.Equal(c.statusCode, r.StatusCode, c.desc)
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
			{path: "/piyo/piyo/", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
			{path: "/hoge/hoge", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
			{path: "/huga/huga", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
			{path: "/zap", statusCode: http.StatusForbidden, desc: `returns 403 because "/zap" is not allowed`},
			{path: "/static", statusCode: http.StatusForbidden, desc: `returns 403 because "/static" is not allowed`},
			{path: "/static/", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/static/foo", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/static/foo/bar.js", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/piyo/static", statusCode: http.StatusForbidden, desc: `returns 403 because "/piyo/static" is not allowed`},
			{path: "/piyo/static/", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/piyo/static/foo", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/piyo/static/foo/bar.js", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/sss/", statusCode: http.StatusForbidden, desc: `returns 403 because "/sss/" is not allowed`},
		}

		for _, method := range METHODS {
			for _, c := range cases {
				t.Run(fmt.Sprintf("?method=%v&path=%v", method, c.path), func(t *testing.T) {
					r, err := doRequest(method, c.path, "bearer TOKEN1")
					assert.Nil(err, fmt.Sprintf("%s has no error", method))
					assert.Equal(c.statusCode, r.StatusCode, c.desc)
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
			{path: "/piyo/piyo/", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
			{path: "/hoge/hoge", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
			{path: "/huga/huga", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
			{path: "/zap", statusCode: http.StatusForbidden, desc: `returns 403 because "/zap" is not allowed`},
			{path: "/static", statusCode: http.StatusForbidden, desc: `returns 403 because "/static" is not allowed`},
			{path: "/static/", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/static/foo", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/static/foo/bar.js", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/piyo/static", statusCode: http.StatusForbidden, desc: `returns 403 because "/piyo/static" is not allowed`},
			{path: "/piyo/static/", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/piyo/static/foo", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/piyo/static/foo/bar.js", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/sss/", statusCode: http.StatusForbidden, desc: `returns 403 because "/sss/" is not allowed`},
		}

		for _, method := range METHODS {
			for _, c := range cases {
				t.Run(fmt.Sprintf("?method=%v&path=%v", method, c.path), func(t *testing.T) {
					r, err := doRequest(method, c.path, "bearer TOKEN2")
					assert.Nil(err, fmt.Sprintf("%s has no error", method))
					assert.Equal(c.statusCode, r.StatusCode, c.desc)
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
			{path: "/", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
			{path: "/some", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
			{path: "/foo/1/", statusCode: http.StatusUnauthorized, desc: "return 401 when when Authorization header is not set"},
			{path: "/foo/a/", statusCode: http.StatusUnauthorized, desc: "return 401 when when Authorization header is not set"},
			{path: "/bar/1/", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
			{path: "/bar/a/", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
			{path: "/piyo/piyo/", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
			{path: "/hoge/hoge", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
			{path: "/huga/huga", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
			{path: "/zap", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
			{path: "/static", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
			{path: "/static/", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/static/foo", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/static/foo/bar.js", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/piyo/static", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
			{path: "/piyo/static/", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/piyo/static/foo", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/piyo/static/foo/bar.js", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/sss/", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
		}

		for _, method := range METHODS {
			for _, c := range cases {
				t.Run(fmt.Sprintf("?method=%v&path=%v", method, c.path), func(t *testing.T) {
					r, err := doRequest(method, c.path, "bearer TOKEN3")
					assert.Nil(err, fmt.Sprintf("%s has no error", method))
					assert.Equal(c.statusCode, r.StatusCode, c.desc)
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
			{path: "/piyo/piyo/", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
			{path: "/hoge/hoge", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
			{path: "/huga/huga", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
			{path: "/zap", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
			{path: "/static", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
			{path: "/static/", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/static/foo", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/static/foo/bar.js", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/piyo/static", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
			{path: "/piyo/static/", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/piyo/static/foo", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/piyo/static/foo/bar.js", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/sss/", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
		}

		for _, method := range METHODS {
			for _, c := range cases {
				t.Run(fmt.Sprintf("?method=%v&path=%v", method, c.path), func(t *testing.T) {
					r, err := doRequest(method, c.path, "bearer TOKEN4")
					assert.Nil(err, fmt.Sprintf("%s has no error", method))
					assert.Equal(c.statusCode, r.StatusCode, c.desc)
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
			{path: "/piyo/piyo/", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
			{path: "/hoge/hoge", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
			{path: "/huga/huga", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
			{path: "/zap", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
			{path: "/static", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
			{path: "/static/", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/static/foo", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/static/foo/bar.js", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/piyo/static", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
			{path: "/piyo/static/", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/piyo/static/foo", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/piyo/static/foo/bar.js", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/sss/", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
		}

		for _, method := range METHODS {
			for _, c := range cases {
				t.Run(fmt.Sprintf("?method=%v&path=%v", method, c.path), func(t *testing.T) {
					r, err := doRequest(method, c.path, "TOKEN1")
					assert.Nil(err, fmt.Sprintf("%s has no error", method))
					assert.Equal(c.statusCode, r.StatusCode, c.desc)
				})
			}
		}
	})

	t.Run(`with valid "user1"`, func(t *testing.T) {
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
			{path: "/piyo/piyo/", statusCode: http.StatusOK, desc: "return 200"},
			{path: "/hoge/hoge", statusCode: http.StatusOK, desc: "return 200"},
			{path: "/huga/huga", statusCode: http.StatusOK, desc: "return 200"},
			{path: "/zap", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
			{path: "/static", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
			{path: "/static/", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/static/foo", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/static/foo/bar.js", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/piyo/static", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
			{path: "/piyo/static/", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/piyo/static/foo", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/piyo/static/foo/bar.js", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/sss/", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
		}

		for _, method := range METHODS {
			for _, c := range cases {
				t.Run(fmt.Sprintf("?method=%v&path=%v", method, c.path), func(t *testing.T) {
					r, err := doRequest(method, c.path, getBasicAuthHeader("user1", "password1"))
					assert.Nil(err, fmt.Sprintf("%s has no error", method))
					assert.Equal(c.statusCode, r.StatusCode, c.desc)
				})
			}
		}
	})

	t.Run(`with valid "user2"`, func(t *testing.T) {
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
			{path: "/piyo/piyo/", statusCode: http.StatusOK, desc: "return 200"},
			{path: "/hoge/hoge", statusCode: http.StatusUnauthorized, desc: `return 401 when "bearer" keyword is missing`},
			{path: "/huga/huga", statusCode: http.StatusUnauthorized, desc: `return 401 when "bearer" keyword is missing`},
			{path: "/zap", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
			{path: "/static", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
			{path: "/static/", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/static/foo", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/static/foo/bar.js", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/piyo/static", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
			{path: "/piyo/static/", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/piyo/static/foo", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/piyo/static/foo/bar.js", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/sss/", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
		}

		for _, method := range METHODS {
			for _, c := range cases {
				t.Run(fmt.Sprintf("?method=%v&path=%v", method, c.path), func(t *testing.T) {
					r, err := doRequest(method, c.path, getBasicAuthHeader("user2", "password2"))
					assert.Nil(err, fmt.Sprintf("%s has no error", method))
					assert.Equal(c.statusCode, r.StatusCode, c.desc)
				})
			}
		}
	})

	t.Run(`with valid "user3"`, func(t *testing.T) {
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
			{path: "/piyo/piyo/", statusCode: http.StatusUnauthorized, desc: `return 401 when "bearer" keyword is missing`},
			{path: "/hoge/hoge", statusCode: http.StatusUnauthorized, desc: `return 401 when "bearer" keyword is missing`},
			{path: "/huga/huga", statusCode: http.StatusUnauthorized, desc: `return 401 when "bearer" keyword is missing`},
			{path: "/zap", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
			{path: "/static", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
			{path: "/static/", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/static/foo", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/static/foo/bar.js", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/piyo/static", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
			{path: "/piyo/static/", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/piyo/static/foo", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/piyo/static/foo/bar.js", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/sss/", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
		}

		for _, method := range METHODS {
			for _, c := range cases {
				t.Run(fmt.Sprintf("?method=%v&path=%v", method, c.path), func(t *testing.T) {
					r, err := doRequest(method, c.path, getBasicAuthHeader("user3", "password3"))
					assert.Nil(err, fmt.Sprintf("%s has no error", method))
					assert.Equal(c.statusCode, r.StatusCode, c.desc)
				})
			}
		}
	})

	t.Run(`with invalid "user1" password`, func(t *testing.T) {
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
			{path: "/piyo/piyo/", statusCode: http.StatusUnauthorized, desc: `return 401 when "bearer" keyword is missing`},
			{path: "/hoge/hoge", statusCode: http.StatusUnauthorized, desc: `return 401 when "bearer" keyword is missing`},
			{path: "/huga/huga", statusCode: http.StatusUnauthorized, desc: `return 401 when "bearer" keyword is missing`},
			{path: "/zap", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
			{path: "/static", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
			{path: "/static/", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/static/foo", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/static/foo/bar.js", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/piyo/static", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
			{path: "/piyo/static/", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/piyo/static/foo", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/piyo/static/foo/bar.js", statusCode: http.StatusOK, desc: "return 200 when path contains '/static/'"},
			{path: "/sss/", statusCode: http.StatusUnauthorized, desc: "return 401 when Authorization header is not set"},
		}

		for _, method := range METHODS {
			for _, c := range cases {
				t.Run(fmt.Sprintf("?method=%v&path=%v", method, c.path), func(t *testing.T) {
					r, err := doRequest(method, c.path, getBasicAuthHeader("user1", "invalid"))
					assert.Nil(err, fmt.Sprintf("%s has no error", method))
					assert.Equal(c.statusCode, r.StatusCode, c.desc)
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
			{path: "/", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/some", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/foo/1/", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/foo/a/", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/bar/1/", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/piyo/piyo/", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/hoge/hoge", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/huga/huga", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/zap", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/static", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/static/", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/static/foo", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/static/foo/bar.js", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/piyo/static", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/piyo/static/", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/piyo/static/foo", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/piyo/static/foo/bar.js", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/sss/", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
		}

		for _, method := range METHODS {
			for _, c := range cases {
				t.Run(fmt.Sprintf("?method=%v&path=%v", method, c.path), func(t *testing.T) {
					r, err := doRequest(method, c.path, "")
					assert.Nil(err, fmt.Sprintf("%s has no error", method))
					assert.Equal(c.statusCode, r.StatusCode, c.desc)
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
			{path: "/", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/some", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/foo/1/", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/foo/a/", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/bar/1/", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/piyo/piyo/", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/hoge/hoge", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/huga/huga", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/zap", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/static", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/static/", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/static/foo", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/static/foo/bar.js", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/piyo/static", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/piyo/static/", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/piyo/static/foo", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/piyo/static/foo/bar.js", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/sss/", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
		}

		for _, method := range METHODS {
			for _, c := range cases {
				t.Run(fmt.Sprintf("?method=%v&path=%v", method, c.path), func(t *testing.T) {
					r, err := doRequest(method, c.path, "bearer TOKEN1")
					assert.Nil(err, fmt.Sprintf("%s has no error", method))
					assert.Equal(c.statusCode, r.StatusCode, c.desc)
				})
			}
		}
	})

	t.Run(`with valid "user1"`, func(t *testing.T) {
		cases := []struct {
			path       string
			statusCode int
			desc       string
		}{
			{path: "/", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/some", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/foo/1/", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/foo/a/", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/bar/1/", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/piyo/piyo/", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/hoge/hoge", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/huga/huga", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/zap", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/static", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/static/", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/static/foo", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/static/foo/bar.js", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/piyo/static", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/piyo/static/", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/piyo/static/foo", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/piyo/static/foo/bar.js", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
			{path: "/sss/", statusCode: http.StatusForbidden, desc: "Get returns 403 when AUTH_TOKENS is not set"},
		}

		for _, method := range METHODS {
			for _, c := range cases {
				t.Run(fmt.Sprintf("?method=%v&path=%v", method, c.path), func(t *testing.T) {
					r, err := doRequest(method, c.path, getBasicAuthHeader("user1", "password1"))
					assert.Nil(err, fmt.Sprintf("%s has no error", method))
					assert.Equal(c.statusCode, r.StatusCode, c.desc)
				})
			}
		}
	})
}
