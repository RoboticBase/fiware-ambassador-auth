/*
Package token : hold token configurations to check sing HTTP Header.

	license: Apache license 2.0
	copyright: Nobuyuki Matsui <nobuyuki.matsui@gmail.com>
*/
package token

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func setUp(t *testing.T) func() {
	t.Helper()
	return func() {
		os.Unsetenv(AuthTokens)
	}
}

func TestNewHolderNoENV(t *testing.T) {
	assert := assert.New(t)
	tearDown := setUp(t)
	defer tearDown()

	holder := NewHolder()

	t.Run("GetHosts()", func(t *testing.T) {
		assert.Equal([]string{}, holder.GetHosts(),
			`GetHosts() returns empty slice when AUTH_TOKENS is not set`)
	})

	t.Run("GetTokens()", func(t *testing.T) {
		assert.Equal([]string(nil), holder.GetTokens("127.0.0.1:8080"),
			`GetTokens() returns empty slice when AUTH_TOKENS is not set`)
	})

	t.Run("HasToken()", func(t *testing.T) {
		assert.False(holder.HasToken("127.0.0.1:8080", ""),
			`HasToken() always returns false when empty token is given`)
		assert.False(holder.HasToken("127.0.0.1:8080", "some"),
			`HasToken() always returns false when AUTH_TOKENS is not set`)
	})

	t.Run("GetAllowedPaths()", func(t *testing.T) {
		assert.Equal([]*regexp.Regexp(nil), holder.GetAllowedPaths("127.0.0.1:8080", ""),
			`GetAllowedPaths() always returns empty slice when empty token is given`)
		assert.Equal([]*regexp.Regexp(nil), holder.GetAllowedPaths("127.0.0.1:8080", "some"),
			`GetAllowedPaths() returns empty slice when AUTH_TOKENS is not set`)
	})

	t.Run("GetBasicAuthConf()", func(t *testing.T) {
		assert.Equal(map[string]map[string]string(nil), holder.GetBasicAuthConf("127.0.0.1:8080"),
			`GetBasicAuthConf() returns empty slice when AUTH_TOKENS is not set`)
	})

	t.Run("GetNoAuthPaths()", func(t *testing.T) {
		assert.Equal([]string(nil), holder.GetNoAuthPaths("127.0.0.1:8080"),
			`GetNoAuthPaths() returns empty slice when AUTH_TOKENS is not set`)
	})
}

func TestNewHolderEmptyENV(t *testing.T) {
	assert := assert.New(t)
	tearDown := setUp(t)
	defer tearDown()

	os.Setenv(AuthTokens, "")

	holder := NewHolder()

	t.Run("GetHosts()", func(t *testing.T) {
		assert.Equal([]string{}, holder.GetHosts(),
			`GetHosts() returns empty slice when AUTH_TOKENS is empty`)
	})

	t.Run("GetTokens()", func(t *testing.T) {
		assert.Equal([]string(nil), holder.GetTokens("127.0.0.1:8080"),
			`GetTokens() returns empty slice when AUTH_TOKENS is empty`)
	})

	t.Run("HasToken()", func(t *testing.T) {
		assert.False(holder.HasToken("127.0.0.1:8080", ""),
			`HasToken() always returns false when empty token is given`)
		assert.False(holder.HasToken("127.0.0.1:8080", "some"),
			`HasToken() always returns false when AUTH_TOKENS is empty`)
	})

	t.Run("GetAllowedPaths()", func(t *testing.T) {
		assert.Equal([]*regexp.Regexp(nil), holder.GetAllowedPaths("127.0.0.1:8080", ""),
			`GetAllowedPaths() always returns empty slice when empty token is given`)
		assert.Equal([]*regexp.Regexp(nil), holder.GetAllowedPaths("127.0.0.1:8080", "some"),
			`GetAllowedPaths() returns emplty slice when AUTH_TOKENS is not set`)
	})

	t.Run("GetBasicAuthConf()", func(t *testing.T) {
		assert.Equal(map[string]map[string]string(nil), holder.GetBasicAuthConf("127.0.0.1:8080"),
			`GetBasicAuthConf() returns empty slice when AUTH_TOKENS is empty`)
	})

	t.Run("GetNoAuthPaths()", func(t *testing.T) {
		assert.Equal([]string(nil), holder.GetNoAuthPaths("127.0.0.1:8080"),
			`GetNoAuthPaths() returns empty slice when AUTH_TOKENS is empty`)
	})
}

func TestNewHolderWithValidENV(t *testing.T) {
	assert := assert.New(t)
	tearDown := setUp(t)
	defer tearDown()

	bearerTokenCases := []struct {
		name  string
		value string
	}{
		{name: "empty1", value: `[]`},
		{name: "empty2", value: `
			[
				{
					"token": "TOKEN1",
					"allowed_paths": []
				}
			]
		`},
		{name: "empty3", value: `
			[
				{
					"token": "TOKEN1",
					"allowed_paths": ["("]
				}
			]
		`},
		{name: "one", value: `
			[
				{
					"token": "TOKEN1",
					"allowed_paths": ["^/foo/\\d+/.*$", "^/bar/.*$"]
				}
			]
		`},
		{name: "multi", value: `
			[
				{
					"token": "TOKEN1",
					"allowed_paths": ["^/foo/\\d+/.*$", "**", "^/bar/.*$"]
				},{
					"token": "TOKEN2",
					"allowed_paths": ["^/bar/.*$", "??"]
				}
			]
		`},
	}

	basicAuthCases := []struct {
		name  string
		value string
	}{
		{name: "empty1", value: `[]`},
		{name: "empty2", value: `
				[
					{
						"username": "user3",
						"password": "password3",
						"allowed_paths": []
					}
				]
			`},
		{name: "one", value: `
				[
					{
						"username": "user1",
						"password": "password1",
						"allowed_paths": ["/piyo/.+/", "/hoge/hoge"]
					}
				]
			`},
		{name: "multi", value: `
				[
					{
						"username": "user1",
						"password": "password1",
						"allowed_paths": ["/piyo/.+/", "/hoge/hoge"]
					}, {
						"username": "user2",
						"password": "password2",
						"allowed_paths": ["/piyo/.+/"]
					}, {
						"username": "user3",
						"password": "password3",
						"allowed_paths": []
					}
				]
			`},
	}

	noAuthCases := []struct {
		name  string
		value string
	}{
		{name: "empty1", value: `{}`},
		{name: "empty2", value: `
				{
					"allowed_paths": []
				}
			`},
		{name: "one", value: `
				{
					"allowed_paths": ["^.*/static/.+$"]
				}
			`},
		{name: "multi", value: `
				{
					"allowed_paths": ["^.*/static/.+$", "icon.png"]
				}
			`},
	}

	for _, bearerTokenCase := range bearerTokenCases {
		for _, basicAuthCase := range basicAuthCases {
			for _, noAuthCase := range noAuthCases {
				host1 := "test1.example.com"
				host2 := "test2.example.com"
				json := fmt.Sprintf(`[
					{
						"host": "%s",
						"settings": {
							"bearer_tokens":%s,
							"basic_auths":%s,
							"no_auths":%s
						}
					},
					{
						"host": "%s",
						"settings": {
							"bearer_tokens": [
								{
									"token": "TOKEN3",
									"allowed_paths": ["^/foo/\\d+/.*$", "^/bar/.*$"]
								}
							],
							"basic_auths": [
								{
									"username": "user4",
									"password": "password4",
									"allowed_paths": ["/piyo/.+/", "/hoge/hoge"]
								}
							],
							"no_auths": {
								"allowed_paths": ["^.*/static/.+$", "icon.png"]
							}
						}
					}
				]`, host1, bearerTokenCase.value, basicAuthCase.value, noAuthCase.value, host2)
				os.Setenv(AuthTokens, json)

				holder := NewHolder()

				t.Run(fmt.Sprintf("bearer_tokens(%s):basic_auths(%s):no_auths(%s)", bearerTokenCase.name, basicAuthCase.name, noAuthCase.name), func(t *testing.T) {
					t.Run("GetHosts()", func(t *testing.T) {
						assert.Len(holder.GetHosts(), 2, `GetHosts() returns two slices`)
						assert.Equal(holder.GetHosts(), []string{host1, host2},
							`GetHosts() returns the host names`)
					})

					switch bearerTokenCase.name {
					case "empty1", "empty2", "empty3":
						t.Run("GetTokens()", func(t *testing.T) {
							assert.Len(holder.GetTokens(host1), 0, `GetTokens() returns empty slice on host1`)
							assert.NotContains(holder.GetTokens(host1), "TOKEN1", `GetTokens() does not contain "TOKEN1" on host1`)
							assert.NotContains(holder.GetTokens(host1), "TOKEN2", `GetTokens() does not contain "TOKEN2" on host1`)
							assert.NotContains(holder.GetTokens(host1), "TOKEN3", `GetTokens() does not contain "TOKEN3" on host1`)
							assert.Len(holder.GetTokens(host2), 1, `GetTokens() returns a slice which has one token on host2`)
							assert.NotContains(holder.GetTokens(host2), "TOKEN1", `GetTokens() does not contain "TOKEN1" on host2`)
							assert.NotContains(holder.GetTokens(host2), "TOKEN2", `GetTokens() does not contain "TOKEN2" on host 2`)
							assert.Contains(holder.GetTokens(host2), "TOKEN3", `GetTokens() contains "TOKEN3" on host2`)
							assert.Len(holder.GetTokens("invalid"), 0, `GetTokens() returns empty slice on invalid host`)
							assert.NotContains(holder.GetTokens("invalid"), "TOKEN1", `GetTokens() does not contain "TOKEN1" on invalid host`)
							assert.NotContains(holder.GetTokens("invalid"), "TOKEN2", `GetTokens() does not contain "TOKEN2" on invalid host`)
							assert.NotContains(holder.GetTokens("invalid"), "TOKEN3", `GetTokens() does not contain "TOKEN3" on invalid host`)
						})
						t.Run("HasToken()", func(t *testing.T) {
							assert.False(holder.HasToken(host1, ""), `HasToken() always returns false when empty token is given`)
							assert.False(holder.HasToken(host1, "some"), `HasToken() returns false when not existing token is given`)
							assert.False(holder.HasToken(host1, "TOKEN1"), `HasToken() returns false when not existing token is given`)
							assert.False(holder.HasToken(host1, "TOKEN2"), `HasToken() returns false when not existing token is given`)
							assert.False(holder.HasToken(host1, "TOKEN3"), `HasToken() returns false when not existing token is given`)
							assert.False(holder.HasToken(host2, ""), `HasToken() always returns false when empty token is given`)
							assert.False(holder.HasToken(host2, "some"), `HasToken() returns false when not existing token is given`)
							assert.False(holder.HasToken(host2, "TOKEN1"), `HasToken() returns false when not existing token is given`)
							assert.False(holder.HasToken(host2, "TOKEN2"), `HasToken() returns false when not existing token is given`)
							assert.True(holder.HasToken(host2, "TOKEN3"), `HasToken() returns true when existing token is given`)
							assert.False(holder.HasToken("invalid", ""), `HasToken() always returns false when invalid host is given`)
							assert.False(holder.HasToken("invalid", "some"), `HasToken() returns false when invalid host is given`)
							assert.False(holder.HasToken("invalid", "TOKEN1"), `HasToken() returns false when invalid host is given`)
							assert.False(holder.HasToken("invalid", "TOKEN2"), `HasToken() returns false when invalid host is given`)
							assert.False(holder.HasToken("invalid", "TOKEN3"), `HasToken() returns false when invalid host is given`)
						})
						t.Run("GetAllowedPaths()", func(t *testing.T) {
							assert.Equal([]*regexp.Regexp(nil), holder.GetAllowedPaths(host1, ""),
								`GetAllowedPaths() always returns empty slice when empty token is given`)
							assert.Equal([]*regexp.Regexp(nil), holder.GetAllowedPaths(host1, "some"),
								`GetAllowedPaths() returns emplty slice when not existing token is given`)
							assert.Len(holder.GetAllowedPaths(host1, "TOKEN1"), 0,
								`GetAllowedPaths(host1, "TOKEN1") returns 0 length slice`)
							assert.Len(holder.GetAllowedPaths(host1, "TOKEN2"), 0,
								`GetAllowedPaths(host1, "TOKEN2") returns 0 length slice`)
							assert.Len(holder.GetAllowedPaths(host1, "TOKEN3"), 0,
								`GetAllowedPaths(host1, "TOKEN3") returns 0 length slice`)
							assert.Equal([]*regexp.Regexp(nil), holder.GetAllowedPaths(host2, ""),
								`GetAllowedPaths() always returns empty slice when empty token is given`)
							assert.Equal([]*regexp.Regexp(nil), holder.GetAllowedPaths(host2, "some"),
								`GetAllowedPaths() returns emplty slice when not existing token is given`)
							assert.Len(holder.GetAllowedPaths(host2, "TOKEN1"), 0,
								`GetAllowedPaths(host2, "TOKEN1") returns 0 length slice`)
							assert.Len(holder.GetAllowedPaths(host2, "TOKEN2"), 0,
								`GetAllowedPaths(host2, "TOKEN2") returns 0 length slice`)
							assert.Len(holder.GetAllowedPaths(host2, "TOKEN3"), 2,
								`GetAllowedPaths(host2, "TOKEN3") returns 2 length slices`)
							assert.Contains(holder.GetAllowedPaths(host2, "TOKEN3"), regexp.MustCompile("^/foo/\\d+/.*$"),
								`GetAllowedPaths(host2, "TOKEN3") contains the slice of Regexp which is compiled from json string`)
							assert.Contains(holder.GetAllowedPaths(host2, "TOKEN3"), regexp.MustCompile("^/bar/.*$"),
								`GetAllowedPaths(host2, "TOKEN3") contains the slice of Regexp which is compiled from json string`)
							assert.Equal([]*regexp.Regexp(nil), holder.GetAllowedPaths("invalid", ""),
								`GetAllowedPaths() always returns empty slice when empty token is given`)
							assert.Equal([]*regexp.Regexp(nil), holder.GetAllowedPaths("invalid", "some"),
								`GetAllowedPaths() returns emplty slice when not existing token is given`)
							assert.Len(holder.GetAllowedPaths("invalid", "TOKEN1"), 0,
								`GetAllowedPaths("invalid host", "TOKEN1") returns 0 length slice`)
							assert.Len(holder.GetAllowedPaths("invalid", "TOKEN2"), 0,
								`GetAllowedPaths("invalid host", "TOKEN2") returns 0 length slice`)
							assert.Len(holder.GetAllowedPaths("invalid", "TOKEN3"), 0,
								`GetAllowedPaths("invalid host", "TOKEN3") returns 0 length slice`)
						})
					case "one":
						t.Run("GetTokens()", func(t *testing.T) {
							assert.Len(holder.GetTokens(host1), 1, `GetTokens() returns a slice which has one token`)
							assert.Contains(holder.GetTokens(host1), "TOKEN1", `GetTokens() contains "TOKEN1"`)
							assert.NotContains(holder.GetTokens(host1), "TOKEN2", `GetTokens() does not contain "TOKEN2"`)
							assert.NotContains(holder.GetTokens(host1), "TOKEN3", `GetTokens() does not contain "TOKEN3"`)
							assert.Len(holder.GetTokens(host2), 1, `GetTokens() returns a slice which has one token on host2`)
							assert.NotContains(holder.GetTokens(host2), "TOKEN1", `GetTokens() does not contain "TOKEN1" on host2`)
							assert.NotContains(holder.GetTokens(host2), "TOKEN2", `GetTokens() does not contain "TOKEN2" on host 2`)
							assert.Contains(holder.GetTokens(host2), "TOKEN3", `GetTokens() contains "TOKEN3" on host2`)
							assert.Len(holder.GetTokens("invalid"), 0, `GetTokens() returns empty slice on invalid host`)
							assert.NotContains(holder.GetTokens("invalid"), "TOKEN1", `GetTokens() does not contain "TOKEN1" on invalid host`)
							assert.NotContains(holder.GetTokens("invalid"), "TOKEN2", `GetTokens() does not contain "TOKEN2" on invalid host`)
							assert.NotContains(holder.GetTokens("invalid"), "TOKEN3", `GetTokens() does not contain "TOKEN3" on invalid host`)
						})
						t.Run("HasToken()", func(t *testing.T) {
							assert.False(holder.HasToken(host1, ""), `HasToken() always returns false when empty token is given`)
							assert.False(holder.HasToken(host1, "some"), `HasToken() returns false when not existing token is given`)
							assert.True(holder.HasToken(host1, "TOKEN1"), `HasToken() returns true when existing token is given`)
							assert.False(holder.HasToken(host1, "TOKEN2"), `HasToken() returns false when not existing token is given`)
							assert.False(holder.HasToken(host1, "TOKEN3"), `HasToken() returns false when not existing token is given`)
							assert.False(holder.HasToken(host2, ""), `HasToken() always returns false when empty token is given`)
							assert.False(holder.HasToken(host2, "some"), `HasToken() returns false when not existing token is given`)
							assert.False(holder.HasToken(host2, "TOKEN1"), `HasToken() returns false when not existing token is given`)
							assert.False(holder.HasToken(host2, "TOKEN2"), `HasToken() returns false when not existing token is given`)
							assert.True(holder.HasToken(host2, "TOKEN3"), `HasToken() returns true when existing token is given`)
							assert.False(holder.HasToken("invalid", ""), `HasToken() always returns false when invalid host is given`)
							assert.False(holder.HasToken("invalid", "some"), `HasToken() returns false when invalid host is given`)
							assert.False(holder.HasToken("invalid", "TOKEN1"), `HasToken() returns false when invalid host is given`)
							assert.False(holder.HasToken("invalid", "TOKEN2"), `HasToken() returns false when invalid host is given`)
							assert.False(holder.HasToken("invalid", "TOKEN3"), `HasToken() returns false when invalid host is given`)
						})
						t.Run("GetAllowedPaths()", func(t *testing.T) {
							assert.Equal([]*regexp.Regexp(nil), holder.GetAllowedPaths(host1, ""),
								`GetAllowedPaths() always returns empty slice when empty token is given`)
							assert.Equal([]*regexp.Regexp(nil), holder.GetAllowedPaths(host1, "some"),
								`GetAllowedPaths() returns emplty slice when not existing token is given`)
							assert.Len(holder.GetAllowedPaths(host1, "TOKEN1"), 2,
								`GetAllowedPaths("TOKEN1") returns 2 length slice`)
							assert.Contains(holder.GetAllowedPaths(host1, "TOKEN1"), regexp.MustCompile("^/foo/\\d+/.*$"),
								`GetAllowedPaths("TOKEN1") contains the slice of Regexp which is compiled from json string`)
							assert.Contains(holder.GetAllowedPaths(host1, "TOKEN1"), regexp.MustCompile("^/bar/.*$"),
								`GetAllowedPaths("TOKEN1") contains the slice of Regexp which is compiled from json string`)
							assert.Len(holder.GetAllowedPaths(host1, "TOKEN2"), 0,
								`GetAllowedPaths("TOKEN2") returns 0 length slice`)
							assert.Len(holder.GetAllowedPaths(host1, "TOKEN3"), 0,
								`GetAllowedPaths(host1, "TOKEN3") returns 0 length slice`)
							assert.Equal([]*regexp.Regexp(nil), holder.GetAllowedPaths(host2, ""),
								`GetAllowedPaths() always returns empty slice when empty token is given`)
							assert.Equal([]*regexp.Regexp(nil), holder.GetAllowedPaths(host2, "some"),
								`GetAllowedPaths() returns emplty slice when not existing token is given`)
							assert.Len(holder.GetAllowedPaths(host2, "TOKEN1"), 0,
								`GetAllowedPaths(host2, "TOKEN1") returns 0 length slice`)
							assert.Len(holder.GetAllowedPaths(host2, "TOKEN2"), 0,
								`GetAllowedPaths(host2, "TOKEN2") returns 0 length slice`)
							assert.Len(holder.GetAllowedPaths(host2, "TOKEN3"), 2,
								`GetAllowedPaths(host2, "TOKEN3") returns 2 length slices`)
							assert.Contains(holder.GetAllowedPaths(host2, "TOKEN3"), regexp.MustCompile("^/foo/\\d+/.*$"),
								`GetAllowedPaths(host2, "TOKEN3") contains the slice of Regexp which is compiled from json string`)
							assert.Contains(holder.GetAllowedPaths(host2, "TOKEN3"), regexp.MustCompile("^/bar/.*$"),
								`GetAllowedPaths(host2, "TOKEN3") contains the slice of Regexp which is compiled from json string`)
							assert.Equal([]*regexp.Regexp(nil), holder.GetAllowedPaths("invalid", ""),
								`GetAllowedPaths() always returns empty slice when empty token is given`)
							assert.Equal([]*regexp.Regexp(nil), holder.GetAllowedPaths("invalid", "some"),
								`GetAllowedPaths() returns emplty slice when not existing token is given`)
							assert.Len(holder.GetAllowedPaths("invalid", "TOKEN1"), 0,
								`GetAllowedPaths("invalid host", "TOKEN1") returns 0 length slice`)
							assert.Len(holder.GetAllowedPaths("invalid", "TOKEN2"), 0,
								`GetAllowedPaths("invalid host", "TOKEN2") returns 0 length slice`)
							assert.Len(holder.GetAllowedPaths("invalid", "TOKEN3"), 0,
								`GetAllowedPaths("invalid host", "TOKEN3") returns 0 length slice`)
						})
					case "multi":
						t.Run("GetTokens()", func(t *testing.T) {
							assert.Len(holder.GetTokens(host1), 2, `GetTokens() returns a slice which has two tokens`)
							assert.Contains(holder.GetTokens(host1), "TOKEN1", `GetTokens() contains "TOKEN1"`)
							assert.Contains(holder.GetTokens(host1), "TOKEN2", `GetTokens() contains "TOKEN2"`)
							assert.NotContains(holder.GetTokens(host1), "TOKEN3", `GetTokens() does not contain "TOKEN3" on host1`)
							assert.Len(holder.GetTokens(host2), 1, `GetTokens() returns a slice which has one token on host2`)
							assert.NotContains(holder.GetTokens(host2), "TOKEN1", `GetTokens() does not contain "TOKEN1" on host2`)
							assert.NotContains(holder.GetTokens(host2), "TOKEN2", `GetTokens() does not contain "TOKEN2" on host 2`)
							assert.Contains(holder.GetTokens(host2), "TOKEN3", `GetTokens() contains "TOKEN3" on host2`)
							assert.Len(holder.GetTokens("invalid"), 0, `GetTokens() returns empty slice on invalid host`)
							assert.NotContains(holder.GetTokens("invalid"), "TOKEN1", `GetTokens() does not contain "TOKEN1" on invalid host`)
							assert.NotContains(holder.GetTokens("invalid"), "TOKEN2", `GetTokens() does not contain "TOKEN2" on invalid host`)
							assert.NotContains(holder.GetTokens("invalid"), "TOKEN3", `GetTokens() does not contain "TOKEN3" on invalid host`)
						})
						t.Run("HasToken()", func(t *testing.T) {
							assert.False(holder.HasToken(host1, ""), `HasToken() always returns false when empty token is given`)
							assert.False(holder.HasToken(host1, "some"), `HasToken() returns false when not existing token is given`)
							assert.True(holder.HasToken(host1, "TOKEN1"), `HasToken() returns true when existing token is given`)
							assert.True(holder.HasToken(host1, "TOKEN2"), `HasToken() returns true when existing token is given`)
							assert.False(holder.HasToken(host1, "TOKEN3"), `HasToken() returns false when not existing token is given`)
							assert.False(holder.HasToken(host2, ""), `HasToken() always returns false when empty token is given`)
							assert.False(holder.HasToken(host2, "some"), `HasToken() returns false when not existing token is given`)
							assert.False(holder.HasToken(host2, "TOKEN1"), `HasToken() returns false when not existing token is given`)
							assert.False(holder.HasToken(host2, "TOKEN2"), `HasToken() returns false when not existing token is given`)
							assert.True(holder.HasToken(host2, "TOKEN3"), `HasToken() returns true when existing token is given`)
							assert.False(holder.HasToken("invalid", ""), `HasToken() always returns false when invalid host is given`)
							assert.False(holder.HasToken("invalid", "some"), `HasToken() returns false when invalid host is given`)
							assert.False(holder.HasToken("invalid", "TOKEN1"), `HasToken() returns false when invalid host is given`)
							assert.False(holder.HasToken("invalid", "TOKEN2"), `HasToken() returns false when invalid host is given`)
							assert.False(holder.HasToken("invalid", "TOKEN3"), `HasToken() returns false when invalid host is given`)
						})
						t.Run("GetAllowedPaths()", func(t *testing.T) {
							assert.Equal([]*regexp.Regexp(nil), holder.GetAllowedPaths(host1, ""),
								`GetAllowedPaths() always returns empty slice when empty token is given`)
							assert.Equal([]*regexp.Regexp(nil), holder.GetAllowedPaths(host1, "some"),
								`GetAllowedPaths() returns emplty slice when not existing token is given`)
							assert.Len(holder.GetAllowedPaths(host1, "TOKEN1"), 2,
								`GetAllowedPaths("TOKEN1") returns 2 length slice`)
							assert.Contains(holder.GetAllowedPaths(host1, "TOKEN1"), regexp.MustCompile("^/foo/\\d+/.*$"),
								`GetAllowedPaths("TOKEN1") contains the slice of Regexp which is compiled from json string`)
							assert.Contains(holder.GetAllowedPaths(host1, "TOKEN1"), regexp.MustCompile("^/bar/.*$"),
								`GetAllowedPaths("TOKEN1") contains the slice of Regexp which is compiled from json string`)
							assert.Len(holder.GetAllowedPaths(host1, "TOKEN2"), 1,
								`GetAllowedPaths("TOKEN2") returns 1 length slice`)
							assert.Contains(holder.GetAllowedPaths(host1, "TOKEN2"), regexp.MustCompile("^/bar/.*$"),
								`GetAllowedPaths("TOKEN2") contains the slice of Regexp which is compiled from json string`)
							assert.Len(holder.GetAllowedPaths(host1, "TOKEN3"), 0,
								`GetAllowedPaths(host1, "TOKEN3") returns 0 length slice`)
							assert.Equal([]*regexp.Regexp(nil), holder.GetAllowedPaths(host2, ""),
								`GetAllowedPaths() always returns empty slice when empty token is given`)
							assert.Equal([]*regexp.Regexp(nil), holder.GetAllowedPaths(host2, "some"),
								`GetAllowedPaths() returns emplty slice when not existing token is given`)
							assert.Len(holder.GetAllowedPaths(host2, "TOKEN1"), 0,
								`GetAllowedPaths(host2, "TOKEN1") returns 0 length slice`)
							assert.Len(holder.GetAllowedPaths(host2, "TOKEN2"), 0,
								`GetAllowedPaths(host2, "TOKEN2") returns 0 length slice`)
							assert.Len(holder.GetAllowedPaths(host2, "TOKEN3"), 2,
								`GetAllowedPaths(host2, "TOKEN3") returns 2 length slices`)
							assert.Contains(holder.GetAllowedPaths(host2, "TOKEN3"), regexp.MustCompile("^/foo/\\d+/.*$"),
								`GetAllowedPaths(host2, "TOKEN3") contains the slice of Regexp which is compiled from json string`)
							assert.Contains(holder.GetAllowedPaths(host2, "TOKEN3"), regexp.MustCompile("^/bar/.*$"),
								`GetAllowedPaths(host2, "TOKEN3") contains the slice of Regexp which is compiled from json string`)
							assert.Equal([]*regexp.Regexp(nil), holder.GetAllowedPaths("invalid", ""),
								`GetAllowedPaths() always returns empty slice when empty token is given`)
							assert.Equal([]*regexp.Regexp(nil), holder.GetAllowedPaths("invalid", "some"),
								`GetAllowedPaths() returns emplty slice when not existing token is given`)
							assert.Len(holder.GetAllowedPaths("invalid", "TOKEN1"), 0,
								`GetAllowedPaths("invalid host", "TOKEN1") returns 0 length slice`)
							assert.Len(holder.GetAllowedPaths("invalid", "TOKEN2"), 0,
								`GetAllowedPaths("invalid host", "TOKEN2") returns 0 length slice`)
							assert.Len(holder.GetAllowedPaths("invalid", "TOKEN3"), 0,
								`GetAllowedPaths("invalid host", "TOKEN3") returns 0 length slice`)
						})
					}

					switch basicAuthCase.name {
					case "empty1", "empty2":
						t.Run("GetBasicAuthConf()", func(t *testing.T) {
							assert.Len(holder.GetBasicAuthConf(host1), 0, `GetBasicAuthConf() returns empty slice`)
							assert.Len(holder.GetBasicAuthConf(host2), 2, `GetBasicAuthConf() returns empty slice`)
							assert.Equal(map[string]string{"user4": "password4"}, holder.GetBasicAuthConf(host2)["/piyo/.+/"])
							assert.Equal(map[string]string{"user4": "password4"}, holder.GetBasicAuthConf(host2)["/hoge/hoge"])
							assert.Len(holder.GetBasicAuthConf("invalid"), 0, `GetBasicAuthConf() returns empty slice`)
						})
					case "one":
						t.Run("GetBasicAuthConf()", func(t *testing.T) {
							assert.Len(holder.GetBasicAuthConf(host1), 2, `GetBasicAuthConf() returns a slice which has two confs`)
							assert.Equal(map[string]string{"user1": "password1"}, holder.GetBasicAuthConf(host1)["/piyo/.+/"])
							assert.Equal(map[string]string{"user1": "password1"}, holder.GetBasicAuthConf(host1)["/hoge/hoge"])
							assert.Len(holder.GetBasicAuthConf(host2), 2, `GetBasicAuthConf() returns empty slice`)
							assert.Equal(map[string]string{"user4": "password4"}, holder.GetBasicAuthConf(host2)["/piyo/.+/"])
							assert.Equal(map[string]string{"user4": "password4"}, holder.GetBasicAuthConf(host2)["/hoge/hoge"])
							assert.Len(holder.GetBasicAuthConf("invalid"), 0, `GetBasicAuthConf() returns empty slice`)
						})
					case "multi":
						t.Run("GetBasicAuthConf()", func(t *testing.T) {
							assert.Len(holder.GetBasicAuthConf(host1), 2, `GetBasicAuthConf() returns a slice which has two confs`)
							assert.Equal(map[string]string{"user1": "password1", "user2": "password2"}, holder.GetBasicAuthConf(host1)["/piyo/.+/"])
							assert.Equal(map[string]string{"user1": "password1"}, holder.GetBasicAuthConf(host1)["/hoge/hoge"])
							assert.Len(holder.GetBasicAuthConf(host2), 2, `GetBasicAuthConf() returns empty slice`)
							assert.Equal(map[string]string{"user4": "password4"}, holder.GetBasicAuthConf(host2)["/piyo/.+/"])
							assert.Equal(map[string]string{"user4": "password4"}, holder.GetBasicAuthConf(host2)["/hoge/hoge"])
							assert.Len(holder.GetBasicAuthConf("invalid"), 0, `GetBasicAuthConf() returns empty slice`)
						})
					}

					switch noAuthCase.name {
					case "empty1", "empty2":
						t.Run("GetNoAuthPaths()", func(t *testing.T) {
							assert.Len(holder.GetNoAuthPaths(host1), 0, `GetNoAuthPaths() returns empty slice`)
							assert.Len(holder.GetNoAuthPaths(host2), 2, `GetNoAuthPaths() returns two slices`)
							assert.Equal([]string{"^.*/static/.+$", "icon.png"}, holder.GetNoAuthPaths(host2))
							assert.Len(holder.GetNoAuthPaths("invalid"), 0, `GetNoAuthPaths() returns empty slice`)
						})
					case "one":
						t.Run("GetNoAuthPaths()", func(t *testing.T) {
							assert.Len(holder.GetNoAuthPaths(host1), 1, `GetNoAuthPaths() returns a slice`)
							assert.Equal([]string{"^.*/static/.+$"}, holder.GetNoAuthPaths(host1))
							assert.Len(holder.GetNoAuthPaths(host2), 2, `GetNoAuthPaths() returns two slices`)
							assert.Equal([]string{"^.*/static/.+$", "icon.png"}, holder.GetNoAuthPaths(host2))
							assert.Len(holder.GetNoAuthPaths("invalid"), 0, `GetNoAuthPaths() returns empty slice`)
						})
					case "multi":
						t.Run("GetNoAuthPaths()", func(t *testing.T) {
							assert.Len(holder.GetNoAuthPaths(host1), 2, `GetNoAuthPaths() returns two slices`)
							assert.Equal([]string{"^.*/static/.+$", "icon.png"}, holder.GetNoAuthPaths(host1))
							assert.Len(holder.GetNoAuthPaths(host2), 2, `GetNoAuthPaths() returns two slices`)
							assert.Equal([]string{"^.*/static/.+$", "icon.png"}, holder.GetNoAuthPaths(host2))
							assert.Len(holder.GetNoAuthPaths("invalid"), 0, `GetNoAuthPaths() returns empty slice`)
						})
					}
				})
			}
		}
	}
}

func TestNewHolderWithInvalidENV(t *testing.T) {
	assert := assert.New(t)
	tearDown := setUp(t)
	defer tearDown()

	testCases := []struct {
		name string
		json string
	}{
		{name: "lostHost", json: `
			[
				{
					"settings": {
						"bearer_tokens": [
							{
								"token": "TOKEN1",
								"allowed_paths": ["^/bar/.*$"]
							}
						],
						"basic_auths": [
							{
								"username": "user1",
								"password": "password1",
								"allowed_paths": ["/piyo/piyo/"]
							}
						],
						"no_auths": {
							"allowd_paths": []
						}
					}
				}
			]
		`},
		{name: "lostSettings", json: `
			[
				{
					"host": "test.example.com"
				}
			]
		`},
		{name: "lostBearerToken", json: `
			[
				{
					"host": "test1.example.com",
					"settings": {
						"bearer_tokens": [
							{
								"allowed_paths": ["^/bar/.*$"]
							}
						],
						"basic_auths": [
							{
								"username": "user1",
								"password": "password1",
								"allowed_paths": ["/piyo/piyo/"]
							}
						],
						"no_auths": {
							"allowd_paths": []
						}
					}
				}
			]
		`},
		{name: "lostBearerAllowedPaths", json: `
			[
				{
					"host": "test1.example.com",
					"settings": {
						"bearer_tokens": [
							{
								"token": "TOKEN1",
							}
						],
						"basic_auths": [
							{
								"username": "user1",
								"password": "password1",
								"allowed_paths": ["/piyo/piyo/"]
							}
						],
						"no_auths": {
							"allowd_paths": []
						}
					}
				}
			]
		`},
		{name: "bearerAllowedPathIsNotList1", json: `
			[
				{
					"host": "test1.example.com",
					"settings": {
						"bearer_tokens": [
							{
								"token": "TOKEN1",
								"allowed_paths": "invalid"
							}
						],
						"basic_auths": [
							{
								"username": "user1",
								"password": "password1",
								"allowed_paths": ["/piyo/piyo/"]
							}
						],
						"no_auths": {
							"allowd_paths": []
						}
					}
				}
			]
		`},
		{name: "bearerAllowedPathIsNotList2", json: `
			[
				{
					"host": "test1.example.com",
					"settings": {
						"bearer_tokens": [
							{
								"token": "TOKEN1",
								"allowed_paths": {}
							}
						],
						"basic_auths": [
							{
								"username": "user1",
								"password": "password1",
								"allowed_paths": ["/piyo/piyo/"]
							}
						],
						"no_auths": {
							"allowd_paths": []
						}
					}
				}
			]
		`},
		{name: "lostUsername", json: `
			[
				{
					"host": "test1.example.com",
					"settings": {
						"bearer_tokens": [
							{
								"token": "TOKEN1",
								"allowed_paths": ["^/bar/.*$"]
							}
						],
						"basic_auths": [
							{
								"password": "password1",
								"allowed_paths": ["/piyo/piyo/"]
							}
						],
						"no_auths": {
							"allowd_paths": []
						}
					}
				}
			]
		`},
		{name: "lostPassword", json: `
			[
				{
					"host": "test1.example.com",
					"settings": {
						"bearer_tokens": [
							{
								"token": "TOKEN1",
								"allowed_paths": ["^/bar/.*$"]
							}
						],
						"basic_auths": [
							{
								"username": "user1",
								"allowed_paths": ["/piyo/piyo/"]
							}
						],
						"no_auths": {
							"allowd_paths": []
						}
					}
				}
			]
		`},
		{name: "lostBasicAllowedPaths", json: `
			[
				{
					"host": "test1.example.com",
					"settings": {
						"bearer_tokens": [
							{
								"token": "TOKEN1",
								"allowed_paths": ["^/bar/.*$"]
							}
						],
						"basic_auths": [
							{
								"username": "user1",
								"password": "password1"
							}
						],
						"no_auths": {
							"allowd_paths": []
						}
					}
				}
			]
		`},
		{name: "basicAllowedPathsIsNotList1", json: `
			[
				{
					"host": "test1.example.com",
					"settings": {
						"bearer_tokens": [
							{
								"token": "TOKEN1",
								"allowed_paths": ["^/bar/.*$"]
							}
						],
						"basic_auths": [
							{
								"username": "user1",
								"password": "password1",
								"allowed_paths": ""
							}
						],
						"no_auths": {
							"allowd_paths": []
						}
					}
				}
			]
		`},
		{name: "basicAllowedPathsIsNotList2", json: `
			[
				{
					"host": "test1.example.com",
					"settings": {
						"bearer_tokens": [
							{
								"token": "TOKEN1",
								"allowed_paths": ["^/bar/.*$"]
							}
						],
						"basic_auths": [
							{
								"username": "user1",
								"password": "password1",
								"allowed_paths": {}
							}
						],
						"no_auths": {
							"allowd_paths": []
						}
					}
				}
			]
		`},
		{name: "lostBearerTokns", json: `
			[
				{
					"host": "test1.example.com",
					"settings": {
						"basic_auths": [
							{
								"username": "user1",
								"password": "password1",
								"allowed_paths": ["/piyo/piyo/"]
							}
						],
						"no_auths": {
							"allowd_paths": []
						}
					}
				}
			]
		`},
		{name: "BearerToknsIsNotList", json: `
			[
				{
					"host": "test1.example.com",
					"settings": {
						"bearer_tokens": true,
						"basic_auths": [
							{
								"username": "user1",
								"password": "password1",
								"allowed_paths": ["/piyo/piyo/"]
							}
						],
						"no_auths": {
							"allowd_paths": []
						}
					}
				}
			]
		`},
		{name: "lostBasicAuths", json: `
			[
				{
					"host": "test1.example.com",
					"settings": {
						"bearer_tokens": [
							{
								"token": "TOKEN1",
								"allowed_paths": ["^/bar/.*$"]
							}
						],
						"no_auths": {
							"allowd_paths": []
						}
					}
				}
			]
		`},
		{name: "basicAuthIsNotList", json: `
			[
				{
					"host": "test1.example.com",
					"settings": {
						"bearer_tokens": [
							{
								"token": "TOKEN1",
								"allowed_paths": ["^/bar/.*$"]
							}
						],
						"basic_auths": false,
						"no_auths": {
							"allowd_paths": []
						}
					}
				}
			]
		`},
		{name: "lostNoAuths", json: `
			[
				{
					"host": "test1.example.com",
					"settings": {
						"bearer_tokens": [
							{
								"token": "TOKEN1",
								"allowed_paths": ["^/bar/.*$"]
							}
						],
						"basic_auths": [
							{
								"username": "user1",
								"password": "password1",
								"allowed_paths": ["/piyo/piyo/"]
							}
						]
					}
				}
			]
		`},
		{name: "noAuthsIsNotDict1", json: `
			[
				{
					"host": "test1.example.com",
					"settings": {
						"bearer_tokens": [
							{
								"token": "TOKEN1",
								"allowed_paths": ["^/bar/.*$"]
							}
						],
						"basic_auths": [
							{
								"username": "user1",
								"password": "password1",
								"allowed_paths": ["/piyo/piyo/"]
							}
						],
						"no_auths": []
					}
				}
			]
		`},
		{name: "noAuthsIsNotDict1", json: `
			[
				{
					"host": "test1.example.com",
					"settings": {
						"bearer_tokens": [
							{
								"token": "TOKEN1",
								"allowed_paths": ["^/bar/.*$"]
							}
						],
						"basic_auths": [
							{
								"username": "user1",
								"password": "password1",
								"allowed_paths": ["/piyo/piyo/"]
							}
						],
						"no_auths": ""
					}
				}
			]
		`},
		{name: "brokenJson", json: `
			[
				{
					"host": "test1.example.com",
					"settings": {
						"bearer_tokens": [
							{
								"token": "TOKEN1",
								"allowed_paths": ["^/bar/.*$"]
							}
						]
						"basic_auths": [
							{
								"username": "user1",
								"password": "password1",
								"allowed_paths": ["/piyo/piyo/"]
							}
						],
						"no_auths": {
							"allowd_paths": []
						}
					}
				}
			]
		`},
	}

	for _, testCase := range testCases {
		os.Setenv(AuthTokens, testCase.json)

		holder := NewHolder()

		t.Run(fmt.Sprintf("testCase(%s)", testCase.name), func(t *testing.T) {
			t.Run("GetHosts()", func(t *testing.T) {
				assert.Equal([]string{}, holder.GetHosts(), `GetHosts() returns empty slice`)
			})
			t.Run("GetTokens()", func(t *testing.T) {
				assert.Len(holder.GetTokens("test1.example.com"), 0, `GetTokens() returns empty slice`)
				assert.NotContains(holder.GetTokens("test1.example.com"), "TOKEN1", `GetTokens() does not contain "TOKEN1"`)
			})
			t.Run("HasToken()", func(t *testing.T) {
				assert.False(holder.HasToken("test1.example.com", ""), `HasToken() always returns false when empty token is given`)
				assert.False(holder.HasToken("test1.example.com", "some"), `HasToken() returns false when not existing token is given`)
				assert.False(holder.HasToken("test1.example.com", "TOKEN1"), `HasToken() returns false when not existing token is given`)
			})
			t.Run("GetAllowedPaths()", func(t *testing.T) {
				assert.Equal([]*regexp.Regexp(nil), holder.GetAllowedPaths("test1.example.com", ""),
					`GetAllowedPaths() always returns empty slice when empty token is given`)
				assert.Equal([]*regexp.Regexp(nil), holder.GetAllowedPaths("test1.example.com", "some"),
					`GetAllowedPaths() returns emplty slice when not existing token is given`)
				assert.Len(holder.GetAllowedPaths("test1.example.com", "TOKEN1"), 0,
					`GetAllowedPaths("TOKEN1") returns 0 length slice`)
			})
			t.Run("GetBasicAuthConf()", func(t *testing.T) {
				assert.Len(holder.GetBasicAuthConf("test1.example.com"), 0, `GetBasicAuthConf() returns empty slice`)
			})
			t.Run("GetNoAuthPaths()", func(t *testing.T) {
				assert.Equal([]string(nil), holder.GetNoAuthPaths("test1.example.com"), `GetNoAuthPaths() returns empty slice`)
			})
		})
	}
}
