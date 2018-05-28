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

	t.Run("GetTokens()", func(t *testing.T) {
		assert.Equal([]string{}, holder.GetTokens(),
			`GetTokens() returns empty slice when AUTH_TOKENS is not set`)
	})

	t.Run("HasToken()", func(t *testing.T) {
		assert.False(holder.HasToken(""),
			`HasToken() always returns false when empty token is given`)
		assert.False(holder.HasToken("some"),
			`HasToken() always returns false when AUTH_TOKENS is not set`)
	})

	t.Run("GetAllowedPaths()", func(t *testing.T) {
		assert.Equal([]*regexp.Regexp(nil), holder.GetAllowedPaths(""),
			`GetAllowedPaths() always returns empty slice when empty token is given`)
		assert.Equal([]*regexp.Regexp(nil), holder.GetAllowedPaths("some"),
			`GetAllowedPaths() returns emplty slice when AUTH_TOKENS is not set`)
	})

	t.Run("GetBasicAuthConf()", func(t *testing.T) {
		assert.Equal(map[string]map[string]string{}, holder.GetBasicAuthConf(),
			`GetBasicAuthConf() returns empty slice when AUTH_TOKENS is not set`)
	})
}

func TestNewHolderEmptyENV(t *testing.T) {
	assert := assert.New(t)
	tearDown := setUp(t)
	defer tearDown()

	os.Setenv(AuthTokens, "")

	holder := NewHolder()

	t.Run("GetTokens()", func(t *testing.T) {
		assert.Equal([]string{}, holder.GetTokens(),
			`GetTokens() returns empty slice when AUTH_TOKENS is empty`)
	})

	t.Run("HasToken()", func(t *testing.T) {
		assert.False(holder.HasToken(""),
			`HasToken() always returns false when empty token is given`)
		assert.False(holder.HasToken("some"),
			`HasToken() always returns false when AUTH_TOKENS is empty`)
	})

	t.Run("GetAllowedPaths()", func(t *testing.T) {
		assert.Equal([]*regexp.Regexp(nil), holder.GetAllowedPaths(""),
			`GetAllowedPaths() always returns empty slice when empty token is given`)
		assert.Equal([]*regexp.Regexp(nil), holder.GetAllowedPaths("some"),
			`GetAllowedPaths() returns emplty slice when AUTH_TOKENS is not set`)
	})

	t.Run("GetBasicAuthConf()", func(t *testing.T) {
		assert.Equal(map[string]map[string]string{}, holder.GetBasicAuthConf(),
			`GetBasicAuthConf() returns empty slice when AUTH_TOKENS is empty`)
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
					"allowed_paths": ["^/foo/\\d+/*", "^/bar/*"]
				}
			]
		`},
		{name: "multi", value: `
			[
				{
					"token": "TOKEN1",
					"allowed_paths": ["^/foo/\\d+/*", "**", "^/bar/*"]
				},{
					"token": "TOKEN2",
					"allowed_paths": ["^/bar/*", "??"]
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
					"allowed_paths": ["/piyo/piyo/", "/hoge/hoge"]
				}
			]
		`},
		{name: "multi", value: `
			[
				{
					"username": "user1",
					"password": "password1",
					"allowed_paths": ["/piyo/piyo/", "/hoge/hoge"]
				}, {
					"username": "user2",
					"password": "password2",
					"allowed_paths": ["/piyo/piyo/"]
				}, {
					"username": "user3",
					"password": "password3",
					"allowed_paths": []
				}
			]
		`},
	}

	for _, bearerTokenCase := range bearerTokenCases {
		for _, basicAuthCase := range basicAuthCases {
			json := fmt.Sprintf(`{"bearer_tokens":%s,"basic_auths":%s}`, bearerTokenCase.value, basicAuthCase.value)
			os.Setenv(AuthTokens, json)

			holder := NewHolder()

			t.Run(fmt.Sprintf("bearer_tokens(%s):basic_auths(%s)", bearerTokenCase.name, basicAuthCase.name), func(t *testing.T) {
				switch bearerTokenCase.name {
				case "empty1", "empty2", "empty3":
					t.Run("GetTokens()", func(t *testing.T) {
						assert.Len(holder.GetTokens(), 0, `GetTokens() returns empty slice`)
						assert.NotContains(holder.GetTokens(), "TOKEN1", `GetTokens() does not contain "TOKEN1"`)
						assert.NotContains(holder.GetTokens(), "TOKEN2", `GetTokens() does not contain "TOKEN2"`)
					})
					t.Run("HasToken()", func(t *testing.T) {
						assert.False(holder.HasToken(""), `HasToken() always returns false when empty token is given`)
						assert.False(holder.HasToken("some"), `HasToken() returns false when not existing token is given`)
						assert.False(holder.HasToken("TOKEN1"), `HasToken() returns false when not existing token is given`)
						assert.False(holder.HasToken("TOKEN2"), `HasToken() returns false when not existing token is given`)
					})
					t.Run("GetAllowedPaths()", func(t *testing.T) {
						assert.Equal([]*regexp.Regexp(nil), holder.GetAllowedPaths(""),
							`GetAllowedPaths() always returns empty slice when empty token is given`)
						assert.Equal([]*regexp.Regexp(nil), holder.GetAllowedPaths("some"),
							`GetAllowedPaths() returns emplty slice when not existing token is given`)
						assert.Len(holder.GetAllowedPaths("TOKEN1"), 0,
							`GetAllowedPaths("TOKEN1") returns 0 length slice`)
						assert.Len(holder.GetAllowedPaths("TOKEN2"), 0,
							`GetAllowedPaths("TOKEN2") returns 0 length slice`)
					})
				case "one":
					t.Run("GetTokens()", func(t *testing.T) {
						assert.Len(holder.GetTokens(), 1, `GetTokens() returns a slice which has one token`)
						assert.Contains(holder.GetTokens(), "TOKEN1", `GetTokens() contains "TOKEN1"`)
						assert.NotContains(holder.GetTokens(), "TOKEN2", `GetTokens() does not contain "TOKEN2"`)
					})
					t.Run("HasToken()", func(t *testing.T) {
						assert.False(holder.HasToken(""), `HasToken() always returns false when empty token is given`)
						assert.False(holder.HasToken("some"), `HasToken() returns false when not existing token is given`)
						assert.True(holder.HasToken("TOKEN1"), `HasToken() returns true when existing token is given`)
						assert.False(holder.HasToken("TOKEN2"), `HasToken() returns false when not existing token is given`)
					})
					t.Run("GetAllowedPaths()", func(t *testing.T) {
						assert.Equal([]*regexp.Regexp(nil), holder.GetAllowedPaths(""),
							`GetAllowedPaths() always returns empty slice when empty token is given`)
						assert.Equal([]*regexp.Regexp(nil), holder.GetAllowedPaths("some"),
							`GetAllowedPaths() returns emplty slice when not existing token is given`)
						assert.Len(holder.GetAllowedPaths("TOKEN1"), 2,
							`GetAllowedPaths("TOKEN1") returns 2 length slice`)
						assert.Contains(holder.GetAllowedPaths("TOKEN1"), regexp.MustCompile("^/foo/\\d+/*"),
							`GetAllowedPaths("TOKEN1") contains the slice of Regexp which is compiled from json string`)
						assert.Contains(holder.GetAllowedPaths("TOKEN1"), regexp.MustCompile("^/bar/*"),
							`GetAllowedPaths("TOKEN1") contains the slice of Regexp which is compiled from json string`)
						assert.Len(holder.GetAllowedPaths("TOKEN2"), 0,
							`GetAllowedPaths("TOKEN2") returns 0 length slice`)
					})
				case "multi":
					t.Run("GetTokens()", func(t *testing.T) {
						assert.Len(holder.GetTokens(), 2, `GetTokens() returns a slice which has two tokens`)
						assert.Contains(holder.GetTokens(), "TOKEN1", `GetTokens() contains "TOKEN1"`)
						assert.Contains(holder.GetTokens(), "TOKEN2", `GetTokens() contains "TOKEN2"`)
					})
					t.Run("HasToken()", func(t *testing.T) {
						assert.False(holder.HasToken(""), `HasToken() always returns false when empty token is given`)
						assert.False(holder.HasToken("some"), `HasToken() returns false when not existing token is given`)
						assert.True(holder.HasToken("TOKEN1"), `HasToken() returns true when existing token is given`)
						assert.True(holder.HasToken("TOKEN2"), `HasToken() returns true when existing token is given`)
					})
					t.Run("GetAllowedPaths()", func(t *testing.T) {
						assert.Equal([]*regexp.Regexp(nil), holder.GetAllowedPaths(""),
							`GetAllowedPaths() always returns empty slice when empty token is given`)
						assert.Equal([]*regexp.Regexp(nil), holder.GetAllowedPaths("some"),
							`GetAllowedPaths() returns emplty slice when not existing token is given`)
						assert.Len(holder.GetAllowedPaths("TOKEN1"), 2,
							`GetAllowedPaths("TOKEN1") returns 2 length slice`)
						assert.Contains(holder.GetAllowedPaths("TOKEN1"), regexp.MustCompile("^/foo/\\d+/*"),
							`GetAllowedPaths("TOKEN1") contains the slice of Regexp which is compiled from json string`)
						assert.Contains(holder.GetAllowedPaths("TOKEN1"), regexp.MustCompile("^/bar/*"),
							`GetAllowedPaths("TOKEN1") contains the slice of Regexp which is compiled from json string`)
						assert.Len(holder.GetAllowedPaths("TOKEN2"), 1,
							`GetAllowedPaths("TOKEN2") returns 1 length slice`)
						assert.Contains(holder.GetAllowedPaths("TOKEN2"), regexp.MustCompile("^/bar/*"),
							`GetAllowedPaths("TOKEN2") contains the slice of Regexp which is compiled from json string`)
					})
				}

				switch basicAuthCase.name {
				case "empty1", "empty2":
					t.Run("GetBasicAuthConf()", func(t *testing.T) {
						assert.Len(holder.GetBasicAuthConf(), 0, `GetBasicAuthConf() returns empty slice`)
					})
				case "one":
					t.Run("GetBasicAuthConf()", func(t *testing.T) {
						assert.Len(holder.GetBasicAuthConf(), 2, `GetBasicAuthConf() returns a slice which has two confs`)
						assert.Equal(map[string]string{"user1": "password1"}, holder.GetBasicAuthConf()["/piyo/piyo/"])
						assert.Equal(map[string]string{"user1": "password1"}, holder.GetBasicAuthConf()["/hoge/hoge"])
					})
				case "multi":
					t.Run("GetBasicAuthConf()", func(t *testing.T) {
						assert.Len(holder.GetBasicAuthConf(), 2, `GetBasicAuthConf() returns a slice which has two confs`)
						assert.Equal(map[string]string{"user1": "password1", "user2": "password2"}, holder.GetBasicAuthConf()["/piyo/piyo/"])
						assert.Equal(map[string]string{"user1": "password1"}, holder.GetBasicAuthConf()["/hoge/hoge"])
					})
				}
			})
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
		{name: "lostBearerToken", json: `
			{
				"bearer_tokens": [
					{
						"allowed_paths": ["^/bar/*"]
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
		`},
		{name: "lostBearerAllowedPaths", json: `
			{
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
				]
			}
		`},
		{name: "bearerAllowedPathIsNotList1", json: `
			{
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
				]
			}
		`},
		{name: "bearerAllowedPathIsNotList2", json: `
			{
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
				]
			}
		`},
		{name: "lostUsername", json: `
			{
				"bearer_tokens": [
					{
						"token": "TOKEN1",
						"allowed_paths": ["^/bar/*"]
					}
				],
				"basic_auths": [
					{
						"password": "password1",
						"allowed_paths": ["/piyo/piyo/"]
					}
				]
			}
		`},
		{name: "lostPassword", json: `
			{
				"bearer_tokens": [
					{
						"token": "TOKEN1",
						"allowed_paths": ["^/bar/*"]
					}
				],
				"basic_auths": [
					{
						"username": "user1",
						"allowed_paths": ["/piyo/piyo/"]
					}
				]
			}
		`},
		{name: "lostBasicAllowedPaths", json: `
			{
				"bearer_tokens": [
					{
						"token": "TOKEN1",
						"allowed_paths": ["^/bar/*"]
					}
				],
				"basic_auths": [
					{
						"username": "user1",
						"password": "password1"
					}
				]
			}
		`},
		{name: "basicAllowedPathsIsNotList1", json: `
			{
				"bearer_tokens": [
					{
						"token": "TOKEN1",
						"allowed_paths": ["^/bar/*"]
					}
				],
				"basic_auths": [
					{
						"username": "user1",
						"password": "password1",
						"allowed_paths": ""
					}
				]
			}
		`},
		{name: "basicAllowedPathsIsNotList2", json: `
			{
				"bearer_tokens": [
					{
						"token": "TOKEN1",
						"allowed_paths": ["^/bar/*"]
					}
				],
				"basic_auths": [
					{
						"username": "user1",
						"password": "password1",
						"allowed_paths": {}
					}
				]
			}
		`},
		{name: "lostBearerTokns", json: `
			{
				"basic_auths": [
					{
						"username": "user1",
						"password": "password1",
						"allowed_paths": ["/piyo/piyo/"]
					}
				]
			}
		`},
		{name: "BearerToknsIsNotList", json: `
			{
				"bearer_tokens": true,
				"basic_auths": [
					{
						"username": "user1",
						"password": "password1",
						"allowed_paths": ["/piyo/piyo/"]
					}
				]
			}
		`},
		{name: "lostBasicAuths", json: `
			{
				"bearer_tokens": [
					{
						"token": "TOKEN1",
						"allowed_paths": ["^/bar/*"]
					}
				]
			}
		`},
		{name: "basicAuthIsNotList", json: `
			{
				"bearer_tokens": [
					{
						"token": "TOKEN1",
						"allowed_paths": ["^/bar/*"]
					}
				],
				"basic_auths": false
			}
		`},
		{name: "listJson", json: `[1, 2, 3]`},
		{name: "brokenJson", json: `
			{
				"bearer_tokens": [
					{
						"token": "TOKEN1",
						"allowed_paths": ["^/bar/*"]
					}
				]
				"basic_auths": [
					{
						"username": "user1",
						"password": "password1",
						"allowed_paths": ["/piyo/piyo/"]
					}
				]
			}
		`},
	}

	for _, testCase := range testCases {
		os.Setenv(AuthTokens, testCase.json)

		holder := NewHolder()

		t.Run(fmt.Sprintf("testCase(%s)", testCase.name), func(t *testing.T) {
			t.Run("GetTokens()", func(t *testing.T) {
				assert.Len(holder.GetTokens(), 0, `GetTokens() returns empty slice`)
				assert.NotContains(holder.GetTokens(), "TOKEN1", `GetTokens() does not contain "TOKEN1"`)
			})
			t.Run("HasToken()", func(t *testing.T) {
				assert.False(holder.HasToken(""), `HasToken() always returns false when empty token is given`)
				assert.False(holder.HasToken("some"), `HasToken() returns false when not existing token is given`)
				assert.False(holder.HasToken("TOKEN1"), `HasToken() returns false when not existing token is given`)
			})
			t.Run("GetAllowedPaths()", func(t *testing.T) {
				assert.Equal([]*regexp.Regexp(nil), holder.GetAllowedPaths(""),
					`GetAllowedPaths() always returns empty slice when empty token is given`)
				assert.Equal([]*regexp.Regexp(nil), holder.GetAllowedPaths("some"),
					`GetAllowedPaths() returns emplty slice when not existing token is given`)
				assert.Len(holder.GetAllowedPaths("TOKEN1"), 0,
					`GetAllowedPaths("TOKEN1") returns 0 length slice`)
			})
			t.Run("GetBasicAuthConf()", func(t *testing.T) {
				assert.Len(holder.GetBasicAuthConf(), 0, `GetBasicAuthConf() returns empty slice`)
			})
		})
	}
}
