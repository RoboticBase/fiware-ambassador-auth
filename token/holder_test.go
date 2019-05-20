/*
Package token : hold token configurations to check sing HTTP Header.

	license: Apache license 2.0
	copyright: Nobuyuki Matsui <nobuyuki.matsui@gmail.com>
*/
package token

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

const tmpFilePrefix = "authtest__holder_*"

func setUp(t *testing.T) (*[]string, func()) {
	t.Helper()
	log.SetOutput(ioutil.Discard)
	var tmpFiles []string
	return &tmpFiles, func() {
		os.Unsetenv(AuthTokens)
		os.Unsetenv(AuthTokensPath)

		for _, tmpFile := range tmpFiles {
			if err := os.Remove(tmpFile); err != nil {
				panic(err)
			}
		}
	}
}

func setUpTmpFile(t *testing.T, tmpFiles *[]string) (*os.File, func()) {
	t.Helper()
	fp, err := ioutil.TempFile("", tmpFilePrefix)
	*tmpFiles = append(*tmpFiles, fp.Name())
	if err != nil {
		panic(err)
	}
	return fp, func() {
		fp.Close()
	}
}

func TestNewHolderEmptyENV(t *testing.T) {
	assert := assert.New(t)
	_, tearDown := setUp(t)
	defer tearDown()

	envCases := []struct {
		name   string
		setEnv func()
	}{
		{
			name: "AUTH_TOKENS and AUTH_TOKENS_PATH are not set",
			setEnv: func() {
				// nothing to do
			},
		},
		{
			name: "AUTH_TOKENS is empty and AUTH_TOKENS_PATH is not set",
			setEnv: func() {
				os.Setenv(AuthTokens, "")
			},
		},
		{
			name: "AUTH_TOKENS_PATH is empty and AUTH_TOKENS is not set",
			setEnv: func() {
				os.Setenv(AuthTokensPath, "")
			},
		},
		{
			name: "AUTH_TOKENS_PATH and AUTH_TOKENS are empty",
			setEnv: func() {
				os.Setenv(AuthTokens, "")
				os.Setenv(AuthTokensPath, "")
			},
		},
		{
			name: "AUTH_TOKENS_PATH does not exist",
			setEnv: func() {
				os.Setenv(AuthTokensPath, "/xyz")
			},
		},
	}

	for _, envCase := range envCases {
		envCase.setEnv()

		holder := NewHolder()

		t.Run(fmt.Sprintf("GetHosts():%s", envCase.name), func(t *testing.T) {
			assert.Equal([]string{}, holder.GetHosts(),
				"GetHosts() returns empty slice when %s", envCase.name)
		})

		t.Run(fmt.Sprintf("GetTokens():%s", envCase.name), func(t *testing.T) {
			assert.Equal([]string(nil), holder.GetTokens("127.0.0.1:8080"),
				"GetTokens() returns empty slice when %s", envCase.name)
		})

		t.Run(fmt.Sprintf("HasTokens():%s", envCase.name), func(t *testing.T) {
			assert.False(holder.HasToken("127.0.0.1:8080", ""),
				`HasToken() always returns false when empty token is given`)
			assert.False(holder.HasToken("127.0.0.1:8080", "some"),
				"HasToken() always returns false when %s", envCase.name)
		})

		t.Run(fmt.Sprintf("GetAllowedPaths():%s", envCase.name), func(t *testing.T) {
			assert.Equal([]*regexp.Regexp(nil), holder.GetAllowedPaths("127.0.0.1:8080", ""),
				`GetAllowedPaths() always returns empty slice when empty token is given`)
			assert.Equal([]*regexp.Regexp(nil), holder.GetAllowedPaths("127.0.0.1:8080", "some"),
				"GetAllowedPaths() returns emplty slice when %s", envCase.name)
		})

		t.Run(fmt.Sprintf("GetBasicAuthConf():%s", envCase.name), func(t *testing.T) {
			assert.Equal(map[string]map[string]string(nil), holder.GetBasicAuthConf("127.0.0.1:8080"),
				"GetBasicAuthConf() returns empty slice when %s", envCase.name)
		})

		t.Run(fmt.Sprintf("GetNoAuthPaths():%s", envCase.name), func(t *testing.T) {
			assert.Equal([]string(nil), holder.GetNoAuthPaths("127.0.0.1:8080"),
				"GetNoAuthPaths() returns empty slice when %s", envCase.name)
		})
	}
}

func TestNewHolderWithValidENV(t *testing.T) {
	assert := assert.New(t)
	tmpFiles, tearDown := setUp(t)
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

	envCases := []struct {
		name   string
		setEnv func(string)
	}{
		{
			name: "AUTH_TOKENS",
			setEnv: func(json string) {
				os.Unsetenv(AuthTokensPath)
				os.Setenv(AuthTokens, json)
			},
		},
		{
			name: "AUTH_TOKENS_PATH",
			setEnv: func(json string) {
				tmpFile, tearDownFile := setUpTmpFile(t, tmpFiles)
				defer tearDownFile()

				os.Unsetenv(AuthTokens)
				tmpFile.WriteString(json)
				os.Setenv(AuthTokensPath, tmpFile.Name())
			},
		},
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

				for _, envCase := range envCases {
					envCase.setEnv(json)

					holder := NewHolder()

					t.Run(fmt.Sprintf("bearer_tokens(%s):basic_auths(%s):no_auths(%s):using %s", bearerTokenCase.name, basicAuthCase.name, noAuthCase.name, envCase.name), func(t *testing.T) {
						t.Run("GetHosts()", func(t *testing.T) {
							assert.Len(holder.GetHosts(), 2, `GetHosts() returns two slices`)
							assert.Equal([]string{host1, host2}, holder.GetHosts(),
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
}

func TestNewHolderWithInvalidENV(t *testing.T) {
	assert := assert.New(t)
	tmpFiles, tearDown := setUp(t)
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

	envCases := []struct {
		name   string
		setEnv func(string)
	}{
		{
			name: "AUTH_TOKENS",
			setEnv: func(json string) {
				os.Unsetenv(AuthTokensPath)
				os.Setenv(AuthTokens, json)
			},
		},
		{
			name: "AUTH_TOKENS_PATH",
			setEnv: func(json string) {
				tmpFile, tearDownFile := setUpTmpFile(t, tmpFiles)
				defer tearDownFile()

				os.Unsetenv(AuthTokens)
				tmpFile.WriteString(json)
				os.Setenv(AuthTokensPath, tmpFile.Name())
			},
		},
	}

	for _, testCase := range testCases {
		for _, envCase := range envCases {
			envCase.setEnv(testCase.json)

			holder := NewHolder()

			t.Run(fmt.Sprintf("testCase(%s) using %s", testCase.name, envCase.name), func(t *testing.T) {
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
}

func TestNewHolderEffectiveENV(t *testing.T) {
	assert := assert.New(t)
	tmpFiles, tearDown := setUp(t)
	tmpFile, tearDownFile := setUpTmpFile(t, tmpFiles)
	defer tearDown()
	defer tearDownFile()

	host1 := "test1.example.com"
	host2 := "test2.example.com"

	json1 := fmt.Sprintf(`
		[
			{
				"host": "%s",
				"settings": {
					"bearer_tokens": [
						{
							"token": "TOKEN1",
							"allowed_paths": ["^/foo/\\d+/.*$", "^/bar/.*$"]
						}
					],
					"basic_auths": [
						{
							"username": "user1",
							"password": "password1",
							"allowed_paths": ["/piyo/.+/", "/hoge/hoge"]
						}
					],
					"no_auths": {
						"allowed_paths": ["^.*/static/.+$", "icon.png"]
					}
				}
			}
		]
	`, host1)

	json2 := fmt.Sprintf(`
		[
			{
				"host": "%s",
				"settings": {
					"bearer_tokens": [
						{
							"token": "TOKEN2",
							"allowed_paths": ["^/buz/\\d+/.*$"]
						}
					],
					"basic_auths": [
						{
							"username": "user2",
							"password": "password2",
							"allowed_paths": ["/fuga/.+/"]
						}
					],
					"no_auths": {
						"allowed_paths": ["^.*/imgs/.+$"]
					}
				}
			}
		]
	`, host2)

	tmpFile.WriteString(json1)
	os.Setenv(AuthTokensPath, tmpFile.Name())
	os.Setenv(AuthTokens, json2)

	holder := NewHolder()

	t.Run("GetHosts()", func(t *testing.T) {
		assert.Len(holder.GetHosts(), 1, `GetHosts() returns one slice`)
		assert.Equal([]string{host1}, holder.GetHosts(),
			`GetHosts() returns "test1.example.com"`)
	})

	t.Run("GetTokens()", func(t *testing.T) {
		assert.Len(holder.GetTokens(host1), 1, `GetTokens() returns a slice which has one token on host1`)
		assert.Contains(holder.GetTokens(host1), "TOKEN1", `GetTokens() contains "TOKEN1" on host1`)
		assert.NotContains(holder.GetTokens(host1), "TOKEN2", `GetTokens() does not contain "TOKEN2" on host1`)
		assert.Len(holder.GetTokens(host2), 0, `GetTokens() returns an empty slice on host2`)
		assert.NotContains(holder.GetTokens(host2), "TOKEN1", `GetTokens() does not contain "TOKEN1" on host2`)
		assert.NotContains(holder.GetTokens(host2), "TOKEN2", `GetTokens() does not contain "TOKEN2" on host2`)
	})

	t.Run("HasTokens()", func(t *testing.T) {
		assert.False(holder.HasToken(host1, ""),
			`HasToken() always returns false when empty token is given`)
		assert.True(holder.HasToken(host1, "TOKEN1"),
			`HasToken() returns true when "TOKEN1" is given on host1`)
		assert.False(holder.HasToken(host1, "TOKEN2"),
			`HasToken() returns false when "TOKEN2" is given on host1`)
		assert.False(holder.HasToken(host2, ""),
			`HasToken() always returns false when empty token is given`)
		assert.False(holder.HasToken(host2, "TOKEN1"),
			`HasToken() returns false when "TOKEN1" is given on host2`)
		assert.False(holder.HasToken(host2, "TOKEN2"),
			`HasToken() returns false when "TOKEN2" is given on host2`)
	})

	t.Run("GetAllowedPaths()", func(t *testing.T) {
		assert.Equal([]*regexp.Regexp(nil), holder.GetAllowedPaths(host1, ""),
			`GetAllowedPaths() always returns empty slice when empty token is given`)
		assert.Contains(holder.GetAllowedPaths(host1, "TOKEN1"), regexp.MustCompile("^/foo/\\d+/.*$"),
			`GetAllowedPaths("TOKEN1") contains the slice of Regexp which is compiled from json string`)
		assert.Contains(holder.GetAllowedPaths(host1, "TOKEN1"), regexp.MustCompile("^/bar/.*$"),
			`GetAllowedPaths("TOKEN1") contains the slice of Regexp which is compiled from json string`)
		assert.NotContains(holder.GetAllowedPaths(host1, "TOKEN2"), regexp.MustCompile("^/buz/\\d+/.*$"),
			`GetAllowedPaths("TOKEN2") does not contain the host2's Regexp`)
		assert.Equal([]*regexp.Regexp(nil), holder.GetAllowedPaths(host2, ""),
			`GetAllowedPaths() always returns empty slice when empty token is given`)
		assert.NotContains(holder.GetAllowedPaths(host2, "TOKEN1"), regexp.MustCompile("^/foo/\\d+/.*$"),
			`GetAllowedPaths("TOKEN1") does not contain the host2's Regexp`)
		assert.NotContains(holder.GetAllowedPaths(host2, "TOKEN1"), regexp.MustCompile("^/bar/.*$"),
			`GetAllowedPaths("TOKEN1") does not contain the host2's Regexp`)
		assert.NotContains(holder.GetAllowedPaths(host2, "TOKEN2"), regexp.MustCompile("^/buz/\\d+/.*$"),
			`GetAllowedPaths("TOKEN2") does not contain the host2's Regexp`)
	})

	t.Run("GetBasicAuthConf()", func(t *testing.T) {
		assert.Len(holder.GetBasicAuthConf(host1), 2, `GetBasicAuthConf() returns a slice which has two confs`)
		assert.Equal(map[string]string{"user1": "password1"}, holder.GetBasicAuthConf(host1)["/piyo/.+/"])
		assert.Equal(map[string]string{"user1": "password1"}, holder.GetBasicAuthConf(host1)["/hoge/hoge"])
		assert.NotEqual(map[string]string{"user2": "password2"}, holder.GetBasicAuthConf(host1)["/fuga/.+/"])
		assert.Len(holder.GetBasicAuthConf(host2), 0, `GetBasicAuthConf() returns empty slice`)
		assert.NotEqual(map[string]string{"user1": "password1"}, holder.GetBasicAuthConf(host2)["/piyo/.+/"])
		assert.NotEqual(map[string]string{"user1": "password1"}, holder.GetBasicAuthConf(host2)["/hoge/hoge"])
		assert.NotEqual(map[string]string{"user2": "password2"}, holder.GetBasicAuthConf(host2)["/fuga/.+/"])
	})

	t.Run("GetNoAuthPaths()", func(t *testing.T) {
		assert.Len(holder.GetNoAuthPaths(host1), 2, `GetNoAuthPaths() returns a slice`)
		assert.Equal([]string{"^.*/static/.+$", "icon.png"}, holder.GetNoAuthPaths(host1))
		assert.Len(holder.GetNoAuthPaths(host2), 0, `GetNoAuthPaths() returns empty slice`)
		assert.Equal([]string(nil), holder.GetNoAuthPaths(host2))
	})
}
