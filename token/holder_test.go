/*
Package token : hold token configurations to check sing HTTP Header.

	license: Apache license 2.0
	copyright: Nobuyuki Matsui <nobuyuki.matsui@gmail.com>
*/
package token

import (
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
		assert.Equal(holder.GetTokens(), []string{},
			`GetTokens() returns empty slice when AUTH_TOKENS is not set`)
	})

	t.Run("HasToken()", func(t *testing.T) {
		assert.False(holder.HasToken(""),
			`HasToken() always returns false when empty token is given`)
		assert.False(holder.HasToken("some"),
			`HasToken() always returns false when AUTH_TOKENS is not set`)
	})

	t.Run("GetAllowedPaths()", func(t *testing.T) {
		assert.Equal(holder.GetAllowedPaths(""), []*regexp.Regexp(nil),
			`GetAllowedPaths() always returns empty slice when empty token is given`)
		assert.Equal(holder.GetAllowedPaths("some"), []*regexp.Regexp(nil),
			`GetAllowedPaths() returns emplty slice when AUTH_TOKENS is not set`)
	})
}

func TestNewHolderEmptyENV(t *testing.T) {
	assert := assert.New(t)
	tearDown := setUp(t)
	defer tearDown()

	os.Setenv(AuthTokens, "")

	holder := NewHolder()

	t.Run("GetTokens()", func(t *testing.T) {
		assert.Equal(holder.GetTokens(), []string{},
			`GetTokens() returns empty slice when AUTH_TOKENS is empty`)
	})

	t.Run("HasToken()", func(t *testing.T) {
		assert.False(holder.HasToken(""),
			`HasToken() always returns false when empty token is given`)
		assert.False(holder.HasToken("some"),
			`HasToken() always returns false when AUTH_TOKENS is empty`)
	})

	t.Run("GetAllowedPaths()", func(t *testing.T) {
		assert.Equal(holder.GetAllowedPaths(""), []*regexp.Regexp(nil),
			`GetAllowedPaths() always returns empty slice when empty token is given`)
		assert.Equal(holder.GetAllowedPaths("some"), []*regexp.Regexp(nil),
			`GetAllowedPaths() returns emplty slice when AUTH_TOKENS is not set`)
	})
}

func TestNewHolderWithValidENV(t *testing.T) {
	assert := assert.New(t)
	tearDown := setUp(t)
	defer tearDown()

	json := `
	{
		"TOKEN1": ["^/foo/\\d+/*", "^/bar/*"],
		"TOKEN2": ["^/bar/*"],
		"TOKEN3": []
	}
	`
	os.Setenv(AuthTokens, json)

	holder := NewHolder()

	t.Run("GetTokens()", func(t *testing.T) {
		assert.Len(holder.GetTokens(), 3,
			`GetTokens() returns 3 length slice`)
		assert.Contains(holder.GetTokens(), "TOKEN1",
			`GetTokens() contains "TOKEN1"`)
		assert.Contains(holder.GetTokens(), "TOKEN2",
			`GetTokens() contains "TOKEN2"`)
		assert.Contains(holder.GetTokens(), "TOKEN3",
			`GetTokens() contains "TOKEN3"`)
	})

	t.Run("HasToken()", func(t *testing.T) {
		assert.False(holder.HasToken(""),
			`HasToken() always returns false when empty token is given`)
		assert.False(holder.HasToken("some"),
			`HasToken() returns false when not existing token is given`)
		assert.True(holder.HasToken("TOKEN1"),
			`HasToken() returns true when existing token is given`)
		assert.True(holder.HasToken("TOKEN2"),
			`HasToken() returns true when existing token is given`)
		assert.True(holder.HasToken("TOKEN3"),
			`HasToken() returns true when existing token is given`)
	})

	t.Run("GetAllowedPaths()", func(t *testing.T) {
		assert.Equal(holder.GetAllowedPaths(""), []*regexp.Regexp(nil),
			`GetAllowedPaths() always returns empty slice when empty token is given`)
		assert.Equal(holder.GetAllowedPaths("some"), []*regexp.Regexp(nil),
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
		assert.Len(holder.GetAllowedPaths("TOKEN3"), 0,
			`GetAllowedPaths("TOKEN2") returns 0 length slice`)
	})
}

func TestNewHolderWithInValidPath(t *testing.T) {
	assert := assert.New(t)
	tearDown := setUp(t)
	defer tearDown()

	json := `
	{
		"TOKEN1": ["^/foo/\\d+/*", 1, "^/bar/*", "(["],
		"TOKEN2": "dummy"
	}
	`
	os.Setenv(AuthTokens, json)

	holder := NewHolder()

	t.Run("GetTokens()", func(t *testing.T) {
		assert.Len(holder.GetTokens(), 1,
			`GetTokens() returns 1 length slice`)
		assert.Contains(holder.GetTokens(), "TOKEN1",
			`GetTokens() contains "TOKEN1"`)
		assert.NotContains(holder.GetTokens(), "TOKEN2",
			`GetTokens() does not contain "TOKEN2" because "TOKEN2"'s value can not convert to slice`)
	})

	t.Run("HasToken()", func(t *testing.T) {
		assert.False(holder.HasToken(""),
			`HasToken() always returns false when empty token is given`)
		assert.False(holder.HasToken("some"),
			`HasToken() returns false when not existing token is given`)
		assert.True(holder.HasToken("TOKEN1"),
			`HasToken() returns true when existing token is given`)
		assert.False(holder.HasToken("TOKEN2"),
			`HasToken() returns false because "TOKEN2"'s value can not convert to slice`)
	})

	t.Run("GetAllowedPaths()", func(t *testing.T) {
		assert.Equal(holder.GetAllowedPaths(""), []*regexp.Regexp(nil),
			`GetAllowedPaths() always returns empty slice when empty token is given`)
		assert.Equal(holder.GetAllowedPaths("some"), []*regexp.Regexp(nil),
			`GetAllowedPaths() returns emplty slice when not existing token is given`)

		assert.Len(holder.GetAllowedPaths("TOKEN1"), 2,
			`GetAllowedPaths("TOKEN1") returns 2 length slice`)
		assert.Contains(holder.GetAllowedPaths("TOKEN1"), regexp.MustCompile("^/foo/\\d+/*"),
			`GetAllowedPaths("TOKEN1") contains the slice of Regexp which is compiled from json string`)
		assert.Contains(holder.GetAllowedPaths("TOKEN1"), regexp.MustCompile("^/bar/*"),
			`GetAllowedPaths("TOKEN1") contains the slice of Regexp which is compiled from json string`)
		assert.NotContains(holder.GetAllowedPaths("TOKEN1"), 1,
			`GetAllowedPaths("TOKEN1") does not contain the object which can not be compiled from json string`)
		assert.NotContains(holder.GetAllowedPaths("TOKEN1"), "([",
			`GetAllowedPaths("TOKEN1") does not contain the object which can not be compiled from json string`)

		assert.Len(holder.GetAllowedPaths("TOKEN2"), 0,
			`GetAllowedPaths("TOKEN2") returns 0 length slice`)
	})
}

func TestNewHolderWithListJson(t *testing.T) {
	assert := assert.New(t)
	tearDown := setUp(t)
	defer tearDown()

	json := `
	[
		{
			"TOKEN1": ["^/foo/\\d+/*", 1, "^/bar/*", "(["],
			"TOKEN2": "dummy"
		}
	]
	`
	os.Setenv(AuthTokens, json)

	holder := NewHolder()

	t.Run("GetTokens()", func(t *testing.T) {
		assert.Equal(holder.GetTokens(), []string{},
			`GetTokens() returns empty slice when AUTH_TOKENS is list json`)
		assert.NotContains(holder.GetTokens(), "TOKEN1",
			`GetTokens() dows not contain "TOKEN1"`)
		assert.NotContains(holder.GetTokens(), "TOKEN2",
			`GetTokens() does not contain "TOKEN2"`)
	})

	t.Run("HasToken()", func(t *testing.T) {
		assert.False(holder.HasToken(""),
			`HasToken() always returns false when empty token is given`)
		assert.False(holder.HasToken("some"),
			`HasToken() returns false when not existing token is given`)
		assert.False(holder.HasToken("TOKEN1"),
			`HasToken() returns false when AUTH_TOKENS is list json`)
		assert.False(holder.HasToken("TOKEN2"),
			`HasToken() returns false when AUTH_TOKENS is list json`)
	})

	t.Run("GetAllowedPaths()", func(t *testing.T) {
		assert.Equal(holder.GetAllowedPaths(""), []*regexp.Regexp(nil),
			`GetAllowedPaths() always returns empty slice when empty token is given`)
		assert.Equal(holder.GetAllowedPaths("some"), []*regexp.Regexp(nil),
			`GetAllowedPaths() returns emplty slice when not existing token is given`)

		assert.Len(holder.GetAllowedPaths("TOKEN1"), 0,
			`GetAllowedPaths("TOKEN1") returns 0 length slice`)
		assert.Len(holder.GetAllowedPaths("TOKEN2"), 0,
			`GetAllowedPaths("TOKEN2") returns 0 length slice`)
	})
}

func TestNewHolderWithInvalidJson(t *testing.T) {
	assert := assert.New(t)
	tearDown := setUp(t)
	defer tearDown()

	json := `
	{
		"TOKEN1": ["^/foo/\\d+/*", 1, "^/bar/*", "(["],
		"TOKEN2": "dummy",
	}
	`
	os.Setenv(AuthTokens, json)

	holder := NewHolder()

	t.Run("GetTokens()", func(t *testing.T) {
		assert.Equal(holder.GetTokens(), []string{},
			`GetTokens() returns empty slice when AUTH_TOKENS is invalid json`)
		assert.NotContains(holder.GetTokens(), "TOKEN1",
			`GetTokens() dows not contain "TOKEN1"`)
		assert.NotContains(holder.GetTokens(), "TOKEN2",
			`GetTokens() does not contain "TOKEN2"`)
	})

	t.Run("HasToken()", func(t *testing.T) {
		assert.False(holder.HasToken(""),
			`HasToken() always returns false when empty token is given`)
		assert.False(holder.HasToken("some"),
			`HasToken() returns false when not existing token is given`)
		assert.False(holder.HasToken("TOKEN1"),
			`HasToken() returns false when AUTH_TOKENS is invalid json`)
		assert.False(holder.HasToken("TOKEN2"),
			`HasToken() returns false when AUTH_TOKENS is invalid json`)
	})

	t.Run("GetAllowedPaths()", func(t *testing.T) {
		assert.Equal(holder.GetAllowedPaths(""), []*regexp.Regexp(nil),
			`GetAllowedPaths() always returns empty slice when empty token is given`)
		assert.Equal(holder.GetAllowedPaths("some"), []*regexp.Regexp(nil),
			`GetAllowedPaths() returns emplty slice when not existing token is given`)

		assert.Len(holder.GetAllowedPaths("TOKEN1"), 0,
			`GetAllowedPaths("TOKEN1") returns 0 length slice`)
		assert.Len(holder.GetAllowedPaths("TOKEN2"), 0,
			`GetAllowedPaths("TOKEN2") returns 0 length slice`)
	})
}
