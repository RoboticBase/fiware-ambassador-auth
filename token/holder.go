/*
Package token : hold token configurations to check sing HTTP Header.

	license: Apache license 2.0
	copyright: Nobuyuki Matsui <nobuyuki.matsui@gmail.com>
*/
package token

import (
	"encoding/json"
	"log"
	"os"
	"regexp"
)

/*
AuthTokens : AUTH_TOKEN is an environment vairable name to set token configurations.
*/
const AuthTokens = "AUTH_TOKENS"

/*
Holder : a struct to hold token configurations.
	Holder construct token configurations from "AUTH_TOKEN" environment variable.
*/
type Holder struct {
	bearerTokenAllowdPathes map[string][]*regexp.Regexp
	bearerTokens            []string
	basicAuthPathes         map[string]map[string]string
}

type authTokens struct {
	BearerTokens []bearerTokens `json:"bearer_tokens"`
	BasicAuths   []basicAuths   `json:"basic_auths"`
}

type bearerTokens struct {
	Token           string   `json:"token"`
	RawAllowedPaths []string `json:"allowed_paths"`
}

type basicAuths struct {
	Username        string   `json:"username"`
	Password        string   `json:"password"`
	RawAllowedPaths []string `json:"allowed_paths"`
}

/*
NewHolder : a factory method to create Holder.
*/
func NewHolder() *Holder {
	rawTokens := os.Getenv(AuthTokens)
	if len(rawTokens) == 0 {
		rawTokens = "{}"
	}
	log.Printf("%s: %v\n--------\n", AuthTokens, rawTokens)

	var authTokenList authTokens

	bearerTokenAllowdPathes := map[string][]*regexp.Regexp{}
	bearerTokens := []string{}
	basicAuthPathes := map[string]map[string]string{}

	if err := json.Unmarshal([]byte(rawTokens), &authTokenList); err == nil {
		for _, bearerToken := range authTokenList.BearerTokens {
			sl := make([]*regexp.Regexp, 0, 0)
			for _, rawAllowedPath := range bearerToken.RawAllowedPaths {
				tokenRe, err := regexp.Compile(rawAllowedPath)
				if err == nil && tokenRe != nil {
					sl = append(sl, tokenRe)
				}
			}
			bearerTokenAllowdPathes[bearerToken.Token] = sl
			bearerTokens = append(bearerTokens, bearerToken.Token)
		}
		for _, basicAuth := range authTokenList.BasicAuths {
			for _, rawAllowedPath := range basicAuth.RawAllowedPaths {
				_, exist := basicAuthPathes[rawAllowedPath]
				if !exist {
					basicAuthPathes[rawAllowedPath] = map[string]string{}
				}
				basicAuthPathes[rawAllowedPath][basicAuth.Username] = basicAuth.Password
			}
		}
	} else {
		log.Printf("AUTH_TOKENS parse failed: %v\n", err)
	}

	log.Printf("bearerTokenAllowdPathes: %v\n--------\n", bearerTokenAllowdPathes)
	log.Printf("basicAuthPathes, %v\n--------\n", basicAuthPathes)

	return &Holder{
		bearerTokenAllowdPathes: bearerTokenAllowdPathes,
		bearerTokens:            bearerTokens,
		basicAuthPathes:         basicAuthPathes,
	}
}

/*
GetTokens : get all bearer tokens held in this Holder.
*/
func (holder *Holder) GetTokens() []string {
	return holder.bearerTokens
}

/*
HasToken : check whether the bearer token is held in this Holder.
*/
func (holder *Holder) HasToken(token string) bool {
	_, ok := holder.bearerTokenAllowdPathes[token]
	return ok
}

/*
GetAllowedPaths : get all allowed paths associated with the bearer token.
*/
func (holder *Holder) GetAllowedPaths(token string) []*regexp.Regexp {
	return holder.bearerTokenAllowdPathes[token]
}

/*
GetBasicAuthConf : get all configurations of basic authentication.
*/
func (holder *Holder) GetBasicAuthConf() map[string]map[string]string {
	return holder.basicAuthPathes
}
