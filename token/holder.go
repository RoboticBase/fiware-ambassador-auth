/*
Package token : hold token configurations to check sing HTTP Header.

	license: Apache license 2.0
	copyright: Nobuyuki Matsui <nobuyuki.matsui@gmail.com>
*/
package token

import (
	"encoding/json"
	"errors"
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

/*
UnmarshalJSON : Unmarshal AUTH_TOKENS and check required
*/
func (t *authTokens) UnmarshalJSON(b []byte) error {
	type authTokensP struct {
		BearerTokens *[]bearerTokens `json:"bearer_tokens"`
		BasicAuths   *[]basicAuths   `json:"basic_auths"`
	}
	var p authTokensP
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	if p.BearerTokens == nil {
		return errors.New("bearer_tokens is required")
	}
	t.BearerTokens = *p.BearerTokens
	if p.BasicAuths == nil {
		return errors.New("basic_auths is required")
	}
	t.BasicAuths = *p.BasicAuths
	return nil
}

type bearerTokens struct {
	Token           string   `json:"token"`
	RawAllowedPaths []string `json:"allowed_paths"`
}

/*
UnmarshalJSON : Unmarshal AUTH_TOKENS and check required
*/
func (t *bearerTokens) UnmarshalJSON(b []byte) error {
	type bearerTokensP struct {
		Token           *string   `json:"token"`
		RawAllowedPaths *[]string `json:"allowed_paths"`
	}
	var p bearerTokensP
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	if p.Token == nil {
		return errors.New("token is required")
	}
	t.Token = *p.Token
	if p.RawAllowedPaths == nil {
		return errors.New("allowed_paths is required")
	}
	t.RawAllowedPaths = *p.RawAllowedPaths
	return nil
}

type basicAuths struct {
	Username        string   `json:"username"`
	Password        string   `json:"password"`
	RawAllowedPaths []string `json:"allowed_paths"`
}

/*
UnmarshalJSON : Unmarshal AUTH_TOKENS and check required
*/
func (a *basicAuths) UnmarshalJSON(b []byte) error {
	type basicAuthsP struct {
		Username        *string   `json:"username"`
		Password        *string   `json:"password"`
		RawAllowedPaths *[]string `json:"allowed_paths"`
	}
	var p basicAuthsP
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	if p.Username == nil {
		return errors.New("username is required")
	}
	a.Username = *p.Username
	if p.Password == nil {
		return errors.New("password is required")
	}
	a.Password = *p.Password
	if p.RawAllowedPaths == nil {
		return errors.New("allowed_paths is required")
	}
	a.RawAllowedPaths = *p.RawAllowedPaths
	return nil
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
			if len(sl) > 0 {
				bearerTokenAllowdPathes[bearerToken.Token] = sl
				bearerTokens = append(bearerTokens, bearerToken.Token)
			}
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
