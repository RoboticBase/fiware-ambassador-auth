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
	"reflect"
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
	tokens map[string][]*regexp.Regexp
	keys   []string
}

/*
NewHolder : a factory method to create Holder.
*/
func NewHolder() *Holder {
	rawTokens := os.Getenv(AuthTokens)
	if len(rawTokens) == 0 {
		rawTokens = "{}"
	}

	tokens := map[string][]*regexp.Regexp{}
	keys := []string{}

	var obj interface{}
	if err := json.Unmarshal([]byte(rawTokens), &obj); err == nil {
		switch jsonTokens := obj.(type) {
		case map[string]interface{}:
			for k, v := range jsonTokens {
				rv := reflect.ValueOf(v)
				if rv.Kind() == reflect.Slice {
					sl := make([]*regexp.Regexp, 0, 0)
					for i := 0; i < rv.Len(); i++ {
						switch tokenValue := rv.Index(i).Interface().(type) {
						case string:
							tokenRe, err := regexp.Compile(tokenValue)
							if err == nil && tokenRe != nil {
								sl = append(sl, tokenRe)
							}
						}
					}
					tokens[k] = sl
				}
			}
		}
		for k := range tokens {
			keys = append(keys, k)
		}
	} else {
		log.Printf("AUTH_TOKENS parse failed: %v\n", err)
	}

	return &Holder{
		tokens: tokens,
		keys:   keys,
	}
}

/*
GetTokens : get all bearer tokens held in this Holder.
*/
func (holder *Holder) GetTokens() []string {
	return holder.keys
}

/*
HasToken : check whether the bearer token is held in this Holder.
*/
func (holder *Holder) HasToken(token string) bool {
	_, ok := holder.tokens[token]
	return ok
}

/*
GetAllowedPaths : get all allowed paths associated with the bearer token.
*/
func (holder *Holder) GetAllowedPaths(token string) []*regexp.Regexp {
	return holder.tokens[token]
}
