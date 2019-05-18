/*
Package token : hold token configurations to check sing HTTP Header.

	license: Apache license 2.0
	copyright: Nobuyuki Matsui <nobuyuki.matsui@gmail.com>
*/
package token

import (
	"encoding/json"
	"errors"
	"github.com/fsnotify/fsnotify"
	"io/ioutil"
	"log"
	"os"
	"regexp"
)

/*
AuthTokens : AUTH_TOKENS is an environment vairable name to set token configurations.
*/
const AuthTokens = "AUTH_TOKENS"

/*
AuthTokensPath : AUTH_TOKENS_PATH is an environment vairable name to set the file path of token configurations file.
*/
const AuthTokensPath = "AUTH_TOKENS_PATH"

/*
Holder : a struct to hold token configurations.
	Holder construct token configurations from "AUTH_TOKEN" environment variable.
*/
type Holder struct {
	hosts                   []string
	bearerTokenAllowedPaths map[string]map[string][]*regexp.Regexp
	bearerTokens            map[string][]string
	basicAuthPaths          map[string]map[string]map[string]string
	noAuthPaths             map[string][]string
}

type hostSettings struct {
	Host       string     `json:"host"`
	AuthTokens authTokens `json:"settings"`
}

/*
UnmarshalJSON : Unmarshal AUTH_TOKENS and check required
*/
func (s *hostSettings) UnmarshalJSON(b []byte) error {
	type hostSettingsP struct {
		Host       *string     `json:"host"`
		AuthTokens *authTokens `json:"settings"`
	}
	var p hostSettingsP
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	if p.Host == nil {
		return errors.New("host is required")
	}
	s.Host = *p.Host
	if p.AuthTokens == nil {
		return errors.New("seettings is required")
	}
	s.AuthTokens = *p.AuthTokens
	return nil
}

type authTokens struct {
	BearerTokens []bearerTokens `json:"bearer_tokens"`
	BasicAuths   []basicAuths   `json:"basic_auths"`
	NoAuths      noAuths        `json:"no_auths"`
}

/*
UnmarshalJSON : Unmarshal AUTH_TOKENS and check required
*/
func (t *authTokens) UnmarshalJSON(b []byte) error {
	type authTokensP struct {
		BearerTokens *[]bearerTokens `json:"bearer_tokens"`
		BasicAuths   *[]basicAuths   `json:"basic_auths"`
		NoAuths      *noAuths        `json:"no_auths"`
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
	if p.NoAuths == nil {
		return errors.New("no_auths is required")
	}
	t.NoAuths = *p.NoAuths
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
		return errors.New("bearer_tokens.token is required")
	}
	t.Token = *p.Token
	if p.RawAllowedPaths == nil {
		return errors.New("bearer_tokens.allowed_paths is required")
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
		return errors.New("basic_auths.username is required")
	}
	a.Username = *p.Username
	if p.Password == nil {
		return errors.New("basic_auths.password is required")
	}
	a.Password = *p.Password
	if p.RawAllowedPaths == nil {
		return errors.New("basic_auths.allowed_paths is required")
	}
	a.RawAllowedPaths = *p.RawAllowedPaths
	return nil
}

type noAuths struct {
	RawAllowedPaths []string `json:"allowed_paths"`
}

/*
UnmarshalJSON : Unmarshal AUTH_TOKENS and check required
*/
func (n *noAuths) UnmarshalJSON(b []byte) error {
	type noAuthsP struct {
		RawAllowedPaths *[]string `json:"allowed_paths"`
	}
	var p noAuthsP
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	if p.RawAllowedPaths == nil {
		n.RawAllowedPaths = []string{}
	} else {
		n.RawAllowedPaths = *p.RawAllowedPaths
	}
	return nil
}

/*
NewHolder : a factory method to create Holder.
*/
func NewHolder() *Holder {
	var holder Holder
	rawTokensPath := os.Getenv(AuthTokensPath)
	if len(rawTokensPath) != 0 {
		loadFile(&holder, rawTokensPath)
		go monitor(&holder, rawTokensPath)
	} else {
		loadEnv(&holder)
	}
	return &holder
}

func loadFile(holder *Holder, rawTokensPath string) {
	rawTokens := []byte("[]")
	if len(rawTokensPath) != 0 {
		f, err := os.Open(rawTokensPath)
		defer f.Close()
		if err == nil {
			log.Printf("read tokens from \"%s\"\n", rawTokensPath)
			rawTokens, err = ioutil.ReadAll(f)
		} else {
			log.Printf("can not open AUTH_TOKENS_PATH: %s\n", rawTokensPath)
		}
	} else {
		log.Printf("empty AUTH_TOKENS_PATH\n")
	}
	log.Printf("rawTokens: \n%s\n--------\n", rawTokens)
	makeHolder(holder, rawTokens)
}

func loadEnv(holder *Holder) {
	rawTokensStr := os.Getenv(AuthTokens)
	if len(rawTokensStr) == 0 {
		rawTokensStr = "[]"
	}
	log.Printf("%s: %v\n--------\n", AuthTokens, rawTokensStr)
	makeHolder(holder, []byte(rawTokensStr))
}

func makeHolder(holder *Holder, rawTokens []byte) {
	var hostSettingsList []hostSettings

	hosts := []string{}
	bearerTokenAllowedPaths := map[string]map[string][]*regexp.Regexp{}
	bearerTokens := map[string][]string{}
	basicAuthPaths := map[string]map[string]map[string]string{}
	noAuthPaths := map[string][]string{}

	if err := json.Unmarshal(rawTokens, &hostSettingsList); err == nil {
		for _, hostSettings := range hostSettingsList {
			hosts = append(hosts, hostSettings.Host)
			for _, bearerToken := range hostSettings.AuthTokens.BearerTokens {
				sl := make([]*regexp.Regexp, 0, 0)
				for _, rawAllowedPath := range bearerToken.RawAllowedPaths {
					tokenRe, err := regexp.Compile(rawAllowedPath)
					if err == nil && tokenRe != nil {
						sl = append(sl, tokenRe)
					}
				}
				if len(sl) > 0 {
					if _, ok := bearerTokenAllowedPaths[hostSettings.Host]; !ok {
						bearerTokenAllowedPaths[hostSettings.Host] = map[string][]*regexp.Regexp{}
					}
					bearerTokenAllowedPaths[hostSettings.Host][bearerToken.Token] = sl
					if _, ok := bearerTokens[hostSettings.Host]; !ok {
						bearerTokens[hostSettings.Host] = []string{}
					}
					bearerTokens[hostSettings.Host] = append(bearerTokens[hostSettings.Host], bearerToken.Token)
				}
			}

			for _, basicAuth := range hostSettings.AuthTokens.BasicAuths {
				for _, rawAllowedPath := range basicAuth.RawAllowedPaths {
					if _, ok := basicAuthPaths[hostSettings.Host]; !ok {
						basicAuthPaths[hostSettings.Host] = map[string]map[string]string{}
					}
					if _, ok := basicAuthPaths[hostSettings.Host][rawAllowedPath]; !ok {
						basicAuthPaths[hostSettings.Host][rawAllowedPath] = map[string]string{}
					}
					basicAuthPaths[hostSettings.Host][rawAllowedPath][basicAuth.Username] = basicAuth.Password
				}
			}
			noAuthPaths[hostSettings.Host] = hostSettings.AuthTokens.NoAuths.RawAllowedPaths
		}
	} else {
		log.Printf("AUTH_TOKENS parse failed: %v\n", err)
	}

	log.Printf("hosts: %v\n--------\n", hosts)
	log.Printf("bearerTokenAllowedPaths: %v\n--------\n", bearerTokenAllowedPaths)
	log.Printf("basicAuthPaths, %v\n--------\n", basicAuthPaths)
	log.Printf("noAuthPaths, %v\n--------\n", noAuthPaths)

	holder.hosts = hosts
	holder.bearerTokenAllowedPaths = bearerTokenAllowedPaths
	holder.bearerTokens = bearerTokens
	holder.basicAuthPaths = basicAuthPaths
	holder.noAuthPaths = noAuthPaths
}

func monitor(holder *Holder, rawTokensPath string) {
	watcher, _ := fsnotify.NewWatcher()
	defer watcher.Close()
	for {
		err := watcher.Add(rawTokensPath)
		if err != nil {
			log.Printf("watcher failed: %v\n", err)
			return
		}
		select {
		case <-watcher.Events:
			loadFile(holder, rawTokensPath)
		}
	}
}

/*
GetHosts : get all hosts held in this Hoder.
*/
func (holder *Holder) GetHosts() []string {
	return holder.hosts
}

/*
GetTokens : get all bearer tokens associated with the host.
*/
func (holder *Holder) GetTokens(host string) []string {
	return holder.bearerTokens[host]
}

/*
HasToken : check whether the bearer token associated with the host is held in this Holder.
*/
func (holder *Holder) HasToken(host string, token string) bool {
	_, ok := holder.bearerTokenAllowedPaths[host][token]
	return ok
}

/*
GetAllowedPaths : get all allowed paths associated with the bearer token.
*/
func (holder *Holder) GetAllowedPaths(host string, token string) []*regexp.Regexp {
	return holder.bearerTokenAllowedPaths[host][token]
}

/*
GetBasicAuthConf : get all configurations of basic authentication associated with the host.
*/
func (holder *Holder) GetBasicAuthConf(host string) map[string]map[string]string {
	return holder.basicAuthPaths[host]
}

/*
GetNoAuthPaths : get all allowed paths without authentication associated with the host.
*/
func (holder *Holder) GetNoAuthPaths(host string) []string {
	return holder.noAuthPaths[host]
}
