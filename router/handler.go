/*
Package router : authorize and authenticate HTTP Request using HTTP Header.

	license: Apache license 2.0
	copyright: Nobuyuki Matsui <nobuyuki.matsui@gmail.com>
*/
package router

import (
	"encoding/base64"
	"net/http"
	"regexp"

	"github.com/gin-gonic/gin"

	"github.com/tech-sketch/fiware-ambassador-auth/token"

	lru "github.com/hashicorp/golang-lru"
)

const authHeader = "authorization"
const basicReStr = `(?i)^basic (.+)$`
const bearerReStr = `(?i)^bearer (.+)$`
const basicUserReStr = `^([^:]+):(.+)$`
const staticReStr = `^.*/static/.*$`
const basicAuthRequiredHeader = `Www-Authenticate: Basic realm="Authorization Required"`

/*
Handler : a struct to handle HTTP Request and check its Header.
	Handler encloses github.com/gin-gonic/gin.Engine.
	Handler authorizes and authenticates all HTTP Requests using its HTTP Header.
*/
type Handler struct {
	Engine                   *gin.Engine
	matchBasicAuthPathCache  *lru.Cache
	verifyBasicAuthCache     *lru.Cache
	matchBearerAuthPathCache *lru.Cache
}

/*
NewHandler : a factory method to create Handler.
*/
func NewHandler() *Handler {
	engine := gin.Default()
	holder := token.NewHolder()

	basicRe := regexp.MustCompile(basicReStr)
	basicUserRe := regexp.MustCompile(basicUserReStr)
	tokenRe := regexp.MustCompile(bearerReStr)
	pathRe := regexp.MustCompile(staticReStr)

	matchBasicAuthPathCache, err := lru.New(1024)
	verifyBasicAuthCache, err := lru.New(1024)
	matchBearerAuthPathCache, err := lru.New(1024)
	if err != nil {
		panic(err)
	}
	router := &Handler{
		Engine:                   engine,
		matchBasicAuthPathCache:  matchBasicAuthPathCache,
		verifyBasicAuthCache:     verifyBasicAuthCache,
		matchBearerAuthPathCache: matchBearerAuthPathCache,
	}

	engine.NoRoute(func(context *gin.Context) {
		path := context.Request.URL.Path
		authHeader := context.Request.Header.Get(authHeader)
		if pathRe.MatchString(path) {
			statusOK(context)
		} else if router.matchBasicAuthPath(path, holder.GetBasicAuthConf()) {
			if router.verifyBasicAuth(path, authHeader, basicRe, basicUserRe, holder.GetBasicAuthConf()) {
				statusOK(context)
			} else {
				basicAuthRequired(context)
			}
		} else {
			if len(authHeader) == 0 {
				authHeaderMissing(context)
			} else {
				matches := tokenRe.FindAllStringSubmatch(authHeader, -1)
				if len(matches) == 0 || !holder.HasToken(matches[0][1]) {
					tokenMissmatch(context)
				} else if !router.matchBearerAuthPath(path, matches[0][1], holder.GetAllowedPaths(matches[0][1])) {
					pathNotAllowed(context)
				} else {
					statusOK(context)
				}
			}
		}
	})

	return router
}

/*
Run : start listening HTTP Request using enclosed gin.Engine.
*/
func (router *Handler) Run(port string) {
	router.Engine.Run(port)
}

func (router *Handler) matchBasicAuthPath(path string, basicAuthConf map[string]map[string]string) bool {
	if !router.matchBasicAuthPathCache.Contains(path) {
		router.matchBasicAuthPathCache.Add(path, false)
		for pathReStr := range basicAuthConf {
			if regexp.MustCompile(pathReStr).MatchString(path) {
				router.matchBasicAuthPathCache.Add(path, true)
			}
		}
	}
	v, _ := router.matchBasicAuthPathCache.Get(path)
	r, _ := v.(bool)
	return r
}

func (router *Handler) verifyBasicAuth(path string, authHeader string, basicRe *regexp.Regexp, basicUserRe *regexp.Regexp, basicAuthConf map[string]map[string]string) bool {
	key := authHeader + "\t" + path
	if !router.verifyBasicAuthCache.Contains(key) {
		matches := basicRe.FindAllStringSubmatch(authHeader, -1)
		router.verifyBasicAuthCache.Add(key, false)
		if len(authHeader) > 0 && len(matches) > 0 {
			encodedUser, err := base64.StdEncoding.DecodeString(matches[0][1])
			if err == nil {
				userMatches := basicUserRe.FindAllStringSubmatch(string(encodedUser), -1)
				if len(userMatches[0]) == 3 {
					for pathReStr, user := range basicAuthConf {
						if regexp.MustCompile(pathReStr).MatchString(path) {
							password, ok := user[userMatches[0][1]]
							if ok {
								if password == userMatches[0][2] {
									router.verifyBasicAuthCache.Add(key, true)
								}
							}
						}
					}
				}
			}
		}
	}
	v, _ := router.verifyBasicAuthCache.Get(key)
	r, _ := v.(bool)
	return r
}

func (router *Handler) matchBearerAuthPath(path string, token string, allowedPaths []*regexp.Regexp) bool {
	key := token + "\t" + path
	if !router.matchBearerAuthPathCache.Contains(key) {
		router.matchBearerAuthPathCache.Add(key, false)
		for _, allowedPath := range allowedPaths {
			if allowedPath.MatchString(path) {
				router.matchBearerAuthPathCache.Add(key, true)
			}
		}
	}
	v, _ := router.matchBearerAuthPathCache.Get(key)
	r, _ := v.(bool)
	return r
}

func authHeaderMissing(context *gin.Context) {
	context.Writer.Header().Set("WWW-Authenticate", "Bearer realm=\"token_required\"")
	context.JSON(http.StatusUnauthorized, gin.H{
		"authorized": false,
		"error":      "missing Header: " + authHeader,
	})
}

func tokenMissmatch(context *gin.Context) {
	context.Writer.Header().Set("WWW-Authenticate", "Bearer realm=\"token_required\" error=\"invalid_token\"")
	context.JSON(http.StatusUnauthorized, gin.H{
		"authorized": false,
		"error":      "token mismatch",
	})
}

func pathNotAllowed(context *gin.Context) {
	context.Writer.Header().Set("WWW-Authenticate", "Bearer realm=\"token_required\" error=\"not_allowed\"")
	context.JSON(http.StatusForbidden, gin.H{
		"authorized": false,
		"error":      "not allowd",
	})
}

func basicAuthRequired(context *gin.Context) {
	context.Writer.Header().Set("WWW-Authenticate", "Basic realm=\"basic authentication required\"")
	context.String(http.StatusUnauthorized, "")
}

func statusOK(context *gin.Context) {
	context.JSON(http.StatusOK, gin.H{
		"authorized": true,
	})
}
