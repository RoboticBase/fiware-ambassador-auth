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
	Engine *gin.Engine
}

/*
NewHandler : a factory method to create Handler.
*/
func NewHandler() *Handler {
	engine := gin.Default()
	holder := token.NewHolder()

	tokenRe := regexp.MustCompile(bearerReStr)
	pathRe := regexp.MustCompile(staticReStr)

	engine.NoRoute(func(context *gin.Context) {
		path := context.Request.URL.Path
		authHeader := context.Request.Header.Get(authHeader)
		if pathRe.MatchString(path) {
			statusOK(context)
		} else if matchBasicAuthPath(path, holder.GetBasicAuthConf()) {
			if verifyBasicAuth(path, authHeader, holder.GetBasicAuthConf()) {
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
				} else if !matchBearerAuthPath(context, holder.GetAllowedPaths(matches[0][1])) {
					pathNotAllowed(context)
				} else {
					statusOK(context)
				}
			}
		}
	})

	router := &Handler{
		Engine: engine,
	}
	return router
}

/*
Run : start listening HTTP Request using enclosed gin.Engine.
*/
func (router *Handler) Run(port string) {
	router.Engine.Run(port)
}

func matchBasicAuthPath(path string, basicAuthConf map[string]map[string]string) bool {
	for pathReStr := range basicAuthConf {
		if regexp.MustCompile(pathReStr).MatchString(path) {
			return true
		}
	}
	return false
}

func verifyBasicAuth(path string, authHeader string, basicAuthConf map[string]map[string]string) bool {
	basicRe := regexp.MustCompile(basicReStr)
	basicUserRe := regexp.MustCompile(basicUserReStr)
	matches := basicRe.FindAllStringSubmatch(authHeader, -1)
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
								return true
							}
						}
					}
				}
			}
		}
	}
	return false
}

func matchBearerAuthPath(context *gin.Context, allowedPaths []*regexp.Regexp) bool {
	path := context.Request.URL.Path
	for _, allowedPath := range allowedPaths {
		if allowedPath.MatchString(path) {
			return true
		}
	}
	return false
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
