/*
Package router : authorize and authenticate HTTP Request using HTTP Header.

	license: Apache license 2.0
	copyright: Nobuyuki Matsui <nobuyuki.matsui@gmail.com>
*/
package router

import (
	"net/http"
	"regexp"

	"github.com/gin-gonic/gin"

	"github.com/tech-sketch/fiware-bearer-auth/token"
)

const authHeader = "authorization"
const bearerRe = `(?i)^bearer (.+)$`

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

	tokenRe := regexp.MustCompile(bearerRe)

	for path, user := range holder.GetBasicAuthConf() {
		basicAuthGroup := engine.Group(path, gin.BasicAuth(user))
		basicAuthGroup.Any("/", func(context *gin.Context) {
			statusOK(context)
		})
	}

	engine.NoRoute(func(context *gin.Context) {
		authHeader := context.Request.Header.Get(authHeader)
		if len(authHeader) == 0 {
			authHeaderMissing(context)
		} else {
			matches := tokenRe.FindAllStringSubmatch(authHeader, -1)
			if len(matches) == 0 || !holder.HasToken(matches[0][1]) {
				tokenMissmatch(context)
			} else if !matchPath(context, holder.GetAllowedPaths(matches[0][1])) {
				pathNotAllowed(context)
			} else {
				statusOK(context)
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

func matchPath(context *gin.Context, allowedPaths []*regexp.Regexp) bool {
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

func statusOK(context *gin.Context) {
	context.JSON(http.StatusOK, gin.H{
		"authorized": true,
	})
}
