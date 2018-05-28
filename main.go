/*
Package main : entry point of fiware-ambassador-auth.

	license: Apache license 2.0
	copyright: Nobuyuki Matsui <nobuyuki.matsui@gmail.com>
*/
package main

import (
	"os"
	"strconv"

	"github.com/tech-sketch/fiware-ambassador-auth/router"
)

const listenPort = "LISTEN_PORT"
const defaultPort = "8080"

func main() {
	handler := router.NewHandler()
	handler.Run(getListenPort())
}

func getListenPort() string {
	port := os.Getenv(listenPort)
	if len(port) == 0 {
		port = defaultPort
	}
	intPort, err := strconv.Atoi(port)
	if err != nil || intPort < 1 || 65535 < intPort {
		port = defaultPort
	}

	return ":" + port
}
