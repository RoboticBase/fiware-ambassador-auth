/*
Package main : entry point of fiware-ambassador-auth.

	license: Apache license 2.0
	copyright: Nobuyuki Matsui <nobuyuki.matsui@gmail.com>
*/
package main

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetListenPortNoEnv(t *testing.T) {
	assert := assert.New(t)

	port := getListenPort()
	assert.Equal(port, ":"+defaultPort)
}

func TestGetListenPortWithEnv(t *testing.T) {
	assert := assert.New(t)

	defaultPort := ":" + defaultPort
	cases := []struct {
		port   string
		expect string
		desc   string
	}{
		{port: "", expect: defaultPort, desc: "empty"},
		{port: "3000", expect: ":3000", desc: "valid port"},
		{port: "dummy", expect: defaultPort, desc: "not int"},
		{port: "-1", expect: defaultPort, desc: "port < 1"},
		{port: "65536", expect: defaultPort, desc: "65535 < port"},
	}

	for _, c := range cases {
		t.Run(fmt.Sprintf("port=%v", c.port), func(t *testing.T) {
			os.Setenv(listenPort, c.port)

			port := getListenPort()
			assert.Equal(port, c.expect, c.desc)
			os.Unsetenv(listenPort)
		})
	}
}
