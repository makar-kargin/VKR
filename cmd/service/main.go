package main

import (
	"encoding/json"
	"flag"
	"fmt"

	"github.com/makar-kargin/VKR/internal/service"
)

var (
	isServer bool
	url      string
	caPath   string
	crtPath  string
	keyPath  string
	allowed  string
)

func main() {
	flag.Parse()

	var allowedNames []string
	err := json.Unmarshal([]byte(allowed), &allowedNames)
	if err != nil {
		panic(err)
	}

	srv, err := service.New(
		crtPath,
		keyPath,
		caPath,
		allowedNames,
	)

	if err != nil {
		panic(err)
	}

	if isServer {
		srv.Serve()
	} else {
		if url == "" {
			panic("url is empty")
		}

		rsp, err := srv.Get(url)
		if err != nil {
			panic(err)
		}

		fmt.Println(rsp)
	}
}

func init() {
	flag.BoolVar(&isServer, "srv", false, "choose server or client mode")
	flag.StringVar(&allowed, "allow", "", "allowed services")
	flag.StringVar(&url, "url", "", "url")
	flag.StringVar(&caPath, "ca", "/Users/makar-kargin/certs/my-ca.pem", "ca path")
	flag.StringVar(&crtPath, "cert", "/Users/makar-kargin/certs/service-1.ru-cert.pem", "client cert path")
	flag.StringVar(&keyPath, "key", "/Users/makar-kargin/certs/service-1.ru-key.pem", "client key path")
}
