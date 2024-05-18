package service

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/makar-kargin/VKR/internal/auth"
)

var (
	oidAuthInfo = asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7}
)

type Service struct {
	clientCertPath string
	clientKeyPath  string
	Server         *http.Server
	Client         *http.Client
	AllowedSrv     []string
}

func New(clientCertPath string, clientKeyPath string, caCertPath string, allowed []string) (*Service, error) {
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	cert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		return nil, err
	}

	srv := &http.Server{
		Addr: ":8443",
		TLSConfig: &tls.Config{
			ClientCAs:  caCertPool,
			ClientAuth: tls.RequireAndVerifyClientCert,
		},
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caCertPool,
				Certificates: []tls.Certificate{cert},
			},
		},
	}

	return &Service{
		clientCertPath: clientCertPath,
		clientKeyPath:  clientKeyPath,
		Server:         srv,
		Client:         client,
		AllowedSrv:     allowed,
	}, nil
}

func (s *Service) authHandler() func(w http.ResponseWriter, r *http.Request) {
	var authInfo auth.Info
	fn := func(w http.ResponseWriter, r *http.Request) {
		certs := r.TLS.PeerCertificates
		for _, cert := range certs {
			for _, ext := range cert.Extensions {
				if !ext.Id.Equal(oidAuthInfo) {
					continue
				}

				var S interface{}
				_, err := asn1.Unmarshal(ext.Value, &S)
				if err != nil {
					return
				}

				str, ok := S.(string)
				if !ok {
					return
				}

				err = json.Unmarshal([]byte(str), &authInfo)
				if err != nil {
					return
				}
			}
		}

		var rsp string
		peerName, _ := authInfo.GetPeerName()

		if !s.authorize(authInfo) {
			w.WriteHeader(http.StatusForbidden)
			rsp = fmt.Sprintf("Service %s, you are not allowed!\n", peerName)
			io.WriteString(w, rsp)
			return
		}

		rsp = fmt.Sprintf("Hello, service %s!\n", peerName)
		io.WriteString(w, rsp)
	}

	return fn
}

func (s *Service) authorize(authInfo auth.Info) bool {
	peerName, ok := authInfo.GetPeerName()
	if !ok {
		return false
	}

	for _, srv := range s.AllowedSrv {
		if srv == peerName {
			return true
		}
	}

	return false
}

func (s *Service) Get(url string) (string, error) {
	r, err := s.Client.Get(url)
	if err != nil {
		return "", err
	}

	// Read the response body
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

func (s *Service) Serve() {
	// Set up a /hello resource handler
	http.HandleFunc("/hello", s.authHandler())

	// Listen to HTTPS connections with the server certificate and wait
	log.Fatal(s.Server.ListenAndServeTLS(s.clientCertPath, s.clientKeyPath))
}
