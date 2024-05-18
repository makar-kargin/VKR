package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/makar-kargin/VKR/internal/auth"
	"github.com/makar-kargin/VKR/internal/ca"
)

var (
	caPath    string
	caKeyPath string
	host      string
	srvName   string
)

func main() {
	flag.Parse()
	var caCert *x509.Certificate
	var caKey *rsa.PrivateKey
	var err error

	if caPath == "" && caKeyPath == "" {
		caKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		keyBytes := x509.MarshalPKCS1PrivateKey(caKey)
		// PEM encoding of private key
		keyPEM := pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: keyBytes,
			},
		)
		err = os.WriteFile("ca-key.pem", keyPEM, 0644)
		if err != nil {
			panic(err)
		}

		rawCaCert, err := ca.NewSelfSignedCertificate(caKey)
		if err != nil {
			panic(err)
		}
		caCert, err = x509.ParseCertificate(rawCaCert)
		if err != nil {
			panic(err)
		}
		pemBytes := pem.EncodeToMemory(
			&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: rawCaCert,
			},
		)
		err = os.WriteFile("my-ca.pem", pemBytes, 0644)
		if err != nil {
			panic(err)
		}
	} else {
		cert, err := tls.LoadX509KeyPair(caPath, caKeyPath)
		if err != nil {
			panic(err)
		}

		caKey = cert.PrivateKey.(*rsa.PrivateKey)

		pubPEM, err := os.ReadFile(caPath)
		if err != nil {
			panic(err)
		}

		block, _ := pem.Decode(pubPEM)
		if block == nil {
			panic("failed to decode PEM data")
		}
		certs, err := x509.ParseCertificates(block.Bytes)
		if err != nil {
			panic("failed to parse certificates")
		}

		caCert = certs[0]
	}

	fmt.Println(caCert.Subject.CommonName)

	cfg := ca.CertConfig{
		CommonName: host,
		AltNames: struct {
			DNSNames []string
			IPs      []net.IP
		}{
			DNSNames: []string{host},
		},
	}

	myKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	keyBytes := x509.MarshalPKCS1PrivateKey(myKey)
	// PEM encoding of private key
	keyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: keyBytes,
		},
	)

	err = os.WriteFile(fmt.Sprintf("%s-key.pem", host), keyPEM, 0644)
	if err != nil {
		panic(err)
	}
	var authInfo auth.Info
	authInfo.Attrs = map[string]string{
		"name": srvName,
	}

	authStr, err := json.Marshal(authInfo)
	if err != nil {
		panic(err)
	}

	myCertRaw, err := ca.NewSignedCertificate(cfg, &myKey.PublicKey, caCert, caKey, string(authStr))
	if err != nil {
		panic(err)
	}
	_, err = x509.ParseCertificate(myCertRaw)
	if err != nil {
		panic(err)
	}

	pemBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: myCertRaw,
		},
	)
	err = os.WriteFile(fmt.Sprintf("%s-cert.pem", host), pemBytes, 0644)
	if err != nil {
		panic(err)
	}
}

func init() {
	flag.StringVar(&host, "host", "", "host")
	flag.StringVar(&caPath, "ca-cert", "", "path to ca cert")
	flag.StringVar(&caKeyPath, "ca-key", "", "path to ca key")
	flag.StringVar(&srvName, "name", "", "service name")
}
