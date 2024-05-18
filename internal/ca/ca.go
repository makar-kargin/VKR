package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math"
	"math/big"
	"net"
	"time"
)

type CertConfig struct {
	CommonName string
	AltNames   struct {
		DNSNames []string
		IPs      []net.IP
	}
}

func NewSelfSignedCertificate(key *rsa.PrivateKey) ([]byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).SetInt64(math.MaxInt64))
	if err != nil {
		return nil, err
	}
	certTmpl := &x509.Certificate{
		IsCA:                  true,
		BasicConstraintsValid: true,
		Subject: pkix.Name{
			Country:      []string{"RU"},
			CommonName:   "my-ca.ru",
			Organization: []string{"my-organization"},
		},
		NotAfter:     time.Now().Add(time.Hour * 24 * 365 * 5).UTC(),
		NotBefore:    time.Now(),
		SerialNumber: serial,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	cert, err := x509.CreateCertificate(rand.Reader, certTmpl, certTmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func NewSignedCertificate(cfg CertConfig, key *rsa.PublicKey, caCert *x509.Certificate, caKey *rsa.PrivateKey, attrs string) ([]byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).SetInt64(math.MaxInt64))
	if err != nil {
		return nil, err
	}
	ext, err := asn1.Marshal(attrs)
	if err != nil {
		return nil, err
	}

	certTmpl := x509.Certificate{
		Subject: pkix.Name{
			CommonName:   cfg.CommonName,
			Organization: caCert.Subject.Organization,
		},
		DNSNames:     cfg.AltNames.DNSNames,
		IPAddresses:  cfg.AltNames.IPs,
		SerialNumber: serial,
		NotBefore:    caCert.NotBefore,
		NotAfter:     time.Now().Add(time.Hour * 24 * 365).UTC(),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		Extensions: []pkix.Extension{
			{
				Id:    asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7},
				Value: ext,
			},
		},
		ExtraExtensions: []pkix.Extension{
			{
				Id:    asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7},
				Value: ext,
			},
		},
	}
	certDERBytes, err := x509.CreateCertificate(rand.Reader, &certTmpl, caCert, key, caKey)
	if err != nil {
		return nil, err
	}
	return certDERBytes, nil
}
