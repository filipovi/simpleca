package ca

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"github.com/filipovi/simpleca/pkg/certificat"
	"github.com/filipovi/simpleca/pkg/key"
)

// SimpleCA contains the root keys and certificat
type SimpleCA struct {
	pk *rsa.PrivateKey
	c  *x509.Certificate
}

// New return a SimpleCA instance
func New() (*SimpleCA, error) {
	pk, err := key.New("ca-key.pem")
	if err != nil {
		return nil, err
	}
	c, err := certificat.New("ca-cert.pem", pk)
	if err != nil {
		return nil, err
	}
	if err = check(pk, c); err != nil {
		return nil, err
	}
	key.Save("ca-key.pem")
	certificat.Save("ca-cert.pem")
	return &SimpleCA{pk, c}, nil
}

// GenerateSignedKeyAndCertificat returns a
func (ca *SimpleCA) GenerateSignedKeyAndCertificat(ips, dns []string) error {
	var cn string
	if len(dns) > 0 {
		cn = dns[0]
	} else {
		cn = ips[0]
	}
	folder := strings.Replace(cn, "*", "_", -1)
	err := os.Mkdir(folder, 0700)
	if err != nil && !os.IsExist(err) {
		return fmt.Errorf("Cannot create folder %s: %s", folder, err)
	}
	pk, err := key.New(fmt.Sprintf("%s/key.pem", folder))
	if err != nil {
		return err
	}
	c, err := certificat.NewSigned(fmt.Sprintf("%s/cert.pem", folder), cn, pk, ca.pk, ca.c, ips, dns)
	if err != nil {
		return err
	}
	if err = check(pk, c); err != nil {
		return err
	}
	key.Save(fmt.Sprintf("%s/key.pem", folder))
	certificat.Save(fmt.Sprintf("%s/cert.pem", folder))
	return nil
}

func check(pk *rsa.PrivateKey, c *x509.Certificate) error {
	isEqual, err := key.Equals(pk.Public(), c.PublicKey)
	if err != nil {
		return fmt.Errorf("comparing public keys: %s", err)
	}
	if !isEqual {
		return fmt.Errorf("public key in CA certificate doesn't match private key")
	}
	return nil
}
