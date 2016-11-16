package www

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/user"
	"path"
	"time"
)

func CreateSSL() error {
	usr, err := user.Current()
	if err != nil {
		return err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)

	host, err := os.Hostname()
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"localhost"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(3, 0, 0),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"localhost", host},
	}

	// generate private key
	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	publickey := &privatekey.PublicKey

	// create a self-signed certificate.
	crt, err := x509.CreateCertificate(rand.Reader, &template, &template, publickey, privatekey)
	if err != nil {
		return err
	}

	// create ~/.www.pem
	pemFile, err := os.Create(path.Join(usr.HomeDir, ".www.pem"))
	if err != nil {
		return err
	}
	pem.Encode(pemFile, &pem.Block{Type: "CERTIFICATE", Bytes: crt})
	pemFile.Close()

	// create ~/.www.key
	keyFile, err := os.Create(path.Join(usr.HomeDir, ".www.key"))
	if err != nil {
		return err
	}
	pem.Encode(keyFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privatekey)},
	)
	keyFile.Close()

	return nil
}
