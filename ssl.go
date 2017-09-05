package www

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path"
	"time"
)

// CreateSSL creates certificate and public key
func CreateSSL(certPath string) error {
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
		NotAfter:    time.Now().AddDate(1, 0, 0),
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

	// create /tmp/.www.pem
	pemFile, err := os.OpenFile(path.Join(certPath, ".www.pem"), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0400)
	if err != nil {
		return err
	}
	pem.Encode(pemFile, &pem.Block{Type: "CERTIFICATE", Bytes: crt})
	pemFile.Close()

	// create /tmp/.www.key
	keyFile, err := os.OpenFile(path.Join(certPath, ".www.key"), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0400)
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
