package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"
)

var version string

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *responseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func www(root string, quiet bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lw := &responseWriter{w, http.StatusOK}
		http.StripPrefix("/", http.FileServer(http.Dir(root))).ServeHTTP(lw, r)
		if !quiet {
			log.Printf("%s [%s] %d %s", r.RemoteAddr, r.URL, lw.statusCode, time.Since(start))
		}
	})
}

func createSSL() ([]byte, []byte, error) {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	host, err := os.Hostname()
	if err != nil {
		return nil, nil, err
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{Organization: []string{"localhost"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", host},
	}
	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	crt, err := x509.CreateCertificate(rand.Reader, &template, &template, &privatekey.PublicKey, privatekey)
	if err != nil {
		return nil, nil, err
	}
	var certOut, keyOut bytes.Buffer
	pem.Encode(&certOut, &pem.Block{Type: "CERTIFICATE", Bytes: crt})
	pem.Encode(&keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privatekey)})
	return certOut.Bytes(), keyOut.Bytes(), nil
}

func main() {
	p := flag.Int("p", 8000, "Listen on `port`")
	q := flag.Bool("q", false, "`quiet` mode")
	r := flag.String("r", ".", "Document `root` path")
	ssl := flag.Bool("ssl", false, "Enable `SSL` https://")
	v := flag.Bool("v", false, fmt.Sprintf("Print version: %s", version))
	flag.Parse()
	if *v {
		fmt.Println(version)
		os.Exit(0)
	}
	if !*q {
		log.Printf("Listening on port: %d\n", *p)
	}
	srv := &http.Server{Addr: fmt.Sprintf(":%d", *p), Handler: www(*r, *q)}
	if *ssl {
		certPEMBlock, keyPEMBlock, err := createSSL()
		if err != nil {
			log.Fatal(err)
		}
		config := &tls.Config{Certificates: make([]tls.Certificate, 1)}
		if config.Certificates[0], err = tls.X509KeyPair(certPEMBlock, keyPEMBlock); err != nil {
			log.Fatal(err)
		}
		srv.TLSConfig = config
		log.Fatal(srv.ListenAndServeTLS("", ""))
	}
	log.Fatal(srv.ListenAndServe())
}
