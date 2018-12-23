package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

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
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject:      pkix.Name{Organization: []string{"www"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	crt, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}
	privKey, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: crt}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privKey}), nil
}

func main() {
	p := flag.Int("p", 8000, "Listen on `port`")
	q := flag.Bool("q", false, "Enable `quiet` mode (no logs)")
	r := flag.String("r", ".", "Document `root path`")
	s := flag.String("s", "", "Use TLS, https://`your-domain.tld`, if \"localhost\" a self-signed certificate will be created and port can be other than 443")
	flag.Parse()
	srv := &http.Server{Addr: fmt.Sprintf(":%d", *p), Handler: www(*r, *q)}
	if *s == "localhost" {
		certPEMBlock, keyPEMBlock, err := createSSL()
		if err != nil {
			log.Fatal(err)
		}
		srv.TLSConfig = &tls.Config{Certificates: make([]tls.Certificate, 1)}
		if srv.TLSConfig.Certificates[0], err = tls.X509KeyPair(certPEMBlock, keyPEMBlock); err != nil {
			log.Fatal(err)
		}
	} else if *s != "" {
		m := autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(*s),
			Cache:      autocert.DirCache("/tmp/.certs")}
		srv.Addr = ":443"
		srv.TLSConfig = &tls.Config{GetCertificate: m.GetCertificate}
	}
	if !*q {
		log.Printf("Listening on *%s\n", srv.Addr)
	}
	if *s == "" {
		log.Fatal(srv.ListenAndServe())
	}
	log.Fatal(srv.ListenAndServeTLS("", ""))
}
