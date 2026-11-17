// The far end of the benchmark: one HTTPS server on 127.0.0.1 that is both the REALITY
// "target" (what the server pretends to be) and the site the clients download from.
//
//	GET /bytes/<n>   n bytes of incompressible data
//	GET /            "ok"
//
// HTTPS so that VLESS + REALITY + Vision runs the way it does on real sites: the inner
// TLS is what Vision's direct mode is for. HTTP/1.1 only, no logging.
//
//	go run tools/bench/target.go <port> <out-dir-for-cert> [<plain-http-port>]
//
// The plain HTTP port serves the same paths without TLS, for the Android probe
// (tools/bench/probe.zig), which reaches the site by IP through the client under test.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var block = func() []byte {
	b := make([]byte, 1<<20)
	rand.Read(b)
	return b
}()

func main() {
	port, dir := os.Args[1], os.Args[2]
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	os.WriteFile(filepath.Join(dir, "target.pem"), certPEM, 0o644)
	kb, _ := x509.MarshalECPrivateKey(key)
	pair, err := tls.X509KeyPair(certPEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}))
	if err != nil {
		log.Fatal(err)
	}

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/bytes/") {
			w.Write([]byte("ok"))
			return
		}
		n, _ := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, "/bytes/"), 10, 64)
		w.Header().Set("Content-Length", strconv.FormatInt(n, 10))
		w.Header().Set("Content-Type", "application/octet-stream")
		for n > 0 {
			c := int64(len(block))
			if n < c {
				c = n
			}
			if _, err := w.Write(block[:c]); err != nil {
				return
			}
			n -= c
		}
	})
	srv := &http.Server{
		Addr:         "127.0.0.1:" + port,
		Handler:      h,
		TLSConfig:    &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}},
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
		ErrorLog:     log.New(os.Stderr, "", 0),
	}
	if len(os.Args) > 3 {
		plain := &http.Server{Addr: "127.0.0.1:" + os.Args[3], Handler: h, ErrorLog: log.New(os.Stderr, "", 0)}
		go func() { log.Fatal(plain.ListenAndServe()) }()
	}
	log.Fatal(srv.ListenAndServeTLS("", ""))
}
