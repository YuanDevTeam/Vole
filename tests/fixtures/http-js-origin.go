// An isolated origin for the shared HTTP JS fixture.
package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	if len(os.Args) != 3 {
		log.Fatal("usage: http-js-origin cert.pem key.pem")
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024))
		if err != nil || r.URL.Path != "/rewrite" || r.Method != http.MethodPost ||
			r.Header.Get("X-Vole-Native") != "ready" || r.Header.Get("X-Vole-Request") != "js" ||
			string(body) != "probe:js" {
			http.Error(w, "unexpected upstream request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Origin-Protocol", r.Proto)
		_, _ = fmt.Fprintf(w, "origin:%s", body)
	})
	server := func(addr string, protocols *http.Protocols) *http.Server {
		return &http.Server{
			Addr: addr, Handler: handler, Protocols: protocols,
			ReadHeaderTimeout: 5 * time.Second,
			TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
		}
	}
	h1 := new(http.Protocols)
	h1.SetHTTP1(true)
	h2 := new(http.Protocols)
	h2.SetHTTP2(true)
	go func() { log.Fatal(server(":18443", h1).ListenAndServeTLS(os.Args[1], os.Args[2])) }()
	go func() { log.Fatal(server(":18444", h2).ListenAndServeTLS(os.Args[1], os.Args[2])) }()
	log.Fatal(server(":18080", h1).ListenAndServe())
}
