package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net/http"

	"cloud-security-assignment/pkg/webhook"
)

func main() {
	var (
		listen     = flag.String("listen", ":8443", "HTTPS listen address")
		certPath   = flag.String("tls-cert", "/tls/tls.crt", "TLS cert path")
		keyPath    = flag.String("tls-key", "/tls/tls.key", "TLS key path")
		malwareURL = flag.String("malware-url", "http://npm-registry-proxy.malware-security.svc.cluster.local:8080/malware", "malware list URL")
		csvPath    = flag.String("csv-path", "/data/findings.csv", "CSV output path")
	)
	flag.Parse()

	h := webhook.NewHandler(*malwareURL, *csvPath)

	mux := http.NewServeMux()
	mux.Handle("/validate", h)
	mux.Handle("/healthz", h)

	srv := &http.Server{
		Addr:    *listen,
		Handler: mux,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	log.Printf("starting admission webhook on %s", *listen)
	if err := srv.ListenAndServeTLS(*certPath, *keyPath); err != nil {
		log.Fatalf("ListenAndServeTLS: %v", err)
	}
}
