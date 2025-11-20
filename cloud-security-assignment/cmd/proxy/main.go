package main

import (
	"flag"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"cloud-security-assignment/pkg/malware"
	"cloud-security-assignment/pkg/proxy"
)

func main() {
	var (
		listen       = flag.String("listen", ":8080", "listen address")
		upstreamStr  = flag.String("upstream", "https://registry.npmjs.org", "upstream npm registry")
		malwareURL   = flag.String("malware-api-url", "", "external malware JSON API URL")
		failClosed   = flag.Bool("fail-closed", false, "fail closed when malware list unavailable")
		cacheTTL     = flag.Duration("cache-ttl", 10*time.Minute, "malware cache TTL")
		cacheBackoff = flag.Duration("cache-backoff-max", 30*time.Minute, "max backoff duration")
	)
	flag.Parse()

	if *malwareURL == "" {
		if env := os.Getenv("MALWARE_API_URL"); env != "" {
			*malwareURL = env
		} else {
			log.Fatal("malware-api-url or MALWARE_API_URL must be set")
		}
	}

	up, err := url.Parse(*upstreamStr)
	if err != nil {
		log.Fatalf("invalid upstream URL: %v", err)
	}

	cache := malware.NewCache(malware.CacheConfig{
		URL:        *malwareURL,
		TTL:        *cacheTTL,
		BackoffMax: *cacheBackoff,
		FailClosed: *failClosed,
	})

	p := proxy.NewProxy(cache, up)
	p.FailClosed = *failClosed

	log.Printf("starting npm proxy on %s, upstream=%s", *listen, up)
	if err := http.ListenAndServe(*listen, p); err != nil {
		log.Fatalf("ListenAndServe: %v", err)
	}
}
