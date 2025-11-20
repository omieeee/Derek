package proxy

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"cloud-security-assignment/pkg/malware"
)

var tgzRe = regexp.MustCompile(`^(.+)-(\d+\.\d+\.\d+.*)\.tgz$`)

type Proxy struct {
	MalwareCache *malware.Cache
	Upstream     *url.URL
	Client       *http.Client
	FailClosed   bool
}

func NewProxy(mc *malware.Cache, upstream *url.URL) *Proxy {
	return &Proxy{
		MalwareCache: mc,
		Upstream:     upstream,
		Client:       &http.Client{},
	}
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Healthz shortcut
	if r.URL.Path == "/healthz" {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
		return
	}

	// Local malware endpoint for webhook sharing
	if r.URL.Path == "/malware" && r.Method == http.MethodGet {
		p.serveMalware(w, r)
		return
	}

	pkgName, version := parseNpmRequest(r)
	if pkgName != "" && version != "" {
		if p.isMalicious(r.Context(), pkgName, version) {
			w.WriteHeader(http.StatusForbidden)
			msg := fmt.Sprintf("install blocked: %s@%s is on malware list\n", pkgName, version)
			_, _ = w.Write([]byte(msg))
			log.Printf("[proxy] blocked %s", msg)
			return
		}
	}

	upstreamURL := p.Upstream.ResolveReference(&url.URL{Path: r.URL.Path, RawQuery: r.URL.RawQuery})
	req, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL.String(), r.Body)
	if err != nil {
		http.Error(w, "failed to build upstream request", http.StatusInternalServerError)
		return
	}
	req.Header = r.Header.Clone()

	resp, err := p.Client.Do(req)
	if err != nil {
		http.Error(w, "upstream registry error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (p *Proxy) serveMalware(w http.ResponseWriter, r *http.Request) {
	list, err := p.MalwareCache.GetList(r.Context())
	if err != nil && p.FailClosed {
		http.Error(w, "malware list unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	data, _ := json.Marshal(list)
	_, _ = w.Write(data)
}

func (p *Proxy) isMalicious(ctx context.Context, name, version string) bool {
	list, err := p.MalwareCache.GetList(ctx)
	if err != nil {
		if p.FailClosed {
			return true
		}
		log.Printf("[proxy] malware cache error (fail-open): %v", err)
		return false
	}
	for _, e := range list {
		if e.Matches(name, version) {
			return true
		}
	}
	return false
}

func parseNpmRequest(r *http.Request) (string, string) {
	// Heuristic for tarball URLs: /@scope/pkg/-/@scope/pkg-1.2.3.tgz
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) >= 2 {
		last := parts[len(parts)-1]
		if strings.HasSuffix(last, ".tgz") {
			m := tgzRe.FindStringSubmatch(last)
			if len(m) == 3 {
				name := m[1]
				version := m[2]
				if strings.HasPrefix(name, "@") && strings.Contains(name, "/") {
					// Scoped pkg; nothing to change
				}
				return name, version
			}
		}
	}
	return "", ""
}

func copyHeader(dst, src http.Header) {
	for k, v := range src {
		for _, val := range v {
			dst.Add(k, val)
		}
	}
}
