package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"mime"
	"net"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/inconshreveable/go-vhost"
	"github.com/pmezard/adblock/adblock"
)

var (
	timeoutStr  = flag.String("timeout", "5m", "HTTP/TCP connections global timeout")
	httpAddr    = flag.String("http", "localhost:1080", "HTTP handler address")
	httpsAddr   = flag.String("https", "localhost:1081", "HTTPS handler address")
	httpDebug   = flag.String("debug-addr", "", "HTTP debug address")
	logRequests = flag.Uint64("log", 0, "enable logging")
	cacheDir    = flag.String("cache", ".cache", "cache directory")
	maxAgeArg   = flag.String("max-age", "24h", "cached entries max age")
	caCert      = flag.String("ca-cert", "", "path to CA certificate")
	caKey       = flag.String("ca-key", "", "path to CA key")
)

type FilteringHandler struct {
	Cache *RuleCache
}

func logRequest(r *http.Request) {
	buf := &bytes.Buffer{}
	fmt.Fprintf(buf, "REQ\n<REQUEST\n%s %s %s %s\n", r.Proto, r.Method, r.URL, r.Host)
	r.Header.Write(buf)
	fmt.Fprintf(buf, "REQUEST>\n")
	log.Println(buf.String())
}

func logResponse(r *http.Response) {
	buf := &bytes.Buffer{}
	fmt.Fprintf(buf, "RSP\n<RESPONSE\n%s %s\n", r.Proto, r.Status)
	r.Header.Write(buf)
	fmt.Fprintf(buf, "RESPONSE>\n")
	log.Println(buf.String())
}

func getReferrerDomain(r *http.Request) string {
	ref := r.Header.Get("Referer")
	if len(ref) > 0 {
		u, err := url.Parse(ref)
		if err == nil {
			return u.Host
		}
	}
	return ""
}

type ProxyState struct {
	Duration time.Duration
	URL      string
}

func (h *FilteringHandler) OnRequest(r *http.Request, ctx *goproxy.ProxyCtx) (
	*http.Request, *http.Response) {

	host := r.URL.Host
	if host == "" {
		host = r.Host
	}
	rq := &adblock.Request{
		URL:          r.URL.String(),
		Domain:       host,
		OriginDomain: getReferrerDomain(r),
	}
	rules := h.Cache.Rules()
	start := time.Now()
	matched, id := rules.Matcher.Match(rq)
	end := time.Now()
	duration := end.Sub(start) / time.Millisecond
	if matched {
		rule := rules.Rules[id]
		log.Printf("rejected in %dms: %s\n", duration, r.URL.String())
		log.Printf("  by %s\n", rule)
		return r, goproxy.NewResponse(r, goproxy.ContentTypeText,
			http.StatusNotFound, "Not Found")
	}
	ctx.UserData = &ProxyState{
		Duration: duration,
		URL:      r.URL.String(),
	}
	return r, nil
}

func (h *FilteringHandler) OnResponse(r *http.Response,
	ctx *goproxy.ProxyCtx) *http.Response {

	if r == nil {
		// Happens if RoundTrip fails
		return r
	}

	state, ok := ctx.UserData.(*ProxyState)
	if !ok {
		// The request was rejected by the previous handler
		return r
	}

	duration2 := time.Duration(0)
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err == nil && len(mediaType) > 0 {
		host := ctx.Req.URL.Host
		if host == "" {
			host = ctx.Req.Host
		}
		rq := &adblock.Request{
			URL:          ctx.Req.URL.String(),
			Domain:       host,
			OriginDomain: getReferrerDomain(ctx.Req),
			ContentType:  mediaType,
		}
		// Second level filtering, based on returned content
		rules := h.Cache.Rules()
		start := time.Now()
		matched, id := rules.Matcher.Match(rq)
		end := time.Now()
		duration2 = end.Sub(start) / time.Millisecond
		if matched {
			r.Body.Close()
			rule := rules.Rules[id]
			log.Printf("rejected in %d/%dms: %s\n", state.Duration, duration2,
				state.URL)
			log.Printf("  by %s\n", rule)
			return goproxy.NewResponse(ctx.Req, goproxy.ContentTypeText,
				http.StatusNotFound, "Not Found")
		}
	}

	if atomic.LoadUint64(logRequests)%2 == 1 {
		logRequest(ctx.Req)
		logResponse(r)
	}
	log.Printf("accepted in %d/%dms: %s\n", state.Duration, duration2, state.URL)
	return r
}

// CachedConfig holds a TLS configuration. It can be in different states:
// - The config is being generated, Config is nil and the Ready channel is set
// - The config is ready, Config is not nil and Ready is closed.
// This mechanism is used to pool concurrent generations of the same certificate.
type CachedConfig struct {
	Config *tls.Config
	Ready  chan struct{}
}

// TLSConfigCache is a goroutine-safe cache of TLS configurations mapped to hosts.
type TLSConfigCache struct {
	cfgBuilder func(string, *goproxy.ProxyCtx) (*tls.Config, error)
	lock       sync.Mutex
	cache      map[string]CachedConfig
	hit        int
	miss       int
}

func NewTLSConfigCache(ca *tls.Certificate) *TLSConfigCache {
	return &TLSConfigCache{
		cfgBuilder: goproxy.TLSConfigFromCA(ca),
		cache:      map[string]CachedConfig{},
	}
}

func getWildcardHost(host string) string {
	first := strings.Index(host, ".")
	if first <= 0 {
		return host
	}
	last := strings.LastIndex(host, ".")
	if last == first {
		// root domain, no wildcard
		return host
	}
	return "*" + host[first:]
}

func (c *TLSConfigCache) GetConfig(host string, ctx *goproxy.ProxyCtx) (*tls.Config, error) {
	host = getWildcardHost(host)
	c.lock.Lock()
	cached, ok := c.cache[host]
	if !ok {
		// Register a config generation event
		cached = CachedConfig{
			Ready: make(chan struct{}),
		}
		c.cache[host] = cached
	}
	if ok {
		c.hit += 1
	} else {
		c.miss += 1
	}
	hit := c.hit
	miss := c.miss
	c.lock.Unlock()

	ctx.Warnf("signing hit/miss: %d/%d (%.1f%%)", hit, miss,
		100.0*float64(hit)/float64(hit+miss))
	if ok {
		// config is being generated or is ready, grab it
		<-cached.Ready
		cfg := cached.Config
		if cfg == nil {
			return nil, fmt.Errorf("failed to generate TLS config for %s", host)
		}
		return cfg, nil
	}

	// Generate it
	start := time.Now()
	cfg, err := c.cfgBuilder(host, ctx)
	stop := time.Now()
	ctx.Warnf("signing %s in %.0fms", host,
		float64(stop.Sub(start))/float64(time.Millisecond))

	c.lock.Lock()
	if err == nil {
		c.cache[host] = CachedConfig{
			Config: cfg,
			Ready:  cached.Ready,
		}
	} else {
		delete(c.cache, host)
		ctx.Warnf("failed to sign %s: %s", host, err)
	}
	close(cached.Ready)
	c.lock.Unlock()
	return cfg, err
}

// copied/converted from https.go
type dumbResponseWriter struct {
	net.Conn
}

func (dumb dumbResponseWriter) Header() http.Header {
	panic("Header() should not be called on this ResponseWriter")
}

func (dumb dumbResponseWriter) Write(buf []byte) (int, error) {
	if bytes.Equal(buf, []byte("HTTP/1.0 200 OK\r\n\r\n")) {
		// throw away the HTTP OK response from the faux CONNECT request
		return len(buf), nil
	}
	return dumb.Conn.Write(buf)
}

func (dumb dumbResponseWriter) WriteHeader(code int) {
	panic("WriteHeader() should not be called on this ResponseWriter")
}

func (dumb dumbResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return dumb, bufio.NewReadWriter(bufio.NewReader(dumb), bufio.NewWriter(dumb)), nil
}

func makeCertificate(certPath, keyPath string) (*tls.Certificate, error) {
	cert, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("cannot load CA certificate: %s", err)
	}
	key, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("cannot load CA key: %s", err)
	}
	ca, err := tls.X509KeyPair(cert, key)
	return &ca, err
}

func runDebugServer(addr string) error {
	http.HandleFunc("/trace", func(w http.ResponseWriter, r *http.Request) {
		res := atomic.AddUint64(logRequests, 1)
		action := "logging requests"
		if res%2 == 0 {
			action = "ignoring requests"
		}
		fmt.Fprintf(w, "%s\n", action)
	})
	return http.ListenAndServe(addr, nil)
}

func listenTransparentTLS(proxy *goproxy.ProxyHttpServer, addr string,
	timeout time.Duration) error {

	// listen to the TLS ClientHello but make it a CONNECT request instead
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("error accepting new connection - %v", err)
			continue
		}
		go func(c net.Conn) {
			c.SetDeadline(time.Now().Add(timeout))
			tlsConn, err := vhost.TLS(c)
			if err != nil {
				log.Printf("error accepting new connection - %v", err)
			}
			if tlsConn.Host() == "" {
				log.Printf("cannot support non-SNI enabled clients")
				return
			}
			connectReq := &http.Request{
				Method: "CONNECT",
				URL: &url.URL{
					Opaque: tlsConn.Host(),
					Host:   net.JoinHostPort(tlsConn.Host(), "443"),
				},
				Host:   tlsConn.Host(),
				Header: make(http.Header),
			}
			resp := dumbResponseWriter{tlsConn}
			proxy.ServeHTTP(resp, connectReq)
		}(c)
	}
}

func runProxy() error {
	flag.Parse()
	timeout, err := time.ParseDuration(*timeoutStr)
	if err != nil {
		return fmt.Errorf("could not parse timeout %s: %s", *timeoutStr, err)
	}
	if *caCert == "" || *caKey == "" {
		return fmt.Errorf("CA certificate and key must be specified")
	}
	ca, err := makeCertificate(*caCert, *caKey)
	if err != nil {
		return err
	}

	maxAge, err := time.ParseDuration(*maxAgeArg)
	if err != nil {
		return fmt.Errorf("invalid max-age: %s", err)
	}
	if maxAge < 0 {
		return fmt.Errorf("invalid negative max-age")
	}
	log.Printf("loading rules")
	cache, err := NewRuleCache(*cacheDir, flag.Args(), maxAge)
	if err != nil {
		return err
	}
	h := &FilteringHandler{
		Cache: cache,
	}

	if *httpDebug != "" {
		log.Printf("starting debug server on %s", *httpDebug)
		go func() {
			log.Println(runDebugServer(*httpDebug))
		}()
	}

	log.Printf("starting servers")
	proxy := goproxy.NewProxyHttpServer()
	proxy.NonproxyHandler = http.HandlerFunc(
		func(w http.ResponseWriter, req *http.Request) {
			if req.Host == "" {
				log.Printf("Cannot handle requests without Host header, e.g., HTTP 1.0")
				return
			}
			req.URL.Scheme = "http"
			req.URL.Host = req.Host
			proxy.ServeHTTP(w, req)
		})

	// Cache MITM certificates
	tlsCache := NewTLSConfigCache(ca)
	MitmConnect := &goproxy.ConnectAction{
		Action: goproxy.ConnectMitm,
		TLSConfig: func(host string, ctx *goproxy.ProxyCtx) (*tls.Config, error) {
			return tlsCache.GetConfig(host, ctx)
		},
	}
	var AlwaysMitm goproxy.FuncHttpsHandler = func(host string, ctx *goproxy.ProxyCtx) (
		*goproxy.ConnectAction, string) {

		return MitmConnect, host
	}
	proxy.OnRequest().HandleConnect(AlwaysMitm)

	proxy.OnRequest().DoFunc(h.OnRequest)
	proxy.OnResponse().DoFunc(h.OnResponse)

	done := make(chan error)
	go func() {
		server := http.Server{
			Addr:         *httpAddr,
			Handler:      proxy,
			ReadTimeout:  timeout,
			WriteTimeout: timeout,
		}
		done <- server.ListenAndServe()
	}()

	go func() {
		done <- listenTransparentTLS(proxy, *httpsAddr, timeout)
	}()

	return <-done
}

func main() {
	err := runProxy()
	if err != nil {
		log.Fatalf("error: %s\n", err)
	}
}
