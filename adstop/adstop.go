package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/inconshreveable/go-vhost"
	"github.com/pmezard/adblock/adblock"
)

var (
	httpAddr  = flag.String("http", "localhost:1080", "HTTP handler address")
	httpsAddr = flag.String("https", "localhost:1081", "HTTPS handler address")
	logp      = flag.Bool("log", false, "enable logging")
)

type FilteringHandler struct {
	Matcher adblock.Matcher
	Rules   []string
}

func logRequest(r *http.Request) {
	log.Printf("%s %s %s %s\n", r.Proto, r.Method, r.URL, r.Host)
	buf := &bytes.Buffer{}
	r.Header.Write(buf)
	log.Println(string(buf.Bytes()))
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

	if *logp {
		logRequest(r)
	}

	host := r.URL.Host
	if host == "" {
		host = r.Host
	}
	rq := &adblock.Request{
		URL:          r.URL.String(),
		Domain:       host,
		OriginDomain: getReferrerDomain(r),
	}
	start := time.Now()
	matched, id := h.Matcher(rq)
	end := time.Now()
	duration := end.Sub(start) / time.Millisecond
	if matched {
		rule := h.Rules[id]
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
		start := time.Now()
		matched, id := h.Matcher(rq)
		end := time.Now()
		duration2 = end.Sub(start) / time.Millisecond
		if matched {
			r.Body.Close()
			rule := h.Rules[id]
			log.Printf("rejected in %d/%dms: %s\n", state.Duration, duration2,
				state.URL)
			log.Printf("  by %s\n", rule)
			return goproxy.NewResponse(ctx.Req, goproxy.ContentTypeText,
				http.StatusNotFound, "Not Found")
		}
	}
	log.Printf("accepted in %d/%dms: %s\n", state.Duration, duration2, state.URL)
	return r
}

func loadBlackList(path string, matcher *adblock.RuleMatcher,
	rules []string) ([]string, int, error) {

	fp, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer fp.Close()

	read := 0
	scanner := bufio.NewScanner(fp)
	for scanner.Scan() {
		s := scanner.Text()
		rule, err := adblock.ParseRule(s)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: could not parse rule:\n  %s\n  %s\n",
				scanner.Text(), err)
			continue
		}
		if rule == nil {
			continue
		}
		err = matcher.AddRule(rule, len(rules))
		read += 1
		if err == nil {
			rules = append(rules, s)
		}
	}
	return rules, read, scanner.Err()
}

func loadBlackLists(paths []string) (adblock.Matcher, []string, error) {
	log.Printf("reading black lists\n")
	matcher := adblock.NewMatcher()
	read := 0
	rules := []string{}
	for _, path := range paths {
		updated, r, err := loadBlackList(path, matcher, rules)
		rules = updated
		if err != nil {
			return nil, nil, err
		}
		read += r
	}
	log.Printf("blacklists built: %d / %d added\n", len(rules), read)
	return matcher.Match, rules, nil
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

func runProxy() error {
	flag.Parse()
	matcher, rules, err := loadBlackLists(flag.Args())
	if err != nil {
		return err
	}
	h := &FilteringHandler{
		Matcher: matcher,
		Rules:   rules,
	}
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
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	proxy.OnRequest().DoFunc(h.OnRequest)
	proxy.OnResponse().DoFunc(h.OnResponse)
	go func() {
		http.ListenAndServe(*httpAddr, proxy)
	}()

	// listen to the TLS ClientHello but make it a CONNECT request instead
	ln, err := net.Listen("tcp", *httpsAddr)
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

func main() {
	err := runProxy()
	if err != nil {
		log.Fatalf("error: %s\n", err)
	}
}
