package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"log"
	"mime"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/pmezard/adblock/adblock"
)

var (
	listen = flag.String("listen", "localhost:1080", "listen on address")
	logp   = flag.Bool("log", false, "enable logging")
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
				ctx.Req.URL.String())
			log.Printf("  by %s\n", rule)
			return goproxy.NewResponse(ctx.Req, goproxy.ContentTypeText,
				http.StatusNotFound, "Not Found")
		}
	}
	log.Printf("accepted in %d/%dms: %s\n", state.Duration, duration2, ctx.Req.URL.String())
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
	proxy.OnRequest().DoFunc(h.OnRequest)
	proxy.OnResponse().DoFunc(h.OnResponse)
	return http.ListenAndServe(*listen, proxy)
}

func main() {
	err := runProxy()
	if err != nil {
		log.Fatalf("error: %s\n", err)
	}
}
