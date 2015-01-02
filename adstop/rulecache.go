package main

import (
	"bufio"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/pmezard/adblock/adblock"
)

type RuleSet struct {
	Matcher *adblock.RuleMatcher
	Rules   []string
}

var (
	defaultDate = time.Time{}
)

// RuleCache holds a RuleSet build from a list of file paths and URLs.
// Non-file resources are cached in a directory and fetched at initialization
// or on Rules() access if their age exceeds maxAge. The new RuleSet is built
// asynchronously and will eventually be returned by another Rules() call.
//
// Note that all resources are updated whenever one goes stale. Rebuilding
// rules can be expensive, refreshing all rules at once is preferable to
// using cached data and rebuilding more frequently.
//
// TODO: Asynchronous implicit updates makes it hard to cleanly manage the
// lifetime of the cache. A Close() method should be provided if necessary.
type RuleCache struct {
	dir         string
	urls        []string
	maxAge      time.Duration
	deadline    time.Time
	matcherLock sync.Mutex
	matcher     *RuleSet
	updating    bool
	cacheLock   sync.Mutex
}

// Creates a new cache.
// URLs must either be file paths or HTTP/HTTPS URLs.
func NewRuleCache(dir string, urls []string, maxAge time.Duration) (*RuleCache, error) {
	path, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	err = os.MkdirAll(path, 0755)
	if err != nil {
		return nil, err
	}
	c := &RuleCache{
		dir:    path,
		urls:   append([]string{}, urls...),
		maxAge: maxAge,
	}
	matcher, oldest, err := c.buildAll(false)
	if err != nil {
		return nil, err
	}
	c.matcher = matcher
	if oldest == defaultDate {
		oldest = time.Now()
	}
	c.deadline = oldest.Add(c.maxAge)
	return c, nil
}

// Turns a string into something suitable for a filename
func makeFilename(name string) string {
	re := regexp.MustCompile(`[^a-z0-9\-_]`)
	return re.ReplaceAllString(name, "-")
}

// Returns a cached resource and its modification date.
func (c *RuleCache) getCached(url string) (io.ReadCloser, time.Time, error) {
	date := time.Time{}
	name := makeFilename(url)
	path := filepath.Join(c.dir, name)
	fp, err := os.Open(path)
	if err != nil {
		return nil, date, err
	}
	st, err := fp.Stat()
	if err != nil {
		fp.Close()
		return nil, date, err
	}
	return fp, st.ModTime(), nil
}

// Add a resource to the cache.
func (c *RuleCache) cache(url string, r io.Reader) error {
	name := makeFilename(url)
	path := filepath.Join(c.dir, name)
	fp, err := os.Create(path)
	if err != nil {
		return err
	}
	_, err = io.Copy(fp, r)
	errClose := fp.Close()
	if err != nil {
		return err
	}
	return errClose
}

// Fetch and HTTP resource and cache it.
func (c *RuleCache) fetchAndCache(url string) error {
	log.Printf("fetching %s", url)
	rsp, err := http.Get(url)
	if err != nil {
		return err
	}
	c.cache(url, rsp.Body)
	rsp.Body.Close()
	return nil
}

// Returns specified resource and last modification date. The date is set
// to time.Time{} for non-cached resources. If "refresh" is false, cached
// resources can be returned. They will be fetched and updated otherwise.
func (c *RuleCache) load(url string, refresh bool) (io.ReadCloser, time.Time, error) {
	if !strings.HasPrefix(url, "http://") &&
		!strings.HasPrefix(url, "https://") {
		// Assume file path
		fp, err := os.Open(url)
		return fp, time.Time{}, err
	}

	fp, date, err := c.getCached(url)
	if err == nil {
		age := time.Now().Sub(date)
		if !refresh && (c.maxAge <= 0 || age < c.maxAge) {
			return fp, date, nil
		}
		fp.Close()
	}

	err = c.fetchAndCache(url)
	if err != nil {
		log.Printf("could not fetch %s: %s", url, err)
	}
	fp, date, err = c.getCached(url)
	return fp, date, err
}

// Add the rules in supplied reader to the matcher. Returns the list of added
// rules (for debugging or tracing purposes) and the total number of read rules.
// Some rules could not have been parsed.
func buildOne(r io.Reader, matcher *adblock.RuleMatcher) ([]string, int, error) {
	read := 0
	rules := []string{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		s := scanner.Text()
		rule, err := adblock.ParseRule(s)
		if err != nil {
			log.Printf("error: could not parse rule:\n  %s\n  %s\n",
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

func (c *RuleCache) buildAll(refresh bool) (*RuleSet, time.Time, error) {
	matcher := adblock.NewMatcher()
	rules := []string{}
	read := 0
	oldest := time.Time{}
	for _, url := range c.urls {
		r, date, err := c.load(url, refresh)
		if err != nil {
			return nil, oldest, err
		}
		if oldest.After(date) {
			oldest = date
		}
		log.Printf("building rules from %s", url)
		built, n, err := buildOne(r, matcher)
		r.Close()
		if err != nil {
			return nil, oldest, err
		}
		rules = append(rules, built...)
		read += n
	}
	log.Printf("blacklists built: %d / %d added\n", len(rules), read)
	return &RuleSet{
		Rules:   rules,
		Matcher: matcher,
	}, oldest, nil
}

func (c *RuleCache) update() error {
	c.cacheLock.Lock()
	matcher, _, err := c.buildAll(true)
	c.cacheLock.Unlock()

	c.matcherLock.Lock()
	if err != nil {
		c.matcher = matcher
	}
	c.deadline = time.Now().Add(c.maxAge)
	c.matcherLock.Unlock()
	return nil
}

// Returns the current RuleSet. If one resource appears to be stale, an
// update is performed asynchronously.
func (c *RuleCache) Rules() *RuleSet {
	c.matcherLock.Lock()
	defer c.matcherLock.Unlock()
	if !c.updating {
		now := time.Now()
		if now.After(c.deadline) {
			c.updating = true
			go func() {
				log.Printf("updating")
				err := c.update()
				if err != nil {
					log.Printf("update error: %s\n", err)
				} else {
					log.Printf("update succeeded\n")
				}
				c.matcherLock.Lock()
				c.updating = true
				c.matcherLock.Unlock()
			}()
		}
	}
	return c.matcher
}
