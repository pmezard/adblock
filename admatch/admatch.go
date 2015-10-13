package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/pmezard/adblock/adblock"
)

func match() error {
	domain := flag.String("domain", "", "URL domain")
	contentType := flag.String("content-type", "", "response Content-Type")
	originDomain := flag.String("origin-domain", "", "parent page domain")
	flag.Parse()
	args := flag.Args()
	if len(args) < 2 {
		return fmt.Errorf("at least one rule file and an URL are expected")
	}
	files := args[:len(args)-1]
	url := args[len(args)-1]
	m, added, err := adblock.NewMatcherFromFiles(files...)
	if err != nil {
		return err
	}
	fmt.Printf("%d rules loaded\n", added)
	rq := &adblock.Request{
		URL:          url,
		Domain:       *domain,
		OriginDomain: *originDomain,
		ContentType:  *contentType,
		Timeout:      5 * time.Second,
	}
	start := time.Now()
	matched, _, err := m.Match(rq)
	if err != nil {
		return err
	}
	end := time.Now()
	suffix := fmt.Sprintf("in %.2fs", float64(end.Sub(start))/float64(time.Second))
	if matched {
		fmt.Println("matched " + suffix)
	} else {
		fmt.Println("not matched " + suffix)
	}
	return nil
}

func main() {
	err := match()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
}
