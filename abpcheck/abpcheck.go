package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"

	"github.com/pmezard/adblock/adblock"
)

func check() error {
	verbose := flag.Bool("v", false, "print rejected rules")
	flag.Parse()
	args := flag.Args()
	if len(args) != 1 {
		return fmt.Errorf("one input rule file expected")
	}
	fp, err := os.Open(args[0])
	if err != nil {
		return err
	}
	defer fp.Close()

	ok := true
	rules := adblock.NewMatcher()
	scanner := bufio.NewScanner(fp)
	for scanner.Scan() {
		rule, err := adblock.ParseRule(scanner.Text())
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: could not parse rule:\n  %s\n  %s\n",
				scanner.Text(), err)
			ok = false
			continue
		}
		if rule == nil {
			continue
		}
		err = rules.AddRule(rule, 0)
		if *verbose && err != nil {
			fmt.Fprintf(os.Stderr, "error: could not add rule:\n  %s\n  %s\n",
				scanner.Text(), err)
			ok = false
		}
	}
	if !ok {
		return fmt.Errorf("some rules could not be parsed")
	}
	fmt.Printf("%s\n", rules)
	return nil
}

func main() {
	err := check()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
}
