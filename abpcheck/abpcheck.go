package main

import (
	"bufio"
	"fmt"
	"os"

	"github.com/pmezard/adblock/adblock"
)

func check() error {
	if len(os.Args) != 2 {
		return fmt.Errorf("one input rule file expected")
	}
	fp, err := os.Open(os.Args[1])
	if err != nil {
		return err
	}
	defer fp.Close()

	ok := true
	rules := []*adblock.Rule{}
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
		rules = append(rules, rule)
	}
	m, err := adblock.NewRuleMatcher(rules)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("some rules could not be parsed")
	}
	fmt.Printf("%s\n", m)
	return nil
}

func main() {
	err := check()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
}
