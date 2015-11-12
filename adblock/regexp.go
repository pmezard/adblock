package adblock

import (
	"fmt"
	"regexp"
	"strings"
)

func ruleToPattern(r *Rule) (string, error) {
	re := []string{}
	for i, p := range r.Parts {
		switch p.Type {
		case Exact:
			re = append(re, regexp.QuoteMeta(p.Value))
		case Wildcard:
			re = append(re, ".*?")
		case Separator:
			re = append(re, `(?:[^\w\d_\-.%]|$)`)
		case StartAnchor:
			if i == 0 {
				re = append(re, "^")
			} else if i == len(r.Parts)-1 {
				re = append(re, "$")
			} else {
				// Assume literal "|"
				re = append(re, regexp.QuoteMeta(p.Value))
			}
		case DomainAnchor:
			if i != 0 {
				return "", fmt.Errorf("must start with the domain anchor: %s", r.Raw)
			}
			re = append(re, `^(?:[^:/?#]+:)?(?://(?:[^/?#]*\.)?)?`)
		default:
			return "", fmt.Errorf("%q is not supported in regexp rule: %s",
				getPartName(p.Type), r.Raw)
		}
	}
	return strings.Join(re, ""), nil
}

func rulesToRegexp(rules []*Rule) (*regexp.Regexp, error) {
	patterns := []string{}
	for _, r := range rules {
		if r.HasOpts() {
			return nil, fmt.Errorf("cannot build regexp on rules with options: %s", r.Raw)
		}
		pattern, err := ruleToPattern(r)
		if err != nil {
			return nil, err
		}
		patterns = append(patterns, pattern)
	}
	if len(patterns) == 0 {
		return nil, nil
	}
	pattern := "(?:" + strings.Join(patterns, "|") + ")"
	return regexp.Compile(pattern)
}
