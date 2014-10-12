package adblock

import (
	"bytes"
	"fmt"
	"testing"
)

type TestInput struct {
	URL     string
	Matched bool
}

func testInputs(t *testing.T, rules string, tests []TestInput) {
	parsed, err := ParseRules(bytes.NewBufferString(rules))
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewRuleMatcher(parsed)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("%s\n", m)
	for _, test := range tests {
		_, opts := m.Match(test.URL)
		res := opts != nil
		if res && !test.Matched {
			t.Errorf("unexpected match: '%s'", test.URL)
		} else if !res && test.Matched {
			t.Errorf("unexpected miss: '%s'", test.URL)
		}
	}
}

func TestExactMatch(t *testing.T) {
	testInputs(t, `
_ads_text.
`,
		[]TestInput{
			{"", false},
			{"foo", false},
			{"stuff=1&_ads_text.", true},
			{"stuff=1&_ads_text.field=bar", true},
		})
}

func TestWildcard(t *testing.T) {
	testInputs(t, `
a*b
ad
`,
		[]TestInput{
			{"", false},
			{"foo", false},
			{"a", false},
			{"ab", true},
			{"acb", true},
			{"cacb", true},
			{"cacbc", true},
			{"ad", true},
		})
}

func TestSeparator(t *testing.T) {
	testInputs(t, `
a^
^d
`,
		[]TestInput{
			{"", false},
			{"a", true},
			{"ab", false},
			{"a:b", true},
			{"d", false},
			{"e:d", true},
		})
}

func TestStartAnchor(t *testing.T) {
	testInputs(t, `
|a
b|
|c|
`,
		[]TestInput{
			//{"", false},
			{"a", true},
			{"za", false},
			{"az", true},
			{"b", true},
			{"zb", true},
			{"bz", false},
			{"c", true},
			{"zc", false},
			{"cz", false},
		})
}

func TestDomainAnchor(t *testing.T) {
	testInputs(t, `
||ads.example.com
||foo.com/baz.gif
`,
		[]TestInput{
			{"http://ads.example.com/foo.gif", true},
			{"http://server1.ads.example.com/foo.gif", true},
			{"https://ads.example.com:8000/foo.gif", true},
			{"http://ads.example.com.ua/foo.gif", false},
			{"http://example.com/redirect/http://ads.example.com/", false},
			{"https://ads.foo.com/baz.gif", true},
			{"https://ads.foo.com/baz.png", false},
		})
}
