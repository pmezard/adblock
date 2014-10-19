package adblock

import (
	"bytes"
	"net/url"
	"os"
	"testing"
)

type TestInput struct {
	URL     string
	Matched bool
}

func loadMatcher(path string) (*RuleMatcher, int, error) {
	fp, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer fp.Close()
	parsed, err := ParseRules(fp)
	if err != nil {
		return nil, 0, err
	}
	m := NewMatcher()
	added := 0
	for _, rule := range parsed {
		err := m.AddRule(rule, 0)
		if err == nil {
			added += 1
		}
	}
	return m, added, nil
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
	for _, test := range tests {
		domain := ""
		if u, err := url.Parse(test.URL); err == nil {
			domain = u.Host
		}
		_, opts := m.Match(test.URL, domain)
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

func TestOptsDomain(t *testing.T) {
	testInputs(t, `
/ads$domain=foo.com|~info.foo.com
`,
		[]TestInput{
			{"http://foo.com/ads", true},
			{"http://other.foo.com/ads", true},
			{"http://info.foo.com/ads", false},
			{"http://foo.com/img", false},
			{"http://other.com/ads", false},
		})
}

func BenchmarkSlowMatching(b *testing.B) {
	m, added, err := loadMatcher("testdata/easylist.txt")
	if err != nil {
		b.Fatal(err)
	}
	if added < 14000 {
		b.Fatalf("not enough rules loaded: %d", added)
	}
	longUrl := "http://www.facebook.com/plugins/like.php?action=recommend&app_id=172278489578477&channel=http%3A%2F%2Fstatic.ak.facebook.com%2Fconnect%2Fxd_arbiter%2Fw9JKbyW340G.js%3Fversion%3D41%23cb%3Df1980a49b4%26domain%3Dtheappendix.net%26origin%3Dhttp%253A%252F%252Ftheappendix.net%252Ff81d34bec%26relation%3Dparent.parent&font=verdana&href=http%3A%2F%2Ftheappendix.net%2Fblog%2F2013%2F7%2Fwhy-does-s-look-like-f-a-guide-to-reading-very-old-books&layout=button_count&locale=en_US&sdk=joey&send=false&show_faces=false&width=90"
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		m.Match(longUrl, "www.facebook.com")
	}
}
