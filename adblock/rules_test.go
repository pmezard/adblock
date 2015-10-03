package adblock

import (
	"bytes"
	"net/url"
	"os"
	"testing"
)

type TestInput struct {
	URL          string
	Matched      bool
	ContentType  string
	OriginDomain string
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
	m := NewMatcher()
	for _, rule := range parsed {
		err = m.AddRule(rule, 0)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, test := range tests {
		rq := Request{
			URL:          test.URL,
			ContentType:  test.ContentType,
			OriginDomain: test.OriginDomain,
		}
		if u, err := url.Parse(test.URL); err == nil {
			rq.Domain = u.Host
		}
		matched, _ := m.Match(&rq)
		if matched && !test.Matched {
			t.Errorf("unexpected match: '%+v'", test)
		} else if !matched && test.Matched {
			t.Errorf("unexpected miss: '%+v'", test)
		}
	}
}

func TestEmptyMatcher(t *testing.T) {
	testInputs(t, `

`,
		[]TestInput{
			{URL: "", Matched: false},
			{URL: "foo", Matched: false},
		})
}

func TestExactMatch(t *testing.T) {
	testInputs(t, `
_ads_text.
`,
		[]TestInput{
			{URL: "", Matched: false},
			{URL: "foo", Matched: false},
			{URL: "stuff=1&_ads_text.", Matched: true},
			{URL: "stuff=1&_ads_text.field=bar", Matched: true},
		})
}

func TestWildcard(t *testing.T) {
	testInputs(t, `
a*b
ad
`,
		[]TestInput{
			{URL: "", Matched: false},
			{URL: "foo", Matched: false},
			{URL: "a", Matched: false},
			{URL: "ab", Matched: true},
			{URL: "acb", Matched: true},
			{URL: "cacb", Matched: true},
			{URL: "cacbc", Matched: true},
			{URL: "ad", Matched: true},
		})
}

func TestSeparator(t *testing.T) {
	testInputs(t, `
a^
^d
`,
		[]TestInput{
			{URL: "", Matched: false},
			{URL: "a", Matched: true},
			{URL: "ab", Matched: false},
			{URL: "a:b", Matched: true},
			{URL: "d", Matched: false},
			{URL: "e:d", Matched: true},
		})
}

func TestStartAnchor(t *testing.T) {
	testInputs(t, `
|a
b|
|c|
`,
		[]TestInput{
			{URL: "a", Matched: true},
			{URL: "za", Matched: false},
			{URL: "az", Matched: true},
			{URL: "b", Matched: true},
			{URL: "zb", Matched: true},
			{URL: "bz", Matched: false},
			{URL: "c", Matched: true},
			{URL: "zc", Matched: false},
			{URL: "cz", Matched: false},
		})
}

func TestDomainAnchor(t *testing.T) {
	testInputs(t, `
||ads.example.com
||foo.com/baz.gif
`,
		[]TestInput{
			{URL: "http://ads.example.com/foo.gif", Matched: true},
			{URL: "http://server1.ads.example.com/foo.gif", Matched: true},
			{URL: "https://ads.example.com:8000/foo.gif", Matched: true},
			{URL: "http://ads.example.com.ua/foo.gif", Matched: false},
			{URL: "http://example.com/redirect/http://ads.example.com/", Matched: false},
			{URL: "https://ads.foo.com/baz.gif", Matched: true},
			{URL: "https://ads.foo.com/baz.png", Matched: false},
		})
}

func TestOptsDomain(t *testing.T) {
	testInputs(t, `
/ads$domain=foo.com|~info.foo.com
`,
		[]TestInput{
			{URL: "http://foo.com/ads", Matched: true},
			{URL: "http://other.foo.com/ads", Matched: true},
			{URL: "http://info.foo.com/ads", Matched: false},
			{URL: "http://foo.com/img", Matched: false},
			{URL: "http://other.com/ads", Matched: false},
		})
}

func TestOptsContent(t *testing.T) {
	testInputs(t, `
/img$image
/notimg$~image
/webfont$font
`,
		[]TestInput{
			{URL: "http://foo.com/img", Matched: false},
			{URL: "http://foo.com/img", Matched: true, ContentType: "image/png"},
			{URL: "http://foo.com/img", Matched: false, ContentType: "text/plain"},
			{URL: "http://foo.com/notimg", Matched: false},
			{URL: "http://foo.com/notimg", Matched: false, ContentType: "image/png"},
			{URL: "http://foo.com/notimg", Matched: true, ContentType: "text/plain"},
			{URL: "http://foo.com/webfont", Matched: true, ContentType: "font/opentype"},
			{URL: "http://foo.com/webfont", Matched: false, ContentType: "image/png"},
		})
}

func TestOptsThirdParty(t *testing.T) {
	testInputs(t, `
/img$third-party
`,
		[]TestInput{
			{URL: "http://foo.com/img", Matched: true},
			{URL: "http://foo.com/img", Matched: true, OriginDomain: "bar.com"},
			{URL: "http://foo.com/img", Matched: false, OriginDomain: "foo.com"},
			{URL: "http://foo.com/img", Matched: true, OriginDomain: "sub.foo.com"},
			{URL: "http://sub.foo.com/img", Matched: false, OriginDomain: "foo.com"},
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
	rq := Request{
		URL:    "http://www.facebook.com/plugins/like.php?action=recommend&app_id=172278489578477&channel=http%3A%2F%2Fstatic.ak.facebook.com%2Fconnect%2Fxd_arbiter%2Fw9JKbyW340G.js%3Fversion%3D41%23cb%3Df1980a49b4%26domain%3Dtheappendix.net%26origin%3Dhttp%253A%252F%252Ftheappendix.net%252Ff81d34bec%26relation%3Dparent.parent&font=verdana&href=http%3A%2F%2Ftheappendix.net%2Fblog%2F2013%2F7%2Fwhy-does-s-look-like-f-a-guide-to-reading-very-old-books&layout=button_count&locale=en_US&sdk=joey&send=false&show_faces=false&width=90",
		Domain: "www.facebook.com",
	}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		m.Match(&rq)
	}
}
