package adblock

import (
	"bytes"
	"net/url"
	"testing"
	"time"
)

type TestInput struct {
	URL          string
	Matched      bool
	ContentType  string
	OriginDomain string
}

func testInputsMode(t *testing.T, rules string, useRegexp bool, tests []TestInput) {
	parsed, err := ParseRules(bytes.NewBufferString(rules))
	if err != nil {
		t.Fatal(err)
	}
	m := NewMatcher()
	nonOpts := []*Rule{}
	for _, rule := range parsed {
		if useRegexp && !rule.HasOpts() {
			nonOpts = append(nonOpts, rule)
			continue
		}
		err = m.AddRule(rule, 0)
		if err != nil {
			t.Fatal(err)
		}
	}
	err = m.SetOptionlessRules(nonOpts)
	if err != nil {
		t.Fatal(err)
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
		matched, _, err := m.Match(&rq)
		if err != nil {
			t.Errorf("unexpected match error: %s, regexp: %v", err, useRegexp)
		} else if matched && !test.Matched {
			t.Errorf("unexpected match: '%+v', regexp: %v", test, useRegexp)
		} else if !matched && test.Matched {
			t.Errorf("unexpected miss: '%+v', regexp: %v", test, useRegexp)
		}
	}
}

func testInputs(t *testing.T, rules string, tests []TestInput) {
	testInputsMode(t, rules, false, tests)
	testInputsMode(t, rules, true, tests)
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
||ads.example.com^
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

func TestInterruptedMatching(t *testing.T) {
	m, added, err := NewMatcherFromFiles(
		"testdata/too_many_wildcards.txt",
	)
	if err != nil {
		t.Fatal(err)
	}
	if added == 0 {
		t.Fatalf("not enough rules loaded: %d", added)
	}
	rq := Request{
		URL:          "http://www.ultimedia.com/api/widget/smart?j=new&t=1444644802198&otherplayer=0&exclude=&meta_description=Le%20Monde.fr%20version%20mobile%20-%20L%E2%80%99attentat%20de%20samedi%20dans%20la%20capitale%20turque%2C%20qui%20a%20fait%20au%20moins%2097%20morts%2C%20met%20au%20jour%20le%20jeu%20dangereux%20du%20pouvoir%2C%20%C3%A0%20trois%20semaines%20des%20l%C3%A9gislatives.&meta_ogtitle=Apr%C3%A8s%20l%E2%80%99attentat%20d%E2%80%99Ankara%2C%20la%20Turquie%20au%20bord%20du%20gouffre&meta_ogdescription=Le%20Monde.fr%20version%20mobile%20-%20L%E2%80%99attentat%20de%20samedi%20dans%20la%20capitale%20turque%2C%20qui%20a%20fait%20au%20moins%2097%20morts%2C%20met%20au%20jour%20le%20jeu%20dangereux%20du%20pouvoir%2C%20%C3%A0%20trois%20semaines%20des%20l%C3%A9gislatives.&meta_title=Apr%C3%A8s%20l%E2%80%99attentat%20d%E2%80%99Ankara%2C%20la%20Turquie%20au%20bord%20du%20gouffre&meta_h1=Apr%C3%A8s%20l%E2%80%99attentat%20d%E2%80%99Ankara%2C%20la%20Turquie%20au%20bord%20du%20gouffre&meta_h2=Depuis%20que%20les%20%C3%A9lecteurs%20turcs%20ont%20refus%C3%A9%20de%20%3Ca%20target%3D%22_blank%22%20onclick%3D%22return%20false%3B%22%20class%3D%22lien_interne%20conjug%22%20href%3D%22http%3A%2F%2Fconjugaison.lemonde.fr%2Fconjugaison%2Fpremier-groupe%2Fdonner%2F%22%20title%3D%22Conjugaison%20du%20verbe%20donner%22%3Edonner%3C%2Fa%3E%2C%20le%207%26nbsp%3Bjuin%2C%20la%20&meta_datepublished=2015-10-12T10%3A34%3A43%2B02%3A00&date=20151012&url=http%3A%2F%2Fmobile.lemonde.fr%2Feurope%2Farticle%2F2015%2F10%2F12%2Fapres-l-attentat-d-ankara-la-turquie-au-bord-du-gouffre_4787525_3214.html&mdtk=01194867&layout=&target=ultimedia_wrapper",
		Domain:       "www.ultimedia.com",
		ContentType:  "application/javascript",
		OriginDomain: "mobile.lemonde.fr",
		Timeout:      200 * time.Millisecond,
	}
	ok, _, err := m.Match(&rq)
	if ok || err == nil {
		t.Fatalf("matcher successfully applied horrible rule, please change the test")
	}
}

func BenchmarkSlowMatching(b *testing.B) {
	m, added, err := NewMatcherFromFiles("testdata/easylist-20141019.txt")
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
