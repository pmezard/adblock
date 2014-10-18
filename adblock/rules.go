package adblock

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"regexp"
	"strings"
)

const (
	Exact        = iota // string to match
	Wildcard     = iota // *
	Separator    = iota // ^
	StartAnchor  = iota // |
	DomainAnchor = iota // ||

	Root = iota
)

func getPartName(ruleType int) string {
	switch ruleType {
	case Exact:
		return "exact"
	case Wildcard:
		return "wildcard"
	case Separator:
		return "separator"
	case StartAnchor:
		return "startanchor"
	case DomainAnchor:
		return "domainanchor"
	case Root:
		return "root"
	default:
		return "unknown"
	}
}

type RulePart struct {
	Type  int
	Value string
}

type RuleOpts struct {
	Raw              string
	Collapse         *bool
	Document         bool
	Domains          []string
	ElemHide         bool
	Image            *bool
	Media            *bool
	Object           *bool
	ObjectSubRequest *bool
	Popup            *bool
	Script           *bool
	Stylesheet       *bool
	SubDocument      *bool
	ThirdParty       *bool
	XmlHttpRequest   *bool
}

func NewRuleOpts(s string) (RuleOpts, error) {
	opts := RuleOpts{Raw: s}
	for _, opt := range strings.Split(s, ",") {
		opt = strings.TrimSpace(opt)
		value := true
		if strings.HasPrefix(opt, "~") {
			value = false
			opt = opt[1:]
		}
		switch {
		case opt == "script":
			opts.Script = &value
		case opt == "image":
			opts.Image = &value
		case opt == "stylesheet":
			opts.Stylesheet = &value
		case opt == "object":
			opts.Object = &value
		case opt == "object-subrequest":
			opts.ObjectSubRequest = &value
		case opt == "subdocument":
			opts.SubDocument = &value
		case opt == "document":
			opts.Document = true
		case opt == "elemhide":
			opts.ElemHide = true
		case opt == "third-party":
			opts.ThirdParty = &value
		case strings.HasPrefix(opt, "domain="):
			s = opt[len("domain="):]
			for _, d := range strings.Split(s, "|") {
				d = strings.TrimSpace(d)
				opts.Domains = append(opts.Domains, d)
			}
		// Undocumented options
		case opt == "xmlhttprequest":
			opts.XmlHttpRequest = &value
		case opt == "media":
			opts.Media = &value
		case opt == "popup":
			opts.Popup = &value
		case opt == "collapse":
			opts.Collapse = &value
		default:
			return opts, fmt.Errorf("unknown rule option: %s", opt)
		}
	}
	return opts, nil
}

type Rule struct {
	Raw       string
	Exception bool
	Parts     []RulePart
	Opts      RuleOpts
}

var (
	NullOpts = RuleOpts{}
)

func (r *Rule) HasOpts() bool {
	// Collapse is related to ElemHide, and irrelevant
	return r.Opts.Document ||
		// Domains is handled
		// ElemHide is irrelevant
		r.Opts.Image != nil ||
		r.Opts.Media != nil ||
		r.Opts.Object != nil ||
		r.Opts.ObjectSubRequest != nil ||
		r.Opts.Popup != nil ||
		r.Opts.Script != nil ||
		r.Opts.Stylesheet != nil ||
		r.Opts.SubDocument != nil ||
		r.Opts.ThirdParty != nil ||
		r.Opts.XmlHttpRequest != nil
}

func ParseRule(s string) (*Rule, error) {
	r := Rule{Raw: s}
	s = strings.TrimSpace(s)
	if len(s) == 0 || s[0] == '!' {
		// Empty or comment
		return nil, nil
	}
	if strings.Contains(s, "##") {
		// Element selectors are not supported
		return nil, nil
	}
	if strings.HasPrefix(s, "@@") {
		r.Exception = true
		s = s[2:]
	}
	if strings.HasPrefix(s, "||") {
		r.Parts = append(r.Parts, RulePart{Type: DomainAnchor, Value: "||"})
		s = s[2:]
	}
	if pos := strings.LastIndex(s, "$"); pos >= 0 {
		optsStr := s[pos+1:]
		// Parse the options later
		opts, err := NewRuleOpts(optsStr)
		if err != nil {
			return nil, err
		}
		r.Opts = opts
		s = s[:pos]
	}

	var p RulePart
	for len(s) > 0 {
		pos := strings.IndexAny(s, "*^|")
		if pos < 0 {
			p := RulePart{Type: Exact, Value: s}
			r.Parts = append(r.Parts, p)
			break
		}
		if pos > 0 {
			p = RulePart{Type: Exact, Value: s[:pos]}
			r.Parts = append(r.Parts, p)
		}
		t := Wildcard
		switch s[pos] {
		case '*':
			t = Wildcard
		case '^':
			t = Separator
		case '|':
			t = StartAnchor
		}
		r.Parts = append(r.Parts, RulePart{Type: t, Value: s[pos : pos+1]})
		s = s[pos+1:]
	}
	return &r, nil
}

func ParseRules(r io.Reader) ([]*Rule, error) {
	rules := []*Rule{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		r, err := ParseRule(scanner.Text())
		if r == nil {
			continue
		}
		if err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, scanner.Err()
}

type Matcher func(url, domain string) (bool, int)

type RuleNode struct {
	Type     int
	Value    []byte
	Opts     []*RuleOpts // non-empty on terminating nodes
	Children []*RuleNode
	RuleId   int
}

func (n *RuleNode) AddRule(parts []RulePart, opts *RuleOpts, id int) error {
	if len(parts) == 0 {
		n.Opts = append(n.Opts, opts)
		n.RuleId = id
		return nil
	}
	// Looks for existing matching rule parts
	part := parts[0]
	if part.Type != Exact && part.Type != Wildcard && part.Type != Separator &&
		part.Type != DomainAnchor {
		return fmt.Errorf("unknown rule part type: %+v", part)
	}
	var child *RuleNode
	value := []byte(part.Value)
	for _, c := range n.Children {
		// TODO: be smarter with ExactMatch
		if c.Type == part.Type && bytes.Equal(c.Value, value) {
			child = c
			break
		}
	}
	created := false
	if child == nil {
		child = &RuleNode{
			Type:  part.Type,
			Value: []byte(part.Value),
		}
		created = true
	}
	err := child.AddRule(parts[1:], opts, id)
	if err == nil && created {
		// Do not modify the tree when failing to insert a rule
		n.Children = append(n.Children, child)
	}
	return err
}

var (
	reSeparator = regexp.MustCompile(`^(?:[^\w\d_\-\.%]|$)`)
)

func matchOptsDomains(opts *RuleOpts, domain string) bool {
	if len(opts.Domains) == 0 {
		return true
	}
	accept := false
	for _, d := range opts.Domains {
		reject := strings.HasPrefix(d, "~")
		if reject {
			d = d[1:]
		}
		if domain == d || strings.HasSuffix(domain, "."+d) {
			if reject {
				return false
			}
			accept = true
		}
	}
	return accept
}

func (n *RuleNode) matchChildren(url []byte, domain string) (int, []*RuleOpts) {
	if len(url) == 0 && len(n.Children) == 0 {
		for _, opt := range n.Opts {
			if !matchOptsDomains(opt, domain) {
				return 0, nil
			}
		}
		return n.RuleId, n.Opts
	}
	// If there are children they have to match
	for _, c := range n.Children {
		ruleId, opts := c.Match(url, domain)
		if opts != nil {
			return ruleId, opts
		}
	}
	return 0, nil
}

func matchDomainAnchor(url []byte, expectedDomain []byte) ([]byte, bool) {
	s := url
	// Match https?://
	if !bytes.HasPrefix(s, []byte("http")) {
		return nil, false
	}
	s = s[4:]
	if len(s) > 0 && s[0] == byte('s') {
		s = s[1:]
	}
	if !bytes.HasPrefix(s, []byte("://")) {
		return nil, false
	}
	s = s[3:]

	// Extract host:port part
	domain := s
	slash := bytes.IndexByte(s, byte('/'))
	if slash < 0 {
		s = nil
	} else {
		domain = s[:slash]
		s = s[slash:]
	}

	// Strip port
Port:
	for i := len(domain); i > 0; i-- {
		c := domain[i-1]
		switch c {
		case byte('0'), byte('1'), byte('2'), byte('3'), byte('4'),
			byte('5'), byte('6'), byte('7'), byte('8'), byte('9'):
			// OK, port numbers
		case byte(':'):
			domain = domain[:i-1]
			break Port
		default:
			break Port
		}
	}
	// Exact match
	if bytes.Equal(expectedDomain, domain) ||
		// Or subdomain
		bytes.HasSuffix(domain, expectedDomain) &&
			len(domain) > len(expectedDomain) &&
			domain[len(domain)-len(expectedDomain)-1] == byte('.') {
		return s, true
	}
	return nil, false
}

func (n *RuleNode) Match(url []byte, domain string) (int, []*RuleOpts) {
	for {
		//fmt.Printf("matching '%s' with %s[%s][final:%v]\n",
		//	string(url), getPartName(n.Type), string(n.Value), n.Opts != nil)
		switch n.Type {
		case Exact:
			if !bytes.HasPrefix(url, n.Value) {
				return 0, nil
			}
			url = url[len(n.Value):]
			return n.matchChildren(url, domain)
		case Separator:
			m := reSeparator.FindSubmatch(url)
			if m == nil {
				return 0, nil
			}
			url = url[len(m[0]):]
			return n.matchChildren(url, domain)
		case Wildcard:
			if len(n.Children) == 0 {
				// Fast-path trailing wildcards
				return n.matchChildren(nil, domain)
			}
			if len(url) == 0 {
				return n.matchChildren(url, domain)
			}
			for i := 0; i < len(url); i++ {
				ruleId, opts := n.matchChildren(url[i:], domain)
				if opts != nil {
					return ruleId, opts
				}
			}
		case DomainAnchor:
			remaining, ok := matchDomainAnchor(url, n.Value)
			if ok {
				return n.matchChildren(remaining, domain)
			}
		case Root:
			return n.matchChildren(url, domain)
		}
		return 0, nil
	}
}

type RuleTree struct {
	root *RuleNode
}

func NewRuleTree() *RuleTree {
	root := &RuleNode{
		Type: Root,
	}
	return &RuleTree{
		root: root,
	}
}

func rewriteDomainAnchors(parts []RulePart) ([]RulePart, error) {
	hasAnchor := false
	rewritten := []RulePart{}
	for i, part := range parts {
		if part.Type == DomainAnchor {
			// Check next part is an exact match
			if i != 0 {
				return nil, fmt.Errorf("invalid non-starting domain anchor")
			}
			if len(parts) < 2 || parts[1].Type != Exact {
				return nil, fmt.Errorf("domain anchor must be followed by exact match")
			}
			hasAnchor = true
		} else if part.Type == Exact && hasAnchor {
			// Extract the domain part of the following Exact part
			value := part.Value
			domain := ""
			slash := strings.Index(value, "/")
			if slash >= 0 {
				domain = value[:slash]
				value = value[slash:]
			} else {
				domain = value
				value = ""
			}
			// Set the domain to the preceding anchor
			rewritten[len(rewritten)-1] = RulePart{
				Type:  DomainAnchor,
				Value: domain,
			}
			if len(value) > 0 {
				// Append remaining trailing Exact
				rewritten = append(rewritten, RulePart{
					Type:  Exact,
					Value: value,
				})
			}
			hasAnchor = false
			continue
		}
		rewritten = append(rewritten, part)
	}
	return rewritten, nil
}

func (t *RuleTree) AddRule(rule *Rule, ruleId int) error {
	if rule.HasOpts() {
		return fmt.Errorf("rule options are not supported")
	}
	rewritten, err := rewriteDomainAnchors(rule.Parts)
	if err != nil {
		return err
	}

	// Add wildcard prefix to most rules
	parts := []RulePart{}
	for i, part := range rewritten {
		first := i == 0
		last := i == len(rewritten)-1
		if first {
			// Match every leading byte unless the rule starts with an anchor
			if part.Type != StartAnchor && part.Type != DomainAnchor {
				parts = append(parts,
					RulePart{
						Type: Wildcard,
					})
			}
		}

		if part.Type == StartAnchor {
			if !first && !last {
				// Anchors in the middle of the rules are not anchor but
				// literal "|"
				parts = append(parts,
					RulePart{
						Type:  Exact,
						Value: "|",
					})
			}
		} else {
			parts = append(parts, part)
		}

		if last {
			// Match every trailing byte unless the rule ends with an anchor
			if part.Type != StartAnchor {
				parts = append(parts,
					RulePart{
						Type: Wildcard,
					})
			}
		}
	}
	if len(parts) == 0 {
		return nil
	}
	return t.root.AddRule(parts, &rule.Opts, ruleId)
}

func (t *RuleTree) Match(url, domain string) (int, []*RuleOpts) {
	return t.root.Match([]byte(url), domain)
}

func (t *RuleTree) String() string {
	w := &bytes.Buffer{}
	var printNode func(*RuleNode, int)
	printNode = func(n *RuleNode, level int) {
		w.WriteString(strings.Repeat(" ", level))
		w.WriteString(getPartName(n.Type))
		switch n.Type {
		case Exact, DomainAnchor:
			w.WriteString("[")
			w.WriteString(string(n.Value))
			w.WriteString("]")
		}
		if len(n.Opts) > 0 {
			for _, opt := range n.Opts {
				fmt.Fprintf(w, "[%s]", opt.Raw)
			}
		}
		w.WriteString("\n")
		for _, c := range n.Children {
			printNode(c, level+1)
		}
	}
	printNode(t.root, 0)
	return w.String()
}

func NewRuleMatcher(rules []*Rule) (*RuleTree, error) {
	tree := NewRuleTree()
	for _, r := range rules {
		err := tree.AddRule(r, 0)
		//if err != nil {
		//	return nil, err
		//}
		_ = err
	}
	return tree, nil
}

type RuleMatcher struct {
	includes *RuleTree
	excludes *RuleTree
}

func NewMatcher() *RuleMatcher {
	return &RuleMatcher{
		includes: NewRuleTree(),
		excludes: NewRuleTree(),
	}
}

func (m *RuleMatcher) AddRule(rule *Rule, ruleId int) error {
	if rule.Exception {
		return m.excludes.AddRule(rule, ruleId)
	} else {
		return m.includes.AddRule(rule, ruleId)
	}
}

func (m *RuleMatcher) Match(url, domain string) (bool, int) {
	id, opts := m.includes.Match(url, domain)
	if opts == nil {
		return false, 0
	}
	_, opts = m.excludes.Match(url, domain)
	return opts == nil, id
}
