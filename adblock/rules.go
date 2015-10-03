/*
Package implements a parser and a matcher for AdBlockPlus rules.

The syntax of AdBlockPlus rules is partially defined in
https://adblockplus.org/en/filter-cheatsheet and
https://adblockplus.org/en/filters.

To parse rules and build a matcher:

	matcher := adblock.NewMatcher()
	fp, err := os.Open("easylist.txt")
	...
	rules, err := adblock.ParseRules(fp)
	for _, rule := range rules {
		err = matcher.AddRule(rule, 0)
		...
	}

To match HTTP requests:

	host := r.URL.Host
	if host == "" {
		host = r.Host
	}
	rq := adblock.Request{
		URL: r.URL.String(),
		Domain: host,
		// possibly fill OriginDomain from Referrer header
		// and ContentType from HTTP response Content-Type.
	}
	matched, id := matcher.Match(rq)
	if matched {
		// Use the rule identifier to print which rules was matched
	}
*/
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

	Root      = iota
	Substring = iota // Wildcard + Exact
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
	case Substring:
		return "substring"
	default:
		return "unknown"
	}
}

// RulePart is the base component of rules. It represents a single
// matching element, like an exact match, a wildcard, a domain anchor...
type RulePart struct {
	// Rule type, like Exact, Wildcard, etc.
	Type int
	// Rule part string representation
	Value string
}

// RuleOpts defines custom rules applied to content once the URL part
// has been matched by the RuleParts.
type RuleOpts struct {
	Raw              string
	Collapse         *bool
	Document         bool
	Domains          []string
	ElemHide         bool
	Font             *bool
	Image            *bool
	Media            *bool
	Object           *bool
	ObjectSubRequest *bool
	Other            *bool
	Popup            *bool
	Script           *bool
	Stylesheet       *bool
	SubDocument      *bool
	ThirdParty       *bool
	XmlHttpRequest   *bool
}

// NewRuleOpts parses the rule part following the '$' separator
// and return content matching options.
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
		case opt == "other":
			opts.Other = &value
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
		case opt == "font":
			opts.Font = &value
		default:
			return opts, fmt.Errorf("unknown rule option: %s", opt)
		}
	}
	return opts, nil
}

// Rule represents a complete adblockplus rule.
type Rule struct {
	// The original string representation
	Raw string
	// Exception is true for exclusion rules (prefixed with "@@")
	Exception bool
	// Parts is the sequence of RulePart matching URLs
	Parts []RulePart
	// Opts are optional rules applied to content
	Opts RuleOpts
}

var (
	NullOpts = RuleOpts{}
)

func (r *Rule) HasOpts() bool {
	// Collapse is related to ElemHide, and irrelevant
	return r.Opts.Document ||
		// len(r.Opts.Domains) > 0 // handled
		// r.Opts.ElemHide // irrelevant
		// r.Opts.Image != nil || // handled
		r.Opts.Media != nil ||
		// r.Opts.Object != nil || // handled
		// r.Opts.ObjectSubRequest != nil || // cannot guess request source
		// r.Opts.Other != nil // not sure what to do with this one
		r.Opts.Popup != nil
	// r.Opts.Script != nil || // handled
	// r.Opts.Stylesheet != nil || // handled
	// r.Opts.SubDocument != nil || // cannot guess request source
	// r.Opts.ThirdParty != nil // handled
	// r.Opts.XmlHttpRequest != nil // cannot guess request source
}

func (r *Rule) HasContentOpts() bool {
	return r.Opts.Image != nil ||
		r.Opts.Object != nil ||
		r.Opts.Script != nil ||
		r.Opts.Stylesheet != nil ||
		r.Opts.Font != nil
}

// ParseRule parses a single rule.
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

// ParseRules returns the sequence of rules extracted from supplied reader
// content.
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

// Request defines client request properties to be matched against a set
// of rules.
type Request struct {
	// URL is matched against rule parts. Mandatory.
	URL string
	// Domain is matched against optional domain or third-party rules
	Domain string
	// ContentType is matched against optional content rules. This
	// information is often available only in client responses. Filters
	// may be applied twice, once at request time, once at response time.
	ContentType string
	// OriginDomain is matched against optional third-party rules.
	OriginDomain string
}

// RuleNode is the node structure of rule trees.
// Rule trees start with a Root node containing any number of non-Root
// RuleNodes.
type ruleNode struct {
	Type     int
	Value    []byte
	Opts     []*RuleOpts // non-empty on terminating nodes
	Children []*ruleNode
	RuleId   int
}

func (n *ruleNode) AddRule(parts []RulePart, opts *RuleOpts, id int) error {
	if len(parts) == 0 {
		n.Opts = append(n.Opts, opts)
		n.RuleId = id
		return nil
	}
	// Looks for existing matching rule parts
	part := parts[0]
	if part.Type != Exact && part.Type != Wildcard && part.Type != Separator &&
		part.Type != DomainAnchor && part.Type != Substring {
		return fmt.Errorf("unknown rule part type: %+v", part)
	}
	var child *ruleNode
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
		child = &ruleNode{
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

func matchOptsContent(opts *RuleOpts, contentType string) bool {
	if opts.Image != nil {
		isImage := strings.HasPrefix(contentType, "image/")
		if isImage != *opts.Image {
			return false
		}
	}
	if opts.Object != nil {
		isObject := strings.Contains(contentType, "shockwave")
		if isObject != *opts.Object {
			return false
		}
	}
	if opts.Script != nil {
		isScript := strings.Contains(contentType, "script")
		if isScript != *opts.Script {
			return false
		}
	}
	if opts.Stylesheet != nil {
		isStylesheet := strings.Contains(contentType, "css")
		if isStylesheet != *opts.Stylesheet {
			return false
		}
	}
	if opts.Font != nil {
		isFont := strings.Contains(contentType, "font")
		if isFont != *opts.Font {
			return false
		}
	}
	return true
}

func matchOptsThirdParty(opts *RuleOpts, origin, domain string) bool {
	if opts.ThirdParty == nil {
		return true
	}
	isSubdomain := origin == domain ||
		strings.HasSuffix(domain, "."+origin)
	return isSubdomain != *opts.ThirdParty
}

func (n *ruleNode) matchChildren(url []byte, rq *Request) (int, []*RuleOpts) {
	if len(url) == 0 && len(n.Children) == 0 {
		for _, opt := range n.Opts {
			if !matchOptsDomains(opt, rq.Domain) {
				return 0, nil
			}
			if !matchOptsContent(opt, rq.ContentType) {
				return 0, nil
			}
			if !matchOptsThirdParty(opt, rq.OriginDomain, rq.Domain) {
				return 0, nil
			}
		}
		return n.RuleId, n.Opts
	}
	// If there are children they have to match
	for _, c := range n.Children {
		ruleId, opts := c.Match(url, rq)
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

// Match evaluates a piece of a request URL against the node subtree. If it
// matches an existing rule, returns the rule identifier and its options set.
// Requests are evaluated by applying the nodes on its URL in DFS order. When
// the URL is completely matched by a terminal node, a node with a non-empty
// Opts set, the Opts are applied on the Request properties.  Any option match
// validates the URL as a whole and the matching rule identifier is returned.
func (n *ruleNode) Match(url []byte, rq *Request) (int, []*RuleOpts) {
	for {
		//fmt.Printf("matching '%s' with %s[%s][final:%v]\n",
		//	string(url), getPartName(n.Type), string(n.Value), n.Opts != nil)
		switch n.Type {
		case Exact:
			if !bytes.HasPrefix(url, n.Value) {
				return 0, nil
			}
			url = url[len(n.Value):]
			return n.matchChildren(url, rq)
		case Separator:
			m := reSeparator.FindSubmatch(url)
			if m == nil {
				return 0, nil
			}
			url = url[len(m[0]):]
			return n.matchChildren(url, rq)
		case Wildcard:
			if len(n.Children) == 0 {
				// Fast-path trailing wildcards
				return n.matchChildren(nil, rq)
			}
			if len(url) == 0 {
				return n.matchChildren(url, rq)
			}
			for i := 0; i < len(url); i++ {
				ruleId, opts := n.matchChildren(url[i:], rq)
				if opts != nil {
					return ruleId, opts
				}
			}
		case DomainAnchor:
			remaining, ok := matchDomainAnchor(url, n.Value)
			if ok {
				return n.matchChildren(remaining, rq)
			}
		case Root:
			return n.matchChildren(url, rq)
		case Substring:
			for {
				if len(url) == 0 {
					break
				}
				pos := bytes.Index(url, n.Value)
				if pos < 0 {
					break
				}
				url = url[pos+len(n.Value):]
				ruleId, opts := n.matchChildren(url, rq)
				if opts != nil {
					return ruleId, opts
				}
			}
		}
		return 0, nil
	}
}

// A RuleTree matches a set of adblockplus rules.
type ruleTree struct {
	root *ruleNode
}

// NewRuleTree returns a new empty RuleTree.
func newRuleTree() *ruleTree {
	return &ruleTree{
		root: &ruleNode{
			Type: Root,
		},
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

// Add explicit leading and trailing wildcards where they are implicitely
// required.
func addLeadingTrailingWildcards(parts []RulePart) []RulePart {
	rewritten := []RulePart{}
	for i, part := range parts {
		first := i == 0
		last := i == len(parts)-1
		if first {
			// Match every leading byte unless the rule starts with an anchor
			if part.Type != StartAnchor && part.Type != DomainAnchor {
				rewritten = append(rewritten,
					RulePart{
						Type: Wildcard,
					})
			}
		}

		if part.Type == StartAnchor {
			if !first && !last {
				// Anchors in the middle of the rules are not anchor but
				// literal "|"
				rewritten = append(rewritten,
					RulePart{
						Type:  Exact,
						Value: "|",
					})
			}
		} else {
			rewritten = append(rewritten, part)
		}

		if last {
			// Match every trailing byte unless the rule ends with an anchor
			if part.Type != StartAnchor {
				rewritten = append(rewritten,
					RulePart{
						Type: Wildcard,
					})
			}
		}
	}
	return rewritten
}

// Rewrite Wildcard + Exact as a Substring
func replaceWildcardWithSubstring(parts []RulePart) []RulePart {
	rewritten := []RulePart{}
	for i, part := range parts {
		if i == 0 || parts[i-1].Type != Wildcard {
			rewritten = append(rewritten, part)
			continue
		}
		if part.Type != Exact {
			rewritten = append(rewritten, part)
			continue
		}
		rewritten[len(rewritten)-1] = RulePart{
			Type:  Substring,
			Value: part.Value,
		}
	}
	return rewritten
}

// AddRule add a rule and its identifier to the rule tree.
func (t *ruleTree) AddRule(rule *Rule, ruleId int) error {
	if rule.HasOpts() {
		return fmt.Errorf("rule options are not supported")
	}
	rewritten, err := rewriteDomainAnchors(rule.Parts)
	if err != nil {
		return err
	}
	rewritten = addLeadingTrailingWildcards(rewritten)
	rewritten = replaceWildcardWithSubstring(rewritten)

	if len(rewritten) == 0 {
		return nil
	}
	return t.root.AddRule(rewritten, &rule.Opts, ruleId)
}

// Match evaluates the request. If it matches any rule, it returns the
// rule identifier and its options.
func (t *ruleTree) Match(rq *Request) (int, []*RuleOpts) {
	return t.root.Match([]byte(rq.URL), rq)
}

func (t *ruleTree) String() string {
	w := &bytes.Buffer{}
	var printNode func(*ruleNode, int)
	printNode = func(n *ruleNode, level int) {
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

// RuleMatcher implements a complete set of include and exclude AdblockPlus
// rules.
type RuleMatcher struct {
	includes *ruleTree
	excludes *ruleTree
	// Rules requiring resource content type
	contentIncludes *ruleTree
	contentExcludes *ruleTree
}

// NewMatcher returns a new empty matcher.
func NewMatcher() *RuleMatcher {
	return &RuleMatcher{
		includes:        newRuleTree(),
		excludes:        newRuleTree(),
		contentIncludes: newRuleTree(),
		contentExcludes: newRuleTree(),
	}
}

// AddRule adds a rule to the matcher. Supplied rule identifier will be
// returned by Match().
func (m *RuleMatcher) AddRule(rule *Rule, ruleId int) error {
	var tree *ruleTree
	if rule.HasContentOpts() {
		if rule.Exception {
			tree = m.contentExcludes
		} else {
			tree = m.contentIncludes
		}
	} else {
		if rule.Exception {
			tree = m.excludes
		} else {
			tree = m.includes
		}
	}
	return tree.AddRule(rule, ruleId)
}

// Match applies include and exclude rules on supplied request. If the
// request is accepted, it returns true and the matching rule identifier.
func (m *RuleMatcher) Match(rq *Request) (bool, int) {
	inc := m.includes
	exc := m.excludes
	if len(rq.ContentType) > 0 {
		inc = m.contentIncludes
		exc = m.contentExcludes
	}
	id, opts := inc.Match(rq)
	if opts == nil {
		return false, 0
	}
	_, opts = exc.Match(rq)
	return opts == nil, id
}

// String returns a textual representation of the include and exclude rules,
// matching request with or without content.
func (m *RuleMatcher) String() string {
	return fmt.Sprintf("includes:\n%s\nexcludes:\n%s\n"+
		"content-includes:\n%s\ncontent-excludes:\n%s\n",
		m.includes, m.excludes, m.contentIncludes, m.contentExcludes)
}
