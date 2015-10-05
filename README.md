# adblock

[![Build Status](https://travis-ci.org/pmezard/adblock.png?branch=master)](https://travis-ci.org/pmezard/adblock)
[![GoDoc](https://godoc.org/github.com/pmezard/adblock?status.svg)](https://godoc.org/github.com/pmezard/adblock)

AdBlockPlus parser, matcher and transparent HTTP/HTTPS proxy

Package documentation can be found at:

  http://godoc.org/github.com/pmezard/adblock/adblock
  
## adstop

adstop is an ad-blocking transparent HTTP/HTTPS proxy.

It was designed to run on low power, low memory ARM devices and serve a couple
of clients, mostly old smartphones which cannot run adblockers themselves.

Before using it, you have to configure your devices and network to make it
accessible as a transparent proxy. One way to achieve this is to install
a VPN on the server side and redirect all HTTP/HTTPS traffic to the proxy
with routing rules. Then make the client browse through the VPN.

HTTPS filtering requires the proxy to intercept the device traffic and decrypt
it. To allow this, you have to generate a certificate and add it to your
device.

```
$ adstop -http localhost:1080 \
	-https localhost:1081     \
	-cache .adstop			  \
	-max-age 24h			  \
	-ca-cert /path/to/ca.cert \
	-ca-key /path/to/ca.key   \
	https://easylist-downloads.adblockplus.org/easylist.txt \
	some_local_list.txt
```
starts the proxy and makes it listen on HTTP on port 1080, HTTPS on port 1081,
fetch and load rules from easylist and a local file, cache easylist in an
.adstop/ directory and refresh it every 24 hours.

### How does it work?

adstop monitors HTTP/HTTPS requests and responses and if one of these matches a
filter, it returns a 404 error to the client. It does not modify response
bodies. Rules without options or which options are not based on returned data
are applied on requests, the others on responses.

The difficult part is to apply Adblock rules. They were designed to operate in
a web browser and were assumed to have access to a lot more of information than
a simple web proxy has. adstop supports only a subset of available rules:
- Rules without options (`"$..."` suffix) are completely supported
- The following options are supported:
  * `domain=foo.com|bar.com|~baz.com`
  * `font`, `image`, `objects`, `script`, `stylesheet` are roughly approximated
    using Content-Type.
  * `thirdparty` is approximated with the Referrer header.
- The following options are not-supported, and related rules are discared:
  * `document`
  * `media`
  * `popup`
- Element hiding rules are ignored.
- Other options are ignored and rules applied without them.

