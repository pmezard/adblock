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

