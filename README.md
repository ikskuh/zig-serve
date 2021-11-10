# zig-serve

A implementation of several network protocols for Zig:

- HTTP 1.1
- Gemini
- Gopher
- Finger

## Status

| Protocol | Status       |
| -------- | ------------ |
| Finger   | Not started  |
| Gopher   | Experimental |
| Gemini   | Experimental |
| HTTP(S)  | Experimental |

_Experimental_ means that there is basic support for the protocol, but no spec compliance has been proven yet.

## Development / Tasks

### Create a new self-signed SSL certificate

```sh-console
openssl req -new -x509 -config examples/data/cert-config.cfg -nodes -newkey rsa:2048 -keyout examples/data/key.pem -out examples/data/cert.pem -days 36500
```

### RFCs & Specs

- [RFC1945](https://datatracker.ietf.org/doc/html/rfc1945) - Hypertext Transfer Protocol -- HTTP/1.0
- [RFC2616](https://datatracker.ietf.org/doc/html/rfc2616) - Hypertext Transfer Protocol -- HTTP/1.1
- [RFC7231](https://datatracker.ietf.org/doc/html/rfc7231) - Hypertext Transfer Protocol (HTTP/1.1): Semantics and Content
- [RFC1436](https://datatracker.ietf.org/doc/html/rfc1436) - The Internet Gopher Protocol (a distributed document search and retrieval protocol)
- [Project Gemini](https://gemini.circumlunar.space/docs/specification.gmi) - Speculative specification
- [RFC1288](https://datatracker.ietf.org/doc/html/rfc1288) - The Finger User Information Protocol
