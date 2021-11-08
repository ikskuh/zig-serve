# zig-serve

## Development / Tasks

### Create a new self-signed SSL certificate

```sh-console
openssl req -new -x509 -config examples/data/cert-config.cfg -nodes -newkey rsa:2048 -keyout examples/data/key.pem -out examples/data/cert.pem -days 36500
```
