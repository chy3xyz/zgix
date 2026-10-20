# Certificates for HTTPS examples

Generate self-signed certificates for testing:

```bash
cd examples/cert
openssl ecparam -genkey -name prime256v1 -out key.pem
openssl req -new -key key.pem -out cert.csr -subj "/CN=localhost"
openssl x509 -req -in cert.csr -signkey key.pem -out cert.pem
```
