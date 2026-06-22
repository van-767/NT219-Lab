# Lab 4 Task 2 — PKI & TLS Deployment
```bash
# Tổng quan
openssl x509 -in cert/certificate.crt -text -noout

# Verify signature chain
openssl verify -CAfile cert/ca_bundle.crt cert/certificate.crt
# → certificate.crt: OK

# TLS handshake
openssl s_client -connect nt219-zerotrust.duckdns.org:443 -servername nt219-zerotrust.duckdns.org 2>&1 


