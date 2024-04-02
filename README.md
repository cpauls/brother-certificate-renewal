# Brother Certificate Renewal

```
usage: brother_update_cert.py [-h] [-p PROTOCOL] [-cP CERTPASSWORD]
                              hostname certificate password

positional arguments:
  hostname              Hostname or IP. Without http://.
  certificate           Full path of the certificate (.pfx file).
  password              Administrator login password

optional arguments:
  -h, --help            show this help message and exit
  -p PROTOCOL, --protocol PROTOCOL
                        Protocol: HTTP or HTTPS. By default it's https
  -cP CERTPASSWORD, --certPassword CERTPASSWORD
                        Password for certificate. By default it's empty ''
```

# Reference
https://davidlebr1.gitbook.io/a-journey-in-infosec/blog/brother-printer-automatic-certificate-renewal
