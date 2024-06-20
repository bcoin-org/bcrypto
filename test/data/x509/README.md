### Generate self-signed x509 Certificate from new private key

```
$ openssl version
LibreSSL 2.6.5

openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout privateKey.key -out certificate.crt
Generating a 2048 bit RSA private key
.......................+++
........+++
writing new private key to 'privateKey.key'
-----
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) []:US
State or Province Name (full name) []:CA
Locality Name (eg, city) []:San Francisco
Organization Name (eg, company) []:bcrypto
Organizational Unit Name (eg, section) []:encodings
Common Name (eg, fully qualified host name) []:https://bcoin.io
Email Address []:satoshi@bcoin.io
```
