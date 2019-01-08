ssl-cert-parse
==============

[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/ambv/black)

Parse SSL certificate information

Usage:

```sh
$ ./ssl-cert-parse.py -h
usage: ssl-cert-parse.py [-h] [-a] [-b] [-d HOSTNAME] [-e] [-f FILENAME]
                         [-p PORT] [-t {tls1,tls1_1,tls1_2}]

optional arguments:
  -h, --help            show this help message and exit
  -a, --all             Show the entire output
  -b, --basic           Show the basic data output
  -d HOSTNAME, --dest HOSTNAME
                        Set the hostname to connect to
  -e, --extended        Show the extended data output
  -f FILENAME, --file FILENAME
                        Set the file that contains the SSL certificate
  -p PORT, --port PORT  Set the port to connect to
  -t {tls1,tls1_1,tls1_2}, --tls-version {tls1,tls1_1,tls1_2}
                        Set the protocol to use when connecting
```
