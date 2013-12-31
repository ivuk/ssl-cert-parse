#!/usr/bin/env python3


import datetime
import ssl
import OpenSSL


def GetCert(SiteName, Port):
    return ssl.get_server_certificate((SiteName, Port))


def ParseCert(CertRaw):
    Cert = OpenSSL.crypto.load_certificate(
        OpenSSL.crypto.FILETYPE_PEM, CertRaw)
    print(str(Cert.get_subject())[18:-2])
    print(datetime.datetime.strptime(str(Cert.get_notBefore())[2:-1],
          '%Y%m%d%H%M%SZ'))
    print(datetime.datetime.strptime(str(Cert.get_notAfter())[2:-1],
          '%Y%m%d%H%M%SZ'))
    print(str(Cert.get_issuer())[18:-2])


CertRaw = GetCert('www.nimium.hr', 443)
print(CertRaw)
ParseCert(CertRaw)
