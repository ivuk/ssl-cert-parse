#!/usr/bin/env python3


import datetime
import ssl
import OpenSSL


def GetCert(SiteName, Port):
    return ssl.get_server_certificate((SiteName, Port))


def ParseCert(CertRaw):
    Cert = OpenSSL.crypto.load_certificate(
        OpenSSL.crypto.FILETYPE_PEM, CertRaw)

    CertSubject = str(Cert.get_subject())[18:-2]
    CertStartDate = datetime.datetime.strptime(str(Cert.get_notBefore())[2:-1],
                                               '%Y%m%d%H%M%SZ')
    CertEndDate = datetime.datetime.strptime(str(Cert.get_notAfter())[2:-1],
                                             '%Y%m%d%H%M%SZ')
    CertIssuer = str(Cert.get_issuer())[18:-2]

    return {'CertSubject': CertIssuer, 'CertStartDate': CertStartDate,
            'CertEndDate': CertEndDate, 'CertIssuer': CertIssuer}


CertRaw = GetCert('some.domain.tld', 443)

print(CertRaw)

Out = ParseCert(CertRaw)
print(Out)
print(Out['CertSubject'])
print(Out['CertStartDate'])
