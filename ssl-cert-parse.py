#!/usr/bin/env python3


import datetime
import ssl
import OpenSSL


def GetCert(SiteName, Port):
    '''Connect to the specified host and get the certificate file'''
    return ssl.get_server_certificate((SiteName, Port))


def ParseCert(CertRaw):
    '''Parse the available data from the certificate file'''
    Cert = OpenSSL.crypto.load_certificate(
        OpenSSL.crypto.FILETYPE_PEM, CertRaw)

    CertExpired = Cert.has_expired()
    CertVersion = Cert.get_version()
    CertSigAlgo = str(Cert.get_signature_algorithm())[2:-1]
    CertSubject = str(Cert.get_subject())[18:-2]
    CertStartDate = datetime.datetime.strptime(str(Cert.get_notBefore())[2:-1],
                                               '%Y%m%d%H%M%SZ')
    CertEndDate = datetime.datetime.strptime(str(Cert.get_notAfter())[2:-1],
                                             '%Y%m%d%H%M%SZ')
    CertIssuer = str(Cert.get_issuer())[18:-2]

    return {'CertSubject': CertSubject, 'CertStartDate': CertStartDate,
            'CertEndDate': CertEndDate, 'CertIssuer': CertIssuer,
            'CertSigAlgo': CertSigAlgo, 'CertExpired': CertExpired,
            'CertVersion': CertVersion}


def PrintOutData(HostName, Port):
    '''Print out the results of ParseCert() function'''
    CertRaw = GetCert(HostName, Port)

    Out = ParseCert(CertRaw)

    print(Out)
    print('Subject:\t{0}'.format(Out['CertSubject']))
    print('Start date:\t{0}'.format(Out['CertStartDate']))
    print('End date:\t{0}'.format(Out['CertEndDate']))
    print('Issuer:\t\t{0}'.format(Out['CertIssuer']))
    print('Algorithm:\t{0}'.format(Out['CertSigAlgo']))
    print('Version:\t{0}'.format(Out['CertVersion']))
    if Out['CertExpired']:
        print('Expired:\tYes')
    else:
        print('Expired:\tNo')

PrintOutData('some.domain.tld', 443)
