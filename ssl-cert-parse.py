#!/usr/bin/env python3


import argparse
import datetime
import OpenSSL
import socket
import sys


def GetCert(SiteName, Port):
    '''Connect to the specified host and get the certificate file'''
    Client = socket.socket()
    Client.connect((SiteName, Port))

    ClientSSL = OpenSSL.SSL.Connection(OpenSSL.SSL.Context(
                                       OpenSSL.SSL.SSLv3_METHOD), Client)
    ClientSSL.set_connect_state()
    ClientSSL.do_handshake()

    CertDataRaw = str(OpenSSL.crypto.dump_certificate(
                      OpenSSL.crypto.FILETYPE_PEM,
                      ClientSSL.get_peer_certificate()))[2:-1]
    CertData = CertDataRaw.split('\\n')
    Cert = ""

    for line in CertData:
        Cert += line + '\n'

    return Cert


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


def ParseCertExtension(CertRaw):
    '''Parse the available extension data from the certificate file'''
    Cert = OpenSSL.crypto.load_certificate(
        OpenSSL.crypto.FILETYPE_PEM, CertRaw)

    print('Number of extensions:\t{0}'.format(Cert.get_extension_count()))

    ExtNum = 0
    ExtNameVal = dict()

    while ExtNum < Cert.get_extension_count():
        ExtName = str(Cert.get_extension(ExtNum).get_short_name())[2:-1]
        # ExtVal is in raw format
        ExtVal = str(Cert.get_extension(ExtNum).get_data())[2:-1]

        ExtNameVal[ExtName] = ExtVal

        ExtNum += 1

    return ExtNameVal


def PrintOutData(HostName, Port):
    '''Print out the results of ParseCert() function'''
    CertRaw = GetCert(HostName, Port)

    Out = ParseCert(CertRaw)

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


def PrintOutExtData(HostName, Port):
    '''Print out the results of ParseCertExtension() function'''
    CertRaw = GetCert(HostName, Port)

    Out = ParseCertExtension(CertRaw)

    for ExtName, ExtVal in Out.items():
        print('{0}:\t{1}'.format(ExtName, ExtVal))


def PrintOutDataTerse(HostName, Port):
    '''Print out the results of ParseCert() function'''
    CertRaw = GetCert(HostName, Port)

    Out = ParseCert(CertRaw)

    print('Start date:\t{0}'.format(Out['CertStartDate']))
    print('End date:\t{0}'.format(Out['CertEndDate']))


def DoIt():
    """
    Set up the available program options
    Call the proper functions with proper parameters depending on user
    input
    """
    parser = argparse.ArgumentParser()

    parser.add_argument('-a', '--all', dest='All',
                        help='Show the entire output', action='store_true')
    parser.add_argument('-b', '--basic', dest='Basic',
                        help='Show the basic data output',
                        action='store_true')
    parser.add_argument('-d', '--dest', dest='HostName',
                        help='Set the hostname to connect to', type=str,
                        action='store')
    parser.add_argument('-e', '--extended', dest='Extended',
                        help='Show the extended data output',
                        action='store_true')
    parser.add_argument('-p', '--port', dest='Port',
                        help='Set the port to connect to', default=443,
                        type=int, action='store')

    args = parser.parse_args()

    if not args.HostName:
        print("You must specify a hostname, use -d or --dest parameter")
        sys.exit(14)

    if args.All:
        PrintOutData(args.HostName, args.Port)
        PrintOutExtData(args.HostName, args.Port)
    elif args.Basic:
        PrintOutData(args.HostName, args.Port)
    elif args.Extended:
        PrintOutExtData(args.HostName, args.Port)
    else:
        PrintOutDataTerse(args.HostName, args.Port)


if __name__ == "__main__":
    DoIt()
