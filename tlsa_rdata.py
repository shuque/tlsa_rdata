#!/usr/bin/env python3

"""
Generate DNS rdata for a TLSA resource record from given parameters.

Usage: tlsa_rdata.py <certfile> <usage> <selector> <matchingtype>

See RFC 6698 for details

       usage: 0, 1, 2, or 3
       selector: 0 (full cert), or 1 (only pubkey)
       matchingtype: 0 (full), 1 (sha256 hash), 2 (sha512 hash)

Author: Shumon Huque <shuque@gmail.com>
"""

import argparse
import hashlib
import M2Crypto


__version__ = "0.3.0"


def process_arguments():
    """Process command line arguments"""

    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="increase output verbosity")
    parser.add_argument("--version", action='version',
                        version='%(prog)s {version}'.format(version=__version__))
    parser.add_argument("filename",
                        help="X.509 certificate file in PEM format")
    parser.add_argument("usage", type=int,
                        help="TLSA usage field (0, 1, 2, or 3)")
    parser.add_argument("selector", type=int,
                        help="TLSA selector: 0 (full cert), 1 (publickey)")
    parser.add_argument("matchingtype", type=int,
                        help="TLSA matching type: 0 (full), 1 (sha256), 2 (sha512)")
    return parser.parse_args()


def compute_hash(func, string):
    """compute hash of string using given hash function"""

    hashfunc = func()
    hashfunc.update(string)
    return hashfunc.hexdigest()


def certfile_to_certobj(filename):
    """convert cert file to M2Crypto X509 object"""

    return M2Crypto.X509.load_cert(filename)


def get_certdata(certobj, sel):
    """given selector, return certificate data in binary (DER) form"""

    if sel == 0:
        certdata = certobj.as_der()
    elif sel == 1:
        certdata = certobj.get_pubkey().as_der()
    else:
        raise ValueError("selector type %d not recognized" % sel)
    return certdata


def get_hexdata(certfile, selector, matchtype):
    """given matchtype, return hex of certdata or its hash"""

    certobj = certfile_to_certobj(certfile)
    certdata = get_certdata(certobj, selector)

    if matchtype == 0:
        hexdata = certdata.hex()
    elif matchtype == 1:
        hexdata = compute_hash(hashlib.sha256, certdata)
    elif matchtype == 2:
        hexdata = compute_hash(hashlib.sha512, certdata)
    else:
        raise ValueError("matchtype %d not recognized" % matchtype)
    return hexdata


def get_rdata(certfile, cusage, selector, matchtype):
    """return presentation format TLSA rdata"""

    hexdata = get_hexdata(certfile, selector, matchtype)
    return "{} {} {} {}".format(cusage, selector, matchtype, hexdata)


if __name__ == '__main__':

    args = process_arguments()
    print(get_rdata(args.filename,
                    args.usage,
                    args.selector,
                    args.matchingtype))
