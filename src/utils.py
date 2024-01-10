# Author : Florian Picca <florian.picca@oppida.fr>
# Date : October 2019

from enum import Enum
import requests
import bs4
import json

"""
Load the different Runners' configuration from the config file.
"""
with open("src/runners.json", "rb") as f:
    RunnerConfs = json.load(f)

"""
This enum indicates the mode of operation to use for the test vectors in case of a bloc cipher like AES.
"""
Mode = Enum("Mode", "ECB CBC CTR CFB OFB GCM")

"""
This enum indicates the nature of the vectors.
 - KAT : Known Answer Test
 - MMT : Multi-block Message Test
 - MCT : Monte Carlo Test (1000 iterations)
"""
Type = Enum("Type", "KAT MMT MCT")

"""
This enum indicates the algorithm to which the test vectors are tied.
 - AES : AES with a 128/192/256 bit key
 - SHA1 : SHA1 producing digests of 160 bits
 - SHA2 : SHA2 family, producing digests of 224/256/384/512 bits
 - ECDH : Elliptic curve Diffie-Hellman key exchange
 - DH : Diffie-Hellman exchange in finite fields
 - HMAC : HMAC applied on SHA1 or SHA2 hash family
 - PBKDF2 : PBKDF2 key derivation based on HMAC SHA1
 - ECDSA : Elliptic curve Digital signature algorithm
 - RSASSA : RSA Signature Scheme with Appendix
 - RSAES : RSA Encryption Scheme
"""
Alg = Enum("Alg", "AES SHA1 SHA2 ECDH DH HMAC PBKDF2 ECDSA RSASSA RSAES")

"""
This enum indicates the operation to perform with a given test vector.
 - ENCR : Encrypts the plaintext
 - DECR : Decrypts the ciphertext
 - SIGN : Signs the message (verification is implicit, if the product is not the one expected)
 - VERIFY : Verify only (used to test bad padding verification)
 - HASH : Hashes the message
 - EXCH : Exchanges a key between 2 parties
"""
Operation = Enum('Operation', 'ENCR DECR SIGN VERIFY HASH EXCH')

"""
This enum indicates the result obtained or expected from a given test vector.
 - OK : The test was successful
 - KO : The test failed
 - ERR : The test encountered an unknown error
 - SKIP : The test was intentionally skipped
"""
Result = Enum('Result', 'OK KO ERR SKIP')

"""
This enum indicates the dialoger commands expected by the external binaries.
"""
Commands = Enum('Commands', 'QUIT VERSION PBKDF HMAC HASHER GCM ECDSA ECDH DH BLOCKCIPHER RSA')


def constructLibEnum():
    """
    This enum indicates the currently supported libraries.
    - Test : The pycrypto python module. Used for validating the test vectors.
    - OpenSSL : The OpenSSL cryptographic library.
    - BouncyCastle : The BouncyCastle cryptographic library.
    """
    # Append the one that are not currently following the standard format
    l = ["Test", "BouncyCastle"]
    for name in RunnerConfs:
        l.append(name)
    return Enum("Lib", " ".join(l))


Lib = constructLibEnum()

def strToEnum(e, s):
    """
    Converts a string representing an enum value, into an enum type.

    :param e: The enum from which the string represents a value.
    :type e: Enum
    :param s: The string representation of the value.
    :type s: str
    :return: The enum whose value is that string.
    :rtype: Enum

    **Examples** ::

        >>> Lib = Enum("Lib", "Test OpenSSL")
        >>> strToEnum(Lib, "OpenSSL")
        <Lib.OpenSSL: 2>

    """
    try:
        return e[s]
    except KeyError:
        return None


def htos(x):
    """
    Converts a hexadecimal string to a byte sequence.
    """
    from binascii import unhexlify
    return unhexlify(x)


def stoh(x):
    """
    Converts a byte sequence to a hexadecimal string.
    """
    from binascii import hexlify
    return hexlify(x).decode('utf-8')


def runProc(*args, **kwargs):
    """
    Launches a subprocess that kills itself when its parent dies.

    :param args: The arguments to launch the subprocess.
    :type args: list[str]

    :return: The STDOUT output of the subprocess launched.
    :rtype: str

    **Examples** ::

        >>> runProc(["pwd"])
        '/tmp/test\\n'
        >>> runProc(["echo", "hello"])
        'hello\\n'
    """
    import subprocess
    p = None
    try:
        p = subprocess.Popen(*args, **kwargs, stdout=subprocess.PIPE)
        p.wait()
        output = p.stdout.read().decode()
        p.stdout.close()
        return output
    finally:
        if p is not None and p.poll() is None:
            p.terminate()  # send sigterm, or ...
            p.kill()  # send sigkill


def getOpenSSLReleases():
    """
    Reads the list of OpenSSL releases from a cache file.
    If the file is not present, the list will be retrieved from GitHub using the API.
    As the API as a rate limit, it's important to only delete the cache file if you want to update the list.
    The rate limit is quite small.

    :return: A dict containing the name of the release as key and the zip download URL as value.
    :rtype: dict[str, str]
    """
    import pickle
    fi = "bin/OpenSSL/versions.pickle"
    try:
        with open(fi, "rb") as f:
            return pickle.load(f)
    except:
        releases = {}
        page = 0
        r = None
        while r != []:
            url = "https://api.github.com/repos/openssl/openssl/tags?page={}".format(page)
            r = requests.get(url).json()
            for e in r:
                if e["name"].lower().startswith("openssl") and "pre" not in e["name"]:
                    releases[e["name"]] = e["zipball_url"]
            page += 1
        with open(fi, "wb") as f:
            pickle.dump(releases, f)
        return releases


def getBouncyCastleReleases():
    """
    Reads the list of BouncyCastle releases from a cache file.
    If the file is not present, the list will be retrieved from the official website.
    To limit the number of requests, it's important to only delete the cache file if you want to update the list.

    :return: A dict containing the name of the release as key and the JAR download URL as value.
    :rtype: dict[str, str]
    """
    import pickle
    fi = "bin/BouncyCastle/versions.pickle"
    try:
        with open(fi, "rb") as f:
            return pickle.load(f)
    except:
        releases = {}
        url = "http://www.bouncycastle.org/archive/"
        r = requests.get(url)
        r = bs4.BeautifulSoup(r.text, features='html5lib')
        for e in r.body.table.tbody.find_all('a'):
            href = e["href"]
            if href.startswith("?") or href == "/":
                continue
            r2 = requests.get(url + href)
            r2 = bs4.BeautifulSoup(r2.text, features='html5lib')
            for a in r2.body.table.tbody.find_all('a'):
                dl = a["href"]
                if dl.startswith("?") or dl == "/":
                    continue
                if not dl.startswith("bcprov-jdk") or not dl.endswith(".jar"):
                    continue
                name = "bcprov {}.{} {}".format(href[0], href[1:3], dl.split("-")[1])
                releases[name] = url+href+dl
        with open(fi, "wb") as f:
            pickle.dump(releases, f)
        return releases


def getMbedTLSReleases():
    """
    Reads the list of mbedTLS releases from a cache file.
    If the file is not present, the list will be retrieved from GitHub using the API.
    As the API as a rate limit, it's important to only delete the cache file if you want to update the list.
    The rate limit is quite small.

    :return: A dict containing the name of the release as key and the zip download URL as value.
    :rtype: dict[str, str]
    """
    import pickle
    fi = "bin/mbedTLS/versions.pickle"
    try:
        with open(fi, "rb") as f:
            return pickle.load(f)
    except:
        releases = {}
        page = 0
        r = None
        while r != []:
            url = "https://api.github.com/repos/ARMmbed/mbedtls/tags?page={}".format(page)
            r = requests.get(url).json()
            for e in r:
                if e["name"].startswith("mbedtls-"):
                    releases[e["name"]] = e["zipball_url"]
            page += 1
        with open(fi, "wb") as f:
            pickle.dump(releases, f)
        return releases


def perror(m):
    """
    Prints a message in red color.

    :param    m: The message to print.
    :type     m: str

    **Examples** ::

        >>> perror("Error")
        Error
    """
    import PySimpleGUI as psg
    psg.cprint(m, colors='red')


def psuccess(m):
    """
    Prints a message in green color.

    :param    m: The message to print.
    :type     m: str

    **Examples** ::

        >>> psuccess("Success")
        Success
    """
    import PySimpleGUI as psg
    psg.cprint(m, colors='green3')


def pwarning(m):
    """
    Prints a message in yellow color.

    :param    m: The message to print.
    :type     m: str

    **Examples** ::

        >>> pwarning("Warning")
        Warning
    """
    import PySimpleGUI as psg
    psg.cprint(m, colors='orange')
