# Author : Florian Picca <florian.picca@oppida.fr>
# Date : October 2019

"""
This file contains all the functions necessary to validate the test vectors.
It's used by the Class Test_Runner.
"""

from .utils import perror, stoh, htos
from Crypto.Cipher import AES
from Crypto.Util import Counter
from hashlib import sha1, sha224, sha256, sha384, sha512
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
import hmac
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5


def aesCBCencr(pt, key, iv):
    """
    AES CBC encryption.
    the arguments must be hexadecimal strings.
    returns the encryption result a hexadecimal string.
    """
    try:
        aes = AES.new(htos(key), AES.MODE_CBC, htos(iv))
        return stoh(aes.encrypt(htos(pt)))
    except Exception as e:
        perror(e)
        return None


def aesECBencr(pt, key):
    """
    AES ECB encryption.
    the arguments must be hexadecimal strings.
    returns the encryption result a hexadecimal string.
    """
    try:
        aes = AES.new(htos(key), AES.MODE_ECB)
        return stoh(aes.encrypt(htos(pt)))
    except Exception as e:
        perror(e)
        return None


def aesCTRencr(pt, key, ctr):
    """
    AES CTR encryption.
    the arguments must be hexadecimal strings.
    returns the encryption result a hexadecimal string.
    """
    try:
        counter = Counter.new(len(ctr) * 4, initial_value=int(ctr, 16))
        aes = AES.new(htos(key), AES.MODE_CTR, counter=counter)
        return stoh(aes.encrypt(htos(pt)))
    except Exception as e:
        perror(e)
        return None


def aesCFBencr(pt, key, iv, seglen):
    """
    AES CFB encryption.
    the arguments must be hexadecimal strings except for seglen.
    returns the encryption result a hexadecimal string.
    """
    try:
        aes = AES.new(htos(key), AES.MODE_CFB, htos(iv), segment_size=seglen)
        return stoh(aes.encrypt(htos(pt)))
    except Exception as e:
        perror(e)
        return None


def aesOFBencr(pt, key, iv):
    """
    AES OFB encryption.
    the arguments must be hexadecimal strings.
    returns the encryption result a hexadecimal string.
    """
    try:
        aes = AES.new(htos(key), AES.MODE_OFB, htos(iv))
        return stoh(aes.encrypt(htos(pt)))
    except Exception as e:
        perror(e)
        return None


def aesCBCdecr(ct, key, iv):
    """
    AES CBC decryption.
    the arguments must be hexadecimal strings.
    returns the decryption result a hexadecimal string.
    """
    try:
        aes = AES.new(htos(key), AES.MODE_CBC, htos(iv))
        return stoh(aes.decrypt(htos(ct)))
    except Exception as e:
        perror(e)
        return None


def aesECBdecr(ct, key):
    """
    AES ECB decryption.
    the arguments must be hexadecimal strings.
    returns the decryption result a hexadecimal string.
    """
    try:
        aes = AES.new(htos(key), AES.MODE_ECB)
        return stoh(aes.decrypt(htos(ct)))
    except Exception as e:
        perror(e)
        return None


def aesCTRdecr(ct, key, ctr):
    """
    AES CTR decryption.
    the arguments must be hexadecimal strings.
    returns the decryption result a hexadecimal string.
    """
    try:
        counter = Counter.new(len(ctr) * 4, initial_value=int(ctr, 16))
        aes = AES.new(htos(key), AES.MODE_CTR, counter=counter)
        return stoh(aes.decrypt(htos(ct)))
    except Exception as e:
        perror(e)
        return None


def aesCFBdecr(ct, key, iv, seglen):
    """
    AES CFB decryption.
    the arguments must be hexadecimal strings except for seglen.
    returns the decryption result a hexadecimal string.
    """
    try:
        aes = AES.new(htos(key), AES.MODE_CFB, htos(iv), segment_size=seglen)
        return stoh(aes.decrypt(htos(ct)))
    except Exception as e:
        perror(e)
        return None


def aesOFBdecr(ct, key, iv):
    """
    AES OFB decryption.
    the arguments must be hexadecimal strings.
    returns the decryption result a hexadecimal string.
    """
    try:
        aes = AES.new(htos(key), AES.MODE_OFB, htos(iv))
        return stoh(aes.decrypt(htos(ct)))
    except Exception as e:
        perror(e)
        return None


def aesCBCencrMCT(pt, key, iv):
    """
    AES CBC MCT encryption.
    the arguments must be hexadecimal strings.
    returns the 1000th encryption result a hexadecimal string.
    """
    try:
        p = htos(pt)
        iv = htos(iv)
        aes = AES.new(htos(key), AES.MODE_CBC, iv)
        for _ in range(1000):
            p, iv = iv, aes.encrypt(p)
        return stoh(iv)
    except Exception as e:
        perror(e)
        return None


def aesECBencrMCT(pt, key):
    """
    AES ECB MCT encryption.
    the arguments must be hexadecimal strings.
    returns the 1000th encryption result a hexadecimal string.
    """
    try:
        aes = AES.new(htos(key), AES.MODE_ECB)
        p = htos(pt)
        for _ in range(1000):
            p = aes.encrypt(p)
        return stoh(p)
    except Exception as e:
        perror(e)
        return None


def aesCFBencrMCT(pt, key, iv, seglen):
    """
    AES CFB MCT encryption.
    the arguments must be hexadecimal strings except for seglen.
    returns the 1000th encryption result a hexadecimal string.
    """
    try:
        iv = htos(iv)
        aes = AES.new(htos(key), AES.MODE_CFB, iv, segment_size=seglen)
        p = htos(pt)
        tmp = []
        res = iv
        for i in range(1000):
            if seglen == 128:
                p, iv = iv, aes.encrypt(p)
                res = iv
            elif seglen == 8:
                res = aes.encrypt(p)
                if i < 16:
                    p = bytes([iv[i]])
                else:
                    p = tmp[i - 16]
                tmp.append(res)
        return stoh(res)
    except Exception as e:
        perror(e)
        return None


def aesOFBencrMCT(pt, key, iv):
    """
    AES OFB MCT encryption.
    the arguments must be hexadecimal strings.
    returns the 1000th encryption result a hexadecimal string.
    """
    try:
        iv = htos(iv)
        aes = AES.new(htos(key), AES.MODE_OFB, iv)
        p = htos(pt)
        for _ in range(1000):
            p, iv = iv, aes.encrypt(p)
        return stoh(iv)
    except Exception as e:
        perror(e)
        return None


def aesCBCdecrMCT(ct, key, iv):
    """
    AES CBC MCT decryption.
    the arguments must be hexadecimal strings.
    returns the 1000th decryption result a hexadecimal string.
    """
    try:
        p = htos(ct)
        iv = htos(iv)
        aes = AES.new(htos(key), AES.MODE_CBC, iv)
        for _ in range(1000):
            p, iv = iv, aes.decrypt(p)
        return stoh(iv)
    except Exception as e:
        perror(e)
        return None


def aesECBdecrMCT(ct, key):
    """
    AES ECB MCT decryption.
    the arguments must be hexadecimal strings.
    returns the 1000th decryption result a hexadecimal string.
    """
    try:
        aes = AES.new(htos(key), AES.MODE_ECB)
        p = htos(ct)
        for _ in range(1000):
            p = aes.decrypt(p)
        return stoh(p)
    except Exception as e:
        perror(e)
        return None


def aesCFBdecrMCT(ct, key, iv, seglen):
    """
    AES CFB MCT decryption.
    the arguments must be hexadecimal strings except for seglen.
    returns the 1000th decryption result a hexadecimal string.
    """
    try:
        iv = htos(iv)
        aes = AES.new(htos(key), AES.MODE_CFB, iv, segment_size=seglen)
        p = htos(ct)
        tmp = []
        res = iv
        for i in range(1000):
            if seglen == 128:
                p, iv = iv, aes.decrypt(p)
                res = iv
            elif seglen == 8:
                res = aes.decrypt(p)
                if i < 16:
                    p = bytes([iv[i]])
                else:
                    p = tmp[i - 16]
                tmp.append(res)
        return stoh(res)
    except Exception as e:
        perror(e)
        return None


def aesOFBdecrMCT(ct, key, iv):
    """
    AES OFB MCT decryption.
    the arguments must be hexadecimal strings.
    returns the 1000th decryption result a hexadecimal string.
    """
    try:
        iv = htos(iv)
        aes = AES.new(htos(key), AES.MODE_OFB, iv)
        p = htos(ct)
        for _ in range(1000):
            p, iv = iv, aes.decrypt(p)
        return stoh(iv)
    except Exception as e:
        perror(e)
        return None


def aesGCMEncr(pt, header, key, nonce, taglen):
    """
    AES GCM encryption.
    The arguments must be hexadecimal strings.
    returns the ciphertext and the associated tag.
    """
    try:
        cipher = AES.new(htos(key), AES.MODE_GCM, nonce=htos(nonce), mac_len=taglen)
        cipher.update(htos(header))
        c, t = cipher.encrypt_and_digest(htos(pt))
        return stoh(c), stoh(t)
    except Exception as e:
        perror(e)
        return None


def aesGCMDecr(ct, header, key, nonce, tag):
    """
    AES GCM decryption.
    The arguments must be hexadecimal strings.
    returns the plaintext or none if the tag is invalid.
    """
    try:
        cipher = AES.new(htos(key), AES.MODE_GCM, nonce=htos(nonce), mac_len=len(htos(tag)))
        cipher.update(htos(header))
        p = cipher.decrypt_and_verify(htos(ct), htos(tag))
        return stoh(p)
    except ValueError:
        # This is raised when the tag is invalid
        # Return something that is not a string
        return False
    except Exception as e:
        perror(e)
        return None


def sha1Hash(pt):
    """
    computes a SHA1 hash.
    pt must be a hexadecimal string.
    returns the hash as a hexadecimal string.
    """
    try:
        hasher = sha1()
        hasher.update(htos(pt))
        return hasher.hexdigest()
    except Exception as e:
        perror(e)
        return None


def sha2Hash(pt, size):
    """
    computes a SHA2 family hash.
    pt must be a hexadecimal string.
    returns the hash as a hexadecimal string.
    """
    try:
        if size == 224:
            hasher = sha224()
        elif size == 256:
            hasher = sha256()
        elif size == 384:
            hasher = sha384()
        elif size == 512:
            hasher = sha512()
        else:
            raise NotImplementedError("Invalid hash size : {}".format(size))
        hasher.update(htos(pt))
        return hasher.hexdigest()
    except Exception as e:
        perror(e)
        return None


def sha1HashMCT(pt):
    """
    Computes MCT test for SHA1.
    pt must be a hexadecimal string
    returns all the checkpoints' hash values as hex strings
    """
    try:
        checkpoints = []
        h = pt  # initial seed
        for i in range(100):
            m = [h] * 3
            # checkpoint every 1000 iterations
            for _ in range(1000):
                h = sha1Hash(''.join(m))
                m.append(h)
                m.pop(0)
            # last h is the new seed
            checkpoints.append(h)
        return checkpoints
    except Exception as e:
        perror(e)
        return None


def sha2HashMCT(pt, size):
    """
    Computes MCT test for SHA2 family.
    pt must be a hexadecimal string
    returns all the checkpoints' hash values as hex strings
    """
    try:
        checkpoints = []
        h = pt  # initial seed
        for i in range(100):
            m = [h] * 3
            # checkpoint every 1000 iterations
            for _ in range(1000):
                h = sha2Hash(''.join(m), size)
                m.append(h)
                m.pop(0)
            # last h is the new seed
            checkpoints.append(h)
        return checkpoints
    except Exception as e:
        perror(e)
        return None


def diffie_hellman(p, g, da, db, hashfunction=None):
    """
    Manual computation of DH.
    Arguments must be hexstrings
    return numbers in decimal form but the hash as hexstring
    """
    p = int(p, 16)
    g = int(g, 16)
    da = int(da, 16)
    db = int(db, 16)

    Apub = pow(g, da, p)
    Bpub = pow(g, db, p)
    sk = pow(Bpub, da, p)
    if hashfunction is not None:
        h = hex(sk)[2:]
        if len(h) % 2 != 0:
            h = '0'+h
        if hashfunction == "SHA512":
            h = sha2Hash(h, 512)
        else:
            raise NotImplementedError("Unknown hash function : {}".format(hashfunction))

        return Apub, Bpub, sk, h
    return Apub, Bpub, sk


def ecdh(curvename, da, xb, yb):
    """
    returns (xa, ya, shared key) in decimal form
    Arguments must be hex strings
    """
    if curvename == "secp192r1":
        curve = ec.SECP192R1()
    elif curvename == "secp224r1":
        curve = ec.SECP224R1()
    elif curvename == "secp256r1":
        curve = ec.SECP256R1()
    elif curvename == "secp384r1":
        curve = ec.SECP384R1()
    elif curvename == "secp521r1":
        curve = ec.SECP521R1()
    elif curvename == "brainpoolP256r1":
        curve = ec.BrainpoolP256R1()
    elif curvename == "brainpoolP384r1":
        curve = ec.BrainpoolP384R1()
    elif curvename == "brainpoolP512r1":
        curve = ec.BrainpoolP512R1()
    else:
        raise NotImplementedError("Unknown curve name : {}".format(curvename))

    da = int(da, 16)
    xb = int(xb, 16)
    yb = int(yb, 16)

    # genere une clé privé A à partir de la valeur secrete pa
    Apvt = ec.derive_private_key(da, curve, default_backend())
    Apub = Apvt.public_key()
    xa = Apub.public_numbers().x
    ya = Apub.public_numbers().y

    # genere une pair de clé B : (p, g, xb, yb)
    Bpub = ec.EllipticCurvePublicNumbers(xb, yb, curve).public_key(default_backend())
    shared_key = int(stoh(Apvt.exchange(ec.ECDH(), Bpub)), 16)

    # calcul la clé partagée
    return xa, ya, shared_key


def ecdsa(curvename, digest, d, k):
    """
    returns (r, s) in decimal form
    Arguments must be hex strings
    """
    if curvename == "secp192r1":
        curve = ec.SECP192R1()
        q = 6277101735386680763835789423176059013767194773182842284081
    elif curvename == "secp224r1":
        curve = ec.SECP224R1()
        q = 26959946667150639794667015087019625940457807714424391721682722368061
    elif curvename == "secp256r1":
        curve = ec.SECP256R1()
        q = 115792089210356248762697446949407573529996955224135760342422259061068512044369
    elif curvename == "secp384r1":
        curve = ec.SECP384R1()
        q = 39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643
    elif curvename == "secp521r1":
        curve = ec.SECP521R1()
        q = 6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449
    elif curvename == "brainpoolP256r1":
        curve = ec.BrainpoolP256R1()
        q = 0xA9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7
    # elif curvename == "brainpoolP384r1":
    #     curve = ec.BrainpoolP384R1()
    # elif curvename == "brainpoolP512r1":
    #     curve = ec.BrainpoolP512R1()
    else:
        raise NotImplementedError("Unknown curve name : {}".format(curvename))

    d = int(d, 16)
    k = int(k, 16)
    h = int(digest[:q.bit_length()//4], 16)

    # W = k*G
    # r = Wx mod q
    r = ec.derive_private_key(k, curve, default_backend()).public_key().public_numbers().x

    # s = k⁻1(h + d*r) mod q
    ki = pow(k, q-2, q)  # because q is prime, we can calculate the inverse like this
    s = (ki*(h + d*r)) % q
    return r, s


def hmacTest(k, h, m, tlen):
    k = htos(k)
    m = htos(m)
    if h == "SHA1":
        h = hmac.new(k, m, sha1)
    elif h == "SHA224":
        h = hmac.new(k, m, sha224)
    elif h == "SHA256":
        h = hmac.new(k, m, sha256)
    elif h == "SHA384":
        h = hmac.new(k, m, sha384)
    elif h == "SHA512":
        h = hmac.new(k, m, sha512)
    else:
        raise NotImplementedError("Unknown hash function : {}".format(h))
    return h.hexdigest()[:tlen*2]


def rsaPKCS1v15Verify(n, e, hash, hash_name, sig):
    n = int(n, 16)
    e = int(e, 16)
    sig = htos(sig)
    hash = htos(hash)
    # Only SHA256 for the moment
    if hash_name != "SHA256":
        raise NotImplementedError("Unknown hash function : {}".format(hash_name))

    # PyCryptodom doesn't allow to verify signatures based on the hash only, so...
    from Crypto.Hash import SHA256

    class fakeObject(SHA256.SHA256Hash):
        def __init__(self, hash):
            self.hash = hash

        def digest(self):
            return self.hash

    h = fakeObject(hash)
    key = RSA.construct((n, e))
    verifier = PKCS1_v1_5.new(key)
    return verifier.verify(h, sig)
