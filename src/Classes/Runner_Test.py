# Author : Florian Picca <florian.picca@oppida.fr>
# Date : October 2019

from .Runner import Runner
from ..utils import *
import src.tests
from hashlib import pbkdf2_hmac
import sys


class Test_Runner(Runner):
    """
    This Runner acts as an interface with a cryptographic python module.
    It's only used to validate the test vectors and make sure they contain no error.
    """

    def compile(self):
        """
        This is a function from the super class that must be overridden.
        Check the Class Runner for complete documentation.
        """
        return True

    def checkEqual(self, a, b):
        """
        Checks if two values are the same.
        If one of the two is None, it means an error has occurred.
        """
        if a is None or b is None:
            return Result.ERR
        if a == b:
            return Result.OK
        return Result.KO

    def version(self):
        """
        This is a function from the super class that must be overridden.
        Check the Class Runner for complete documentation.
        """
        return "Python {}".format(sys.version.split(' \n')[0])

    def encrypt(self, v):
        """
        Handles vectors that are related to encryption.
        """
        if self.parser.alg == Alg.AES:
            if self.parser.mode == Mode.CBC:
                # AES CBC
                return self.checkEqual(src.tests.aesCBCencr(v.pt, v.key, v.iv), v.ct)
            elif self.parser.mode == Mode.ECB:
                # AES ECB
                return self.checkEqual(src.tests.aesECBencr(v.pt, v.key), v.ct)
            elif self.parser.mode == Mode.CTR:
                # AES CTR
                return self.checkEqual(src.tests.aesCTRencr(v.pt, v.key, v.iv), v.ct)
            elif self.parser.mode == Mode.CFB:
                # AES CFB
                return self.checkEqual(src.tests.aesCFBencr(v.pt, v.key, v.iv, v.segment_len), v.ct)
            elif self.parser.mode == Mode.OFB:
                # AES OFB
                return self.checkEqual(src.tests.aesOFBencr(v.pt, v.key, v.iv), v.ct)
            elif self.parser.mode == Mode.GCM:
                # AES GCM
                return self.checkEqual(src.tests.aesGCMEncr(v.pt, v.header, v.key, v.iv, len(v.tag)//2), (v.ct, v.tag))
        raise NotImplementedError()

    def decrypt(self, v):
        """
        Handles vectors that are related to decryption.
        """
        if self.parser.alg == Alg.AES:
            if self.parser.mode == Mode.CBC:
                # AES CBC
                return self.checkEqual(src.tests.aesCBCdecr(v.ct, v.key, v.iv), v.pt)
            elif self.parser.mode == Mode.ECB:
                # AES ECB
                return self.checkEqual(src.tests.aesECBdecr(v.ct, v.key), v.pt)
            elif self.parser.mode == Mode.CTR:
                # AES CTR
                return self.checkEqual(src.tests.aesCTRdecr(v.ct, v.key, v.iv), v.pt)
            elif self.parser.mode == Mode.CFB:
                # AES CFB
                return self.checkEqual(src.tests.aesCFBdecr(v.ct, v.key, v.iv, v.segment_len), v.pt)
            elif self.parser.mode == Mode.OFB:
                # AES OFB
                return self.checkEqual(src.tests.aesOFBdecr(v.ct, v.key, v.iv), v.pt)
            elif self.parser.mode == Mode.GCM:
                # AES GCM
                return self.checkEqual(src.tests.aesGCMDecr(v.ct, v.header, v.key, v.iv, v.tag), v.pt)
        raise NotImplementedError()

    def encryptMCT(self, v):
        """
        Handles vectors that are related to MCT encryption.
        """
        if self.parser.alg == Alg.AES:
            if self.parser.mode == Mode.CBC:
                # AES CBC
                return self.checkEqual(src.tests.aesCBCencrMCT(v.pt, v.key, v.iv), v.ct)
            elif self.parser.mode == Mode.ECB:
                # AES ECB
                return self.checkEqual(src.tests.aesECBencrMCT(v.pt, v.key), v.ct)
            elif self.parser.mode == Mode.CFB:
                # AES CFB
                return self.checkEqual(src.tests.aesCFBencrMCT(v.pt, v.key, v.iv, v.segment_len), v.ct)
            elif self.parser.mode == Mode.OFB:
                # AES OFB
                return self.checkEqual(src.tests.aesOFBencrMCT(v.pt, v.key, v.iv), v.ct)
        raise NotImplementedError()

    def decryptMCT(self, v):
        """
        Handles vectors that are related to MCT decryption.
        """
        if self.parser.alg == Alg.AES:
            if self.parser.mode == Mode.CBC:
                # AES CBC
                return self.checkEqual(src.tests.aesCBCdecrMCT(v.ct, v.key, v.iv), v.pt)
            elif self.parser.mode == Mode.ECB:
                # AES ECB
                return self.checkEqual(src.tests.aesECBdecrMCT(v.ct, v.key), v.pt)
            elif self.parser.mode == Mode.CFB:
                # AES CFB
                return self.checkEqual(src.tests.aesCFBdecrMCT(v.ct, v.key, v.iv, v.segment_len), v.pt)
            elif self.parser.mode == Mode.OFB:
                # AES OFB
                return self.checkEqual(src.tests.aesOFBdecrMCT(v.ct, v.key, v.iv), v.pt)
        raise NotImplementedError()

    def hash(self, v):
        """
        Handles vectors that are related to hashing.
        """
        if self.parser.alg == Alg.SHA1:
            return self.checkEqual(src.tests.sha1Hash(v.pt), v.digest)
        if self.parser.alg == Alg.SHA2:
            return self.checkEqual(src.tests.sha2Hash(v.pt, len(v.digest)*4), v.digest)
        if self.parser.alg == Alg.HMAC:
            return self.checkEqual(src.tests.hmacTest(v.key, v.hash_function, v.pt, len(v.digest)//2), v.digest)
        if self.parser.alg == Alg.PBKDF2:
            return self.checkEqual(pbkdf2_hmac(v.hash_function, htos(v.pt), htos(v.salt),
                                               v.iterations, len(v.digest)//2).hex(), v.digest)

    def hashMCT(self, v):
        """
        Handles vectors that are related to MCT hashing.
        """
        if self.parser.alg == Alg.SHA1:
            return self.checkEqual(src.tests.sha1HashMCT(v.pt), v.checkpoints)
        if self.parser.alg == Alg.SHA2:
            return self.checkEqual(src.tests.sha2HashMCT(v.pt, len(v.pt)*4), v.checkpoints)

    def exchange(self, v):
        """
        Handles vectors that are related to key exchanges.
        """
        if self.parser.alg == Alg.ECDH:
            return self.checkEqual(src.tests.ecdh(v.curve, v.da, v.xb, v.yb),
                                   (int(v.xa, 16), int(v.ya, 16), int(v.sk, 16)))
        elif self.parser.alg == Alg.DH:
            return self.checkEqual(src.tests.diffie_hellman(v.p, v.g, v.da, v.db, v.hash_function),
                                   (int(v.ya, 16), int(v.yb, 16), int(v.sk, 16), v.digest))
        else:
            raise NotImplementedError("Unknown alg : {}".format(self.parser.alg.name))

    def signAndverify(self, v):
        """
        Handles vectors that are related to signatures.
        """
        if self.parser.alg == Alg.ECDSA:
            r, s = src.tests.ecdsa(v.curve, v.digest, v.da, v.k)
            # Convert to number to handle possible missing 0's at the start of the hex strings
            return self.checkEqual((r, s), (int(v.r, 16), int(v.s, 16)))

    def verifyOnly(self, v):
        """
        Handles vectors that are related to signatures.
        """
        # RSA
        if self.parser.alg == Alg.RSASSA:
            res = src.tests.rsaPKCS1v15Verify(v.modulus, v.pb_exp, v.pt, v.hash_function, v.digest)
            if res:
                return Result.OK
            return Result.KO

    def handleVector(self, v):
        """
        This is a function from the super class that must be overridden.
        Check the Class Runner for complete documentation.
        """
        # MCT
        if self.parser.type == Type.MCT:
            if v.operation == Operation.ENCR:
                return self.encryptMCT(v)
            elif v.operation == Operation.DECR:
                return self.decryptMCT(v)
            elif v.operation == Operation.HASH:
                return self.hashMCT(v)
            else:
                raise NotImplementedError("Unknown operation : {}".format(v.operation.name))

        # anything else
        if v.operation == Operation.ENCR:
            return self.encrypt(v)
        elif v.operation == Operation.DECR:
            return self.decrypt(v)
        elif v.operation == Operation.HASH:
            return self.hash(v)
        elif v.operation == Operation.EXCH:
            return self.exchange(v)
        elif v.operation == Operation.SIGN:
            return self.signAndverify(v)
        elif v.operation == Operation.VERIFY:
            return self.verifyOnly(v)
        else:
            raise NotImplementedError("Unknown operation : {}".format(v.operation.name))
