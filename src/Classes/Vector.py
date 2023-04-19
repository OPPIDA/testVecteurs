# Author : Florian Picca <florian.picca@oppida.fr>
# Date : October 2019

from ..utils import *


class Vector:
    """
    Generic class representing a single vector.
    """

    def __init__(self, data):
        """
        Initializes a Vector instance depending on data contained in a dictionary.
        If a field is not contained in data, it will be set to None.

        :param data: The vector's data
        :type data: dict
        """
        # -- Required attributes -- (They must exist for every single vector)

        # The operation to perform with this test vector (Check documentation of Operation)
        self.operation = strToEnum(Operation, data.get('operation'))
        # The expected outcome of this test vector (Check documentation of Result)
        self.expected = strToEnum(Result, data.get('expected'))

        # -- General Attributes --

        # Represents a key : cipher's key, HMAC's key, ...
        self.key = data.get('key')
        # Represents a plaintext or a message to encrypt/hash
        self.pt = data.get('pt')
        # Represents the result of a HASH operation : HMAC, PBKDF2, SHA1, SHA2, ...
        self.digest = data.get('digest')
        # The hash function used internally by the algorithm : DH, PBKDF2, HMAC
        self.hash_function = data.get('hash_function')

        # -- Block Cipher --

        # The intialization vector
        self.iv = data.get('iv')
        # The ciphertext
        self.ct = data.get('ct')
        # CFB mode segment size
        self.segment_len = data.get('seglen')
        # AEAD modes header/additionnal data
        self.header = data.get('header')
        # AEAD modes header/additionnal data
        self.tag = data.get('tag')

        # -- Hash Function --

        # MCT intermediate values for hash functions
        self.checkpoints = data.get('checkpoints')

        # -- ECDH --

        # x coordinate of A's public point
        self.xa = data.get('xa')
        # x coordinate of B's public point
        self.xb = data.get('xb')
        # y coordinate of A's public point
        self.ya = data.get('ya')
        # x coordinate of B's public point
        self.yb = data.get('yb')
        # A's private value
        self.da = data.get('da')
        # shared key between A and B
        self.sk = data.get('sk')
        # The curve's identifier
        self.curve = data.get('curve')

        # -- DH --

        # The prime of the finite field
        self.p = data.get('p')
        # The generator of the finite field
        self.g = data.get('g')
        # B's private value
        self.db = data.get('db')

        # -- PBKDF2 --

        # The number of iterations to use for key derivation
        self.iterations = data.get('iterations')
        # The salt used in the process
        self.salt = data.get('salt')

        # -- ECDSA --

        # the private key d is stored in self.da like for ECDH
        # the message digest is stored in self.digest
        # the curve is stored in self.curve like for ECDH
        # The value r of the signature
        self.r = data.get('r')
        # The value s of the signature
        self.s = data.get('s')
        # The value k that generated r
        self.k = data.get('k')

        # -- RSA --

        # The RSA modulus n
        self.modulus = data.get('modulus')
        # The RSA public exponent e
        self.pb_exp = data.get('pb_exp')
        # The RSA private exponent d
        self.priv_exp = data.get('priv_exp')
        # The RSA padding scheme used
        self.padding = data.get('padding')

        # Add here

    def __str__(self):
        desc = ""
        if self.operation is not None:
            desc += "operation = {}\n".format(self.operation.name)
        if self.expected is not None:
            desc += "expected = {}\n".format(self.expected.name)
        if self.key is not None:
            desc += "key = {}\n".format(self.key)
        if self.iv is not None:
            desc += "iv = {}\n".format(self.iv)
        if self.pt is not None:
            desc += "plaintext = {}\n".format(self.pt)
        if self.ct is not None:
            desc += "ciphertext = {}\n".format(self.ct)
        if self.segment_len is not None:
            desc += "seglen = {}\n".format(self.segment_len)
        if self.digest is not None:
            desc += "digest = {}\n".format(self.digest)
        # Don't print self.checkpoints
        if self.xa is not None:
            desc += "xa = {}\n".format(self.xa)
        if self.xb is not None:
            desc += "xb = {}\n".format(self.xb)
        if self.ya is not None:
            desc += "ya = {}\n".format(self.ya)
        if self.yb is not None:
            desc += "yb = {}\n".format(self.yb)
        if self.da is not None:
            desc += "da = {}\n".format(self.da)
        if self.sk is not None:
            desc += "sk = {}\n".format(self.sk)
        if self.curve is not None:
            desc += "curve = {}\n".format(self.curve)
        if self.p is not None:
            desc += "p = {}\n".format(self.p)
        if self.g is not None:
            desc += "g = {}\n".format(self.g)
        if self.db is not None:
            desc += "db = {}\n".format(self.db)
        if self.hash_function is not None:
            desc += "hash_function = {}\n".format(self.hash_function)
        if self.iterations is not None:
            desc += "iterations = {}\n".format(self.iterations)
        if self.salt is not None:
            desc += "salt = {}\n".format(self.salt)
        if self.header is not None:
            desc += "header = {}\n".format(self.header)
        if self.tag is not None:
            desc += "tag = {}\n".format(self.tag)
        if self.r is not None:
            desc += "r = {}\n".format(self.r)
        if self.s is not None:
            desc += "s = {}\n".format(self.s)
        if self.k is not None:
            desc += "k = {}\n".format(self.k)
        if self.modulus is not None:
            desc += "modulus = {}\n".format(self.modulus)
        if self.pb_exp is not None:
            desc += "pb_exp = {}\n".format(self.pb_exp)
        if self.priv_exp is not None:
            desc += "priv_exp = {}\n".format(self.priv_exp)
        if self.padding is not None:
            desc += "padding = {}\n".format(self.padding)
        return desc
