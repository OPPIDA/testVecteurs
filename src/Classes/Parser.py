# Author : Florian Picca <florian.picca@oppida.fr>
# Date : October 2019

import os
from ..utils import *
from .Vector import Vector


class Parser:
    """
    this class is responsible for reading test vector files and loading the test vectors to be tested.
    """

    def __init__(self, alg, type=None, mode=None, silent=False):
        self.alg = alg
        # alg can't be None otherwise this means we haven't implemented the algorithm yet.
        # This should never happen because user inputs are restricted
        if self.alg is None:
            raise NotImplementedError("Unknown algorithm : {}".format(alg))
        self.type = type
        self.mode = mode
        self.silent = silent
        self.vectors = []
        self._loadVectors()

    def _validComb(self):
        """
        Indicates if a combination of algorithm, type of test vector and mode of operation is valid.
        Some combinations don't exist and thus don't contain any vector.
        for example :
            - SHA1 in CBC mode doesn't make sense, so it should return None.
            - SHA1 and SHA2 don't have MMT type vectors, so it should return None.
        """
        if self.alg == Alg.AES:
            if self.mode is None or self.type is None:
                # AES must use a mode and a type
                return False
            if self.mode == Mode.CTR and self.type != Type.KAT:
                # AES CTR only has KAT
                return False
            if self.mode == Mode.GCM and self.type != Type.MMT:
                # AES GCM only has MMT
                return False
        if self.alg == Alg.SHA1 or self.alg == Alg.SHA2:
            if self.mode is not None or self.type is Type.MMT or self.type is None:
                # SHA1 and SHA2 only have KAT and MCT and no modes
                return False
        if self.alg == Alg.ECDH or self.alg == Alg.DH or self.alg == Alg.PBKDF2 or \
                self.alg == Alg.RSASSA or self.alg == Alg.RSAES:
            if self.mode is not None or self.type is not None:
                # ECDH, DH, PBKDF2, RSASSA, RSAES don't have modes or type
                return False
        if self.alg == Alg.HMAC:
            if self.mode is not None or self.type is not Type.MMT:
                # HMAC only has MMT vectors
                return False
        # By default, return True so files are still searched
        return True

    def _loadVectors(self):
        """
        Reads all files in the vector directory and loads all the vectors that correspond to the parser's criteria.
        """
        if not self._validComb():
            # If we know that a specific combination doesn't exist, don't even search
            if not self.silent:
                a = None
                t = None
                m = None
                if self.alg is not None:
                    a = self.alg.name
                if self.type is not None:
                    t = self.type.name
                if self.mode is not None:
                    m = self.mode.name
                pwarning("No test vectors of type {} for algorithm {} with mode {}. Skipping...".format(t, a, m))
            return

        VECTOR_DIR = "vecteurs/"
        # only .json files are test vectors
        files = [x for x in os.listdir(VECTOR_DIR) if x.endswith(".json")]
        for name in files:
            data = json.load(open(VECTOR_DIR+name))
            # must be same alg, same type and same mode
            if strToEnum(Alg, data['alg']) == self.alg and \
                    strToEnum(Type, data['type']) == self.type and \
                    strToEnum(Mode, data['mode']) == self.mode:
                for vdata in data['vectors']:
                    # Construct the vector and append it to the internal list of vectors to test
                    v = Vector(vdata)
                    self.vectors.append(v)
