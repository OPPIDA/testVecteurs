# Author : Florian Picca <florian.picca@oppida.fr>
# Date : December 2019

from .Runner import Runner
from ..utils import *
from os.path import exists, realpath


class BouncyCastle_Runner(Runner):
    """
    This Runner acts as an interface with the BouncyCastle cryptographic library.
    """

    def version(self):
        """
        This is a function from the super class that must be overridden.
        Check the Class Runner for complete documentation.
        """
        return "BouncyCastle {}".format(self.dialog([Commands.VERSION.name]))

    def compile(self):
        """
        This is a function from the super class that must be overridden.
        Check the Class Runner for complete documentation.
        """
        try:
            # Stores the full path to the previously compiled library, so we don't recompile if it hasn't changed
            previous = None
            if exists("bin/BouncyCastle/libs/currentLib"):
                previous = realpath("bin/BouncyCastle/libs/currentLib")
            new = None
            if self.path is not None and not exists(self.path) and self.path.startswith("http"):
                # Download the OpenSSL version and set the LD_PRELOAD to it
                pwarning("Installing BouncyCastle library from JAR : {}".format(self.path))
                runProc(["bin/BouncyCastle/install.py", self.path])
                self.path = "bin/BouncyCastle/libs/currentLib"
                new = realpath(self.path)
            elif self.path is None or exists(self.path):
                runProc(["rm", "-f", "bin/BouncyCastle/libs/currentLib"])
            else:
                perror("ldpreload is not a valid file or URL")
                return False
            # always compile if Version.class is missing. This is the case when freshly pulled from GitHub
            if new != previous or not exists("bin/BouncyCastle/Version.class"):
                # Recompile Binaries to use the right version of OpenSSL
                runProc(["make", "-C", "bin/BouncyCastle/", "clean"])
                runProc(["make", "-C", "bin/BouncyCastle/"])
                # find a way to check for compilation success
            return True
        except:
            perror("Something went wrong during compilation")
            return False

    def checkEqual(self, a, b):
        """
        Checks if two values are the same.
        If one of the two is empty, it means an error has occurred.
        """
        if a == '' or b == '':
            return Result.ERR
        if a == b:
            return Result.OK
        return Result.KO

    def dialog(self, cmd):
        """
        Send a command to the Java dialoger which will dispatch the request to the right Class.
        This drastically improves the execution speed of the test vectors as the JVM is not loaded every time.
        Before, it took 3 hours to run the AES GCM vectors, now it takes 2 seconds !

        :param cmd: A list an arguments to execute
        :return: str
        """
        # replace empty strings with "#"
        newCmd = []
        for e in cmd:
            if e == "":
                e = "#"
            newCmd.append(e)

        cmd = ",".join(newCmd).encode()
        self.dialoger.stdin.write(cmd + b'\n')
        self.dialoger.stdin.flush()
        res = []
        line = self.dialoger.stdout.readline().strip().decode().lower()
        while line != '>':
            res.append(line)
            line = self.dialoger.stdout.readline().strip().decode().lower()
        return "\n".join(res)

    def encrypt(self, v):
        """
        Calls the program bin/BouncyCastle/Blockcipher.class with the right arguments.
        This program is responsible for encrypting or decrypting with a block cipher and mode using OpenSSL.
        For documentation on the arguments, check the source code of the program.
        """

        if self.parser.alg == Alg.AES:
            seglen = ''
            if v.segment_len is not None and v.segment_len != 128:
                seglen = v.segment_len
            ciphername = "AES-{}-{}{}".format(len(v.key) * 4, self.parser.mode.name, seglen)
        else:
            raise NotImplementedError("Unknown algorithm : {}".format(self.parser.alg.name))

        if self.parser.mode == Mode.GCM:
            cttag = self.dialog([Commands.GCM.name, v.pt, v.key, v.iv, v.header, v.tag, 'E'])
            ct = cttag[:-len(v.tag)]
            tag = cttag[-len(v.tag):]
            return self.checkEqual((ct, tag), (v.ct, v.tag))
        if self.parser.type == Type.MCT:
            ct = self.dialog([Commands.BLOCKCIPHER.name, v.pt, v.key, v.iv or '', ciphername, 'E', 'MCT'])
            return self.checkEqual(ct, v.ct)
        else:
            ct = self.dialog([Commands.BLOCKCIPHER.name, v.pt, v.key, v.iv or '', ciphername, 'E', ''])
            return self.checkEqual(ct, v.ct)

    def decrypt(self, v):
        """
        Calls the program bin/BouncyCastle/Blockcipher.bin with the right arguments.
        This program is responsible for encrypting or decrypting with a block cipher and mode using OpenSSL.
        For documentation on the arguments, check the source code of the program.
        """

        if self.parser.alg == Alg.AES:
            seglen = ''
            if v.segment_len is not None and v.segment_len != 128:
                seglen = v.segment_len
            ciphername = "AES-{}-{}{}".format(len(v.key) * 4, self.parser.mode.name, seglen)
        else:
            raise NotImplementedError("Unknown algorithm : {}".format(self.parser.alg.name))

        if self.parser.mode == Mode.GCM:
            pt = self.dialog([Commands.GCM.name, v.ct, v.key, v.iv, v.header, v.tag, 'D'])
            if pt == "good":
                return Result.OK
            if pt == "fail":
                return Result.KO
            return self.checkEqual(pt, v.pt)
        if self.parser.type == Type.MCT:
            pt = self.dialog([Commands.BLOCKCIPHER.name, v.ct, v.key, v.iv or '', ciphername, 'D', 'MCT'])
            return self.checkEqual(pt, v.pt)
        else:
            pt = self.dialog([Commands.BLOCKCIPHER.name, v.ct, v.key, v.iv or '', ciphername, 'D', ''])
            return self.checkEqual(pt, v.pt)

    def hash(self, v):
        """
        For normal hashing :
        Calls the program bin/BouncyCastle/Hasher.class with the right arguments.
        This program is responsible for computing hashes using OpenSSL.

        For HMAC :
        Calls the program bin/BouncyCastle/HMAC.class with the right arguments.
        This program is responsible for computing HMAC tags using OpenSSL.

        For PBKDF2 :
        Calls the program bin/BouncyCastle/PBKDF.class with the right arguments.
        This program is responsible for derivating keys using PBKDF2 with HMAC SHA1, using OpenSSL.

        For documentation on the arguments, check the source code of the program.
        """
        if self.parser.alg == Alg.HMAC:
            h = self.dialog([Commands.HMAC.name, v.key, v.pt, v.hash_function])
            return self.checkEqual(h[:len(v.digest)], v.digest)
        if self.parser.alg == Alg.PBKDF2:
            h = self.dialog([Commands.PBKDF.name, v.pt, v.salt, str(v.iterations),
                             str(len(v.digest)//2), v.hash_function])
            return self.checkEqual(h, v.digest)
        elif self.parser.alg == Alg.SHA1:
            hashname = "SHA1"
        elif self.parser.alg == Alg.SHA2:
            if self.parser.type == Type.MCT:
                hashname = "SHA"+str(len(v.pt)*4)
            else:
                hashname = "SHA"+str(len(v.digest)*4)
        else:
            raise NotImplementedError("Unknown hash algorithm : {}".format(self.parser.alg))
        # hashname must follow a special format for OpenSSL, see bin/OpenSSL/hasher.c

        if self.parser.type == Type.MCT:
            # In case of MCT tests, all checkpoint values are returned and compared to the expected one,
            # not just the last
            checkpoints = self.dialog([Commands.HASHER.name, v.pt, hashname, 'MCT']).split("\n")
            return self.checkEqual(checkpoints, v.checkpoints)
        else:
            h = self.dialog([Commands.HASHER.name, v.pt, hashname, ''])
            return self.checkEqual(h, v.digest)

    def exchange(self, v):
        """
        Handles vectors that are related to key exchanges.
        """

        if self.parser.alg == Alg.ECDH:
            xa, ya, sk = self.dialog([Commands.ECDH.name, v.curve, v.da, v.xb, v.yb]).split("\n")
            # Convert to number to handle possible missing 0's at the start of the hex strings
            return self.checkEqual((int(xa, 16), int(ya, 16), int(sk, 16)),
                                   (int(v.xa, 16), int(v.ya, 16), int(v.sk, 16)))

        elif self.parser.alg == Alg.DH:
            if v.hash_function is None:
                ya, yb, sk = self.dialog([Commands.DH.name, v.p, v.g, v.da, v.db, '']).split("\n")
                # Convert to number to handle possible missing 0's at the start of the hex strings
                return self.checkEqual((int(ya, 16), int(yb, 16), int(sk, 16)),
                                       (int(v.ya, 16), int(v.yb, 16), int(v.sk, 16)))
            else:
                ya, yb, sk, digest = self.dialog([Commands.DH.name, v.p, v.g, v.da, v.db, v.hash_function]).split("\n")
                # Convert to number to handle possible missing 0's at the start of the hex strings
                return self.checkEqual((int(ya, 16), int(yb, 16), int(sk, 16), int(digest, 16)),
                                       (int(v.ya, 16), int(v.yb, 16), int(v.sk, 16), int(v.digest, 16)))

        else:
            raise NotImplementedError("Unknown alg : {}".format(self.parser.alg.name))

    def signAndverify(self, v):
        """
        Handles vectors that are related to signatures.
        """
        if self.parser.alg == Alg.ECDSA:
            # r, s = self.execute(["bin/OpenSSL/ecdsa.bin", v.curve, v.digest, v.da, v.k]).split(" ")
            # Convert to number to handle possible missing 0's at the start of the hex strings
            # return self.checkEqual((int(r, 16), int(s, 16)), (int(v.r, 16), int(v.s, 16)))
            return Result.SKIP

    def handleVector(self, v):
        """
        This is a function from the super class that must be overridden.
        Check the Class Runner for complete documentation.
        """
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
        else:
            raise NotImplementedError("Unknown operation : {}".format(v.operation.name))

    def initDialog(self):
        import subprocess
        fullcmd = ["java", "-cp"]
        cp = "bin/BouncyCastle"
        if self.path is not None:
            cp += ":"
            cp += self.path
        fullcmd += [cp, "Dialoger"]
        self.dialoger = subprocess.Popen(fullcmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    def closeDialog(self):
        self.dialoger.stdin.write(Commands.QUIT.name.encode()+b"\n")
        self.dialoger.stdin.flush()
