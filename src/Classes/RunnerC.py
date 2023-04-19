# Author : Florian Picca <florian.picca@oppida.fr>
# Date : July 2019

from ..utils import *
from .Runner import Runner
from os.path import exists, realpath

# The error that the dialoger returns on stdout if a feature is not implemented.
NOT_IMPLEMENTED_ERROR = "not_implemented"


class RunnerC(Runner):
    """
    This Runner acts as an interface with any C-based cryptographic library that follows the template provided.
    """

    def __init__(self, parser, config):
        super().__init__(parser)
        # Name of the shared library
        self.library_name = config["libName"]
        # Path to the directory containing all the binaries
        self.binary_dir = config["binary_dir"]
        # Path to the shared library .so file
        self.currentLib_path = self.binary_dir + "/libs/currentLib"
        # Path to the Include/ directory used during compilation of the shared library
        self.currentInclude_path = self.binary_dir + "/libs/currentInclude"
        # Path to the source directory used during compilation of the shared library
        self.currentSource_path = self.binary_dir + "/libs/currentPath"
        # Path to the automatic installation script of the shared library
        self.installScript_path = self.binary_dir + "/install.py"
        # Path to the dialoger binary
        self.dialoger_path = self.binary_dir + "/dialoger.bin"

    def version(self):
        """
        This is a function from the super class that must be overridden.
        Check the Class Runner for complete documentation.
        """
        return self.dialog([Commands.VERSION.name])

    def compile(self):
        """
        This is a function from the super class that must be overridden.
        Check the Class Runner for complete documentation.

        Will recompile the C source files using the target library version (if supported) every time
        the version selection changes.
        """
        try:
            # Stores the full path to the previously compiled library, so we don't recompile if it hasn't changed
            previous = None
            if exists(self.currentLib_path):
                previous = realpath(self.currentLib_path)
            new = None
            if self.path is not None and not exists(self.path) and self.path.startswith("http"):
                # Specified a version using a URL
                # Download the library version and set the LD_PRELOAD to it
                pwarning("Installing {} library from source : {}".format(self.library_name, self.path))
                # Run the automatic install script
                runProc([self.installScript_path, self.path])
                # Set LD_PRELOAD path
                self.path = self.currentLib_path
                new = realpath(self.path)
            elif self.path is None or exists(self.path):
                # No version selection supported in the GUI
                runProc(["rm", "-f", self.currentLib_path, self.currentInclude_path, self.currentSource_path])
            else:
                perror("ldpreload is not a valid file or URL")
                return False
            # always compile if dialoger.bin is missing. This is the case when freshly pulled from GitHub
            if new != previous or not exists(self.dialoger_path):
                # Recompile Binaries to use the right version of the library
                runProc(["make", "-C", self.binary_dir, "clean"])
                runProc(["make", "-C", self.binary_dir])
                # dialoger.bin should exist now, otherwise something went wrong during compilation
            return exists(self.dialoger_path)
        except Exception as e:
            perror("Something went wrong during compilation")
            perror(e)
            return False

    def checkEqual(self, a, b):
        """
        Checks if two values are the same.
        If one of the two is empty, it means an error has occurred.
        """
        if a == NOT_IMPLEMENTED_ERROR or b == NOT_IMPLEMENTED_ERROR:
            # If the dialoger says a feature is not implemented,
            # consider the test as been skipped
            return Result.SKIP
        if a == '' or b == '':
            return Result.ERR
        if a == b:
            return Result.OK
        return Result.KO

    def dialog(self, cmd):
        """
        Send a command to the dialoger which will dispatch the request to the right function.

        :param cmd: A list an arguments to execute
        :return: str
        """
        # replace empty strings with "#"
        # The dialoger will treat them as empty strings, a ",," is not considered empty by the dialoger
        newCmd = []
        for e in cmd:
            if e == "":
                e = "#"
            newCmd.append(e)
        # Send CSV
        cmd = ",".join(newCmd).encode()
        self.dialoger.stdin.write(cmd + b'\n')
        self.dialoger.stdin.flush()
        res = []
        line = self.dialoger.stdout.readline().strip().decode().lower()
        # a ">" indicates the next input
        while line != '>':
            res.append(line)
            line = self.dialoger.stdout.readline().strip().decode().lower()
        # If there is multiple lines, reconstruct them
        return "\n".join(res)

    def encrypt(self, v):
        """
        Calls the code in blockcipher.c or gcm.c with the right arguments.
        This program is responsible for encrypting or decrypting with a block cipher and mode.
        For documentation on the arguments, check the source code of the program.
        """
        if self.parser.alg == Alg.AES:
            seglen = ''
            if v.segment_len is not None and v.segment_len != 128:
                seglen = v.segment_len
            # cipher names follow the OpenSSl syntax in lower case : aes-256-gcm, aes-128-cfb8, aes-192-cbc, ...
            ciphername = "AES-{}-{}{}".format(len(v.key) * 4, self.parser.mode.name, seglen).lower()
        else:
            raise NotImplementedError("Unknown algorithm : {}".format(self.parser.alg.name))

        # GCM mode is seperated. No MCT tests for this one
        if self.parser.mode == Mode.GCM:
            res = self.dialog([Commands.GCM.name, v.pt, v.key, v.iv, v.header, v.tag, ciphername, 'E'])
            # handle this case here because 2 values are expected
            if res == NOT_IMPLEMENTED_ERROR:
                return Result.SKIP
            ct, tag = res.split(",")
            return self.checkEqual((ct, tag), (v.ct, v.tag))

        # Other modes
        mct = ''
        if self.parser.type == Type.MCT:
            mct = 'MCT'
        ct = self.dialog([Commands.BLOCKCIPHER.name, v.pt, v.key, v.iv or '', ciphername, 'E', mct])
        return self.checkEqual(ct, v.ct)

    def decrypt(self, v):
        """
        Calls the code in blockcipher.c or gcm.c with the right arguments.
        This program is responsible for encrypting or decrypting with a block cipher and mode.
        For documentation on the arguments, check the source code of the program.
        """
        if self.parser.alg == Alg.AES:
            seglen = ''
            if v.segment_len is not None and v.segment_len != 128:
                seglen = v.segment_len
            # cipher names follow the OpenSSl syntax in lower case : aes-256-gcm, aes-128-cfb8, aes-192-cbc, ...
            ciphername = "AES-{}-{}{}".format(len(v.key) * 4, self.parser.mode.name, seglen).lower()
        else:
            raise NotImplementedError("Unknown algorithm : {}".format(self.parser.alg.name))

        # GCM mode is seperated. No MCT tests for this one
        if self.parser.mode == Mode.GCM:
            pt = self.dialog([Commands.GCM.name, v.ct, v.key, v.iv, v.header, v.tag, ciphername, 'D'])
            if pt == "fail":
                return Result.KO
            if pt == "good":
                return Result.OK
            return self.checkEqual(pt, v.pt)

        # Other modes
        mct = ''
        if self.parser.type == Type.MCT:
            mct = 'MCT'
        pt = self.dialog([Commands.BLOCKCIPHER.name, v.ct, v.key, v.iv or '', ciphername, 'D', mct])
        return self.checkEqual(pt, v.pt)

    def hash(self, v):
        """
        For normal hashing :
        Calls the code in hasher.c with the right arguments.
        This program is responsible for computing hashes.

        For HMAC :
        Calls the code in hmac.c with the right arguments.
        This program is responsible for computing HMAC tags.

        For PBKDF2 :
        Calls the code in pbkdf.c with the right arguments.
        This program is responsible for derivating keys using PBKDF2 with HMAC SHA1.

        For documentation on the arguments, check the source code of the program.
        """
        # HMAC
        if self.parser.alg == Alg.HMAC:
            h = self.dialog([Commands.HMAC.name, v.key, v.pt, v.hash_function])
            return self.checkEqual(h[:len(v.digest)], v.digest)

        # PBKDF2
        if self.parser.alg == Alg.PBKDF2:
            h = self.dialog([Commands.PBKDF.name, v.pt, v.salt, str(v.iterations),
                             str(len(v.digest)//2), v.hash_function])
            return self.checkEqual(h, v.digest)

        # SHA1, SHA2-X
        # hash names follow the format of OpenSSL : SHA1, SHA256, SHA384, ...
        elif self.parser.alg == Alg.SHA1:
            hashname = "SHA1"
        elif self.parser.alg == Alg.SHA2:
            if self.parser.type == Type.MCT:
                hashname = "SHA"+str(len(v.pt)*4)
            else:
                hashname = "SHA"+str(len(v.digest)*4)
        else:
            raise NotImplementedError("Unknown hash algorithm : {}".format(self.parser.alg))

        # MCT vectors produce more output
        if self.parser.type == Type.MCT:
            res = self.dialog([Commands.HASHER.name, v.pt, hashname, 'MCT'])
            # handle this case here because several values are expected
            if res == NOT_IMPLEMENTED_ERROR:
                return Result.SKIP
            # In case of MCT tests, all checkpoint values are returned and compared to the expected ones,
            # not just the last
            checkpoints = res.split("\n")
            return self.checkEqual(checkpoints, v.checkpoints)
        else:
            h = self.dialog([Commands.HASHER.name, v.pt, hashname, ''])
            return self.checkEqual(h, v.digest)

    def exchange(self, v):
        """
        Calls the code in ecdh.c or dh.c with the right arguments.
        This program is responsible for performing key exchanges.
        For documentation on the arguments, check the source code of the program.
        """
        # ECDH
        if self.parser.alg == Alg.ECDH:
            res = self.dialog([Commands.ECDH.name, v.curve, v.da, v.xb, v.yb])
            # handle this case here because 3 values are expected
            if res == NOT_IMPLEMENTED_ERROR:
                return Result.SKIP
            xa, ya, sk = res.split(" ")
            # Convert to number to handle possible missing 0's at the start of the hex strings
            return self.checkEqual((int(xa, 16), int(ya, 16), int(sk, 16)),
                                   (int(v.xa, 16), int(v.ya, 16), int(v.sk, 16)))

        # DH
        elif self.parser.alg == Alg.DH:
            # Without hashing as post-treatment
            if v.hash_function is None:
                res = self.dialog([Commands.DH.name, v.p, v.g, v.da, v.db, ''])
                # handle this case here because 2 values are expected
                if res == NOT_IMPLEMENTED_ERROR:
                    return Result.SKIP
                ya, yb, sk = res.split(" ")
                # Convert to number to handle possible missing 0's at the start of the hex strings
                return self.checkEqual((int(ya, 16), int(yb, 16), int(sk, 16)),
                                       (int(v.ya, 16), int(v.yb, 16), int(v.sk, 16)))

            # With hashing as post-treatment
            else:
                res = self.dialog([Commands.DH.name, v.p, v.g, v.da, v.db, v.hash_function])
                # handle this case here because 2 values are expected
                if res == NOT_IMPLEMENTED_ERROR:
                    return Result.SKIP
                ya, yb, sk, digest = res.split(" ")
                # Convert to number to handle possible missing 0's at the start of the hex strings
                return self.checkEqual((int(ya, 16), int(yb, 16), int(sk, 16), int(digest, 16)),
                                       (int(v.ya, 16), int(v.yb, 16), int(v.sk, 16), int(v.digest, 16)))

        else:
            raise NotImplementedError("Unknown alg : {}".format(self.parser.alg.name))

    def signAndverify(self, v):
        """
        Calls the code in ecdsa.c with the right arguments.
        This program is responsible for signing data only (for the moment).
        For documentation on the arguments, check the source code of the program.
        """
        # ECDSA
        if self.parser.alg == Alg.ECDSA:
            res = self.dialog([Commands.ECDSA.name, v.curve, v.digest, v.da, v.k])
            # handle this case here because 2 values are expected
            if res == NOT_IMPLEMENTED_ERROR:
                return Result.SKIP
            r, s = res.split(" ")
            # Convert to number to handle possible missing 0's at the start of the hex strings
            return self.checkEqual((int(r, 16), int(s, 16)), (int(v.r, 16), int(v.s, 16)))

    def verifyOnly(self, v):
        """
        Calls the code in rsa.c with the right arguments.
        This program is responsible for verifying signatures only (for the moment).
        For documentation on the arguments, check the source code of the program.
        """
        # RSA
        if self.parser.alg == Alg.RSASSA:
            res = self.dialog([Commands.RSA.name, v.modulus, v.pb_exp, v.priv_exp,
                               v.pt, v.digest, v.hash_function, v.padding, "V"])
            # handle this case here because we are not calling checkEqual
            if res == NOT_IMPLEMENTED_ERROR:
                return Result.SKIP
            if res == "fail":
                return Result.KO
            if res == "good":
                return Result.OK

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
        elif v.operation == Operation.VERIFY:
            return self.verifyOnly(v)
        else:
            raise NotImplementedError("Unknown operation : {}".format(v.operation.name))

    def initDialog(self):
        """
        This function starts the dialoger before running the tests vectors.
        """
        import subprocess
        fullcmd = [self.dialoger_path]
        env = None
        if self.path is not None:
            # Add all the preloaded libraries in the ENV if provided
            env = {"LD_PRELOAD": self.path}
        self.dialoger = subprocess.Popen(fullcmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=env)

    def closeDialog(self):
        """
        This function terminates the dialoger once all tests vectors have been run.
        """
        self.dialoger.stdin.write(Commands.QUIT.name.encode()+b"\n")
        self.dialoger.stdin.flush()
