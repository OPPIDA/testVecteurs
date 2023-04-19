# Author : Florian Picca <florian.picca@oppida.fr>
# Date : October 2019

from .utils import *
from .Classes.Parser import Parser
from .Classes.Runner_BouncyCastle import BouncyCastle_Runner
from .Classes.Runner_Test import Test_Runner
from .Classes.RunnerC import RunnerC


def runTests(lib, alg, type=None, mode=None, ldpreload=None, silent=False, window=None):
    """
    Runs the test vectors corresponding to a specific combination of algorithm, type of vector and mode of operation
    for a specific target library.

    :param lib: The target library to test.
    :type lib: Enum
    :param alg: The cryptographic algorithm to use.
    :type alg: Enum
    :param type: The type of test vectors to use.
    :type type: Enum
    :param mode: The mode of operation to use for block ciphers.
    :type mode: Enum
    :param ldpreload: The path to the library to preload.
    :type ldpreload: str
    :param silent: Print logs ?
    :type silent: bool
    :param window: The window used to display progress
    :type window: RunTestsWindow
    """
    parser = Parser(alg, type=type, mode=mode, silent=silent)
    if lib == Lib.BouncyCastle:
        runner = BouncyCastle_Runner(parser)
    elif lib == Lib.Test:
        runner = Test_Runner(parser)
    # Automatically load them from the runners.json file
    else:
        conf = RunnerConfs.get(lib.name)
        if conf is None:
            # Should never happen because choices for lib are limited by argparse
            raise NotImplementedError("Unknown library : {}".format(lib))
        if conf["type"] == "C":
            runner = RunnerC(parser, conf)
        else:
            raise NotImplementedError("Unknown runner type : {}".format(conf["type"]))
    # Specify the libraries to preload
    runner.path = ldpreload
    # Launch tests
    runner.run(silent=silent, window=window)
