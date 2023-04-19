# Author : Florian Picca <florian.picca@oppida.fr>
# Date : October 2019

from ..utils import *


class Runner:
    """
    Top level Class implementing the handling of test vector results.
    Subclasses must override the function handleVector().

    Take a look at the Class Test_Runner or OpenSSL_Runner for an example on how you must create your subclasses.
    """

    def __init__(self, parser):
        # The parser from which to read the vectors.
        self.parser = parser
        # Indicates that all test vectors produced expected results.
        self.success = True
        # How many test vectors were skipped.
        self.skipped = 0
        # Specify a path to the library if the version to test is different then the one installed.
        self.path = None
        # The Java dialoger handle
        self.dialoger = None

    def handleVector(self, v):
        """
        Function to implement in subclasses that will call the right program with the right arguments in order to handle
        a given test vector for the target library.
        Check the documentation of the class Vector for a description of its attributes.

        :param v: The test vector to handle.
        :type v: Vector
        :return: The result of the test.
        :rtype: Result
        """
        raise NotImplementedError("You have to override this function in your subclasses.")

    def _check(self, res, v):
        """
        Checks if the result of a test is the expected outcome.
        If not, logs the error.

        :param res: The result from the run.
        :type res: Result
        :param v: The vector that was tested.
        :type v: Vector
        """
        if res is None:
            raise NotImplementedError("A value of type <Result> was expected.")
        if res != Result.SKIP and res != v.expected:
            perror("Failed test ! Obtained : {}".format(res.name))
            perror("Details of the test vector :")
            perror(v)
            self.success = False
        if res == Result.SKIP:
            self.skipped += 1

    def compile(self):
        """
        This function is called at the beginning of the function run().
        It should perform all the compilation steps, if needed.
        If you don't need to perform compilation steps, simply return True.

        :return: The compilation's success.
        :rtype: bool
        """
        raise NotImplementedError("You have to override this function in your subclasses.")

    def version(self):
        """
        This function is called by the function run() to print the current version of the library tested.

        :return: The library's complete version string.
        :rtype: str
        """
        raise NotImplementedError("You have to override this function in your subclasses.")

    def initDialog(self):
        """
        Instanciate the Java dialoger, only used for Java libraries.
        This is used to prevent loading the JVM for every vector, which is extremely slow.
        """
        pass

    def closeDialog(self):
        """
        Close the Java dialoger, only used for Java libraries.
        This is used to prevent loading the JVM for every vector, which is extremely slow.
        """
        pass

    def run(self, silent=False, window=None):
        """
        Runs all the test vectors found in the parser and checks their results against the expected outcome.

        :param silent: Only logs failed tests.
        :type silent: bool
        :param window: The window to which the progressbar is attached.
        :type window: RunTestsWindow
        """
        if len(self.parser.vectors) == 0:
            pwarning(f"No test vectors for {self.parser.alg.name}")
            return
        if not self.compile():
            perror("Error during compilation")
            return

        self.success = True
        self.skipped = 0
        vectors = self.parser.vectors

        self.initDialog()

        if not silent:
            print("Running {} tests for {}".format(len(self.parser.vectors), self.parser.alg.name))
            if self.parser.mode is not None:
                print("Mode : {}".format(self.parser.mode.name))
            if self.parser.type is not None:
                print("Type : {}".format(self.parser.type.name))
            print("Version : {}".format(self.version()))

        if window is not None:
            window.resetInternalProgressBar(len(vectors))

        for v in vectors:
            self._check(self.handleVector(v), v)
            if window is not None:
                window.incrementInternalProgressBar()

        self.closeDialog()

        if self.success and not silent:
            psuccess("All tests OK")
        if self.skipped > 0 and not silent:
            pwarning(f"{self.skipped} test(s) were intentionally skipped")
