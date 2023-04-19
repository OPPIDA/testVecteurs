from ..guiUtils import *
from ...utils import *
from ...main import runTests

# A description of every selectable option
DESC = {
    "-libselect-": {
        "Test": """A collection of python modules used to verify the correctness of the test vectors.
This is only used during the development process of this tool.""",
        "BouncyCastle": """The BouncyCastle cryptographic library, written in Java.
This tool is not compatible with all the BC versions available.
When choosing a provider from the list, always get the most recent JDK (>= 15, if possible)."""
    },

    "-typeselect-": {
        "All": """All the available types""",
        "KAT": """KAT stands for Known Answer Test.
In case of a block cipher, the test vectors are composed of a single block of input data.""",
        "MMT": """MMT stands for Multi-block Message Test.
The test vectors are composed of multiple blocks of input data.""",
        "MCT": """MCT stands for Monte Carlo Test.
In case of a block cipher, the test vectors are composed of a single block of input data.
The output is fed back into the algorithm as a new input.
This process is repeated 1 000 times."""
    },

    "-algselect-": {
        "AES": """The AES algorithm.
Encryption and decryption for every key size is tested (128, 192, 256).
The test vectors come from the NIST.""",
        "SHA1": """The SHA1 algorithm.
The only hash size is tested (160).
The test vectors come from the NIST.""",
        "SHA2": """The SHA2 algorithm.
Every hash sizes are tested (224, 256, 384, 512).
The test vectors come from the NIST.""",
        "HMAC": """The HMAC algorithm.
Every combination with the following hash functions are tested :
 - SHA-1
 - All functions of SHA-2 (224, 256, 384, 512)
 The test vectors come from the NIST.""",
        "ECDH": """The ECDH key exchange algorithm.
The following curves are tested :
 - secp192r1
 - secp224r1
 - secp256r1
 - secp384r1
 - secp521r1
 - brainpoolP256r1
 - brainpoolP384r1
 - brainpoolP512r1
The test vectors come from the NIST and the various RFC.
IPSEC_DR test vectors are applied on brainpoolP256r1 and secp256r1.""",
        "DH": """The DH key exchange algorithm.
The tests cover the case when the secret is raw or when it's hashed using SHA2-256.
Other hash functions are supported by this tool for the post-treatment but no test vectors are provided for them.
The test vectors come from the NIST.""",
        "PBKDF2": """The PBKDF2 algorithm.
The test vectors come from RFC 6070.
The hash function used is SHA-1.""",
        "ECDSA": """The ECDSA signature algorithm
The following curves are tested :
 - secp192r1
 - secp224r1
 - secp256r1
 - secp384r1
 - secp521r1
The test vectors come from the NIST.
IPSEC_DR test vectors are applied on brainpoolP256r1 and secp256r1.""",
        "RSASSA": """The RSA Signature Scheme with Appendix
The following padding schemes are tested:
 - PKCS1-v1.5
 - PSS (verification only) (todo)
The test vectors come from Oppida.""",
        "RSAES": """The RSA Encryption Scheme
The following padding schemes are tested (decryption only):
 - PKCS1-v1.5(todo)
 - OAEP (todo)
 - None (todo)
The test vectors come from Oppida."""
    },

    "-modeselect-": {
        "All": """All the available modes""",
        "ECB": """The ECB mode.
This mode doesn't use an IV.""",
        "CBC": """The CBC mode.
This mode uses an IV.""",
        "CTR": """The CTR mode.
This mode uses a counter instead of an IV.
There are only KAT test vectors for this mode.""",
        "OFB": """The OFB mode.
This mode uses an IV.""",
        "CFB": """The CFB mode.
This mode uses an IV and a segment length.
The following segment lengths are tested :
 - 8 bits
 - 128 bits""",
        "GCM": """The GCM mode.
This mode uses a counter, a tag and additional data.
There are only MMT tests vectors for this mode."""
    }
}


class RunTestsWindow:

    def __init__(self):
        char_width = 7  # default font size
        window_width = 133 * char_width
        combo_width = 25
        txt_width = combo_width + 2
        space_width = (window_width//char_width - txt_width * 4)//5
        three_cols = txt_width*3 + space_width*2
        four_cols = txt_width*4 + space_width*3

        layout = [
            [psg.VPush()],
            horizontalCenter([
                psg.Text("Library :", size=txt_width),
                psg.Text("Algorithm :", size=txt_width),
                psg.Text("Test type :", size=txt_width, key="-typelabel-"),
                psg.Text("Mode :", size=txt_width, key="-modelabel-")
            ]),
            horizontalCenter([
                psg.Combo([], readonly=True, size=combo_width, key="-libselect-", enable_events=True),
                psg.Combo([], readonly=True, size=combo_width, key="-algselect-", enable_events=True),
                toggleableCombo([], readonly=True, size=combo_width, key="-typeselect-", enable_events=True),
                toggleableCombo([], readonly=True, size=combo_width, key="-modeselect-", enable_events=True)
            ]),
            horizontalCenter([
                psg.Text("", size=txt_width, key="-versionlabel-"),
                psg.Text("Description :", size=three_cols)
            ]),
            horizontalCenter([
                psg.Column([[psg.Combo([], readonly=True, size=combo_width, key="-versionselect-", enable_events=True)]
                            ], vertical_alignment="top"),
                psg.Multiline("", size=(three_cols, 10), disabled=True, no_scrollbar=True, key="-desc-", border_width=0)
            ]),
            [psg.Push(), psg.Button("Run", button_color="green3"), psg.Button("Clear logs"), psg.Push()],
            horizontalCenter([psg.pin(psg.ProgressBar(0, size_px=(four_cols*char_width, 3), key="-pbar-",
                                                      bar_color=("green3", "")))]),
            horizontalCenter([psg.pin(psg.ProgressBar(0, size_px=(four_cols * char_width, 3), key="-pbar2-"))]),
            horizontalCenter([psg.Text("Logs :", size=four_cols)]),
            horizontalCenter([psg.Multiline(size=(four_cols, 20), reroute_cprint=True, reroute_stdout=True,
                                            disabled=True, no_scrollbar=True, autoscroll=True, key="-log-")]),
            [psg.VPush()],
        ]
        self.window = psg.Window(title="TestVecteur", layout=layout, size=(window_width, 650), finalize=True)

        # initial state
        self.window["-desc-"].update(background_color=psg.theme_background_color())
        self.window["-typelabel-"].update(value="Test type :")
        self.window["-modelabel-"].update(value="Mode :")
        select = self.window["-versionselect-"]
        select.update(values=[], visible=False)
        self.window["-versionlabel-"].update(value="")
        self.window["-desc-"].update(value="Click on an element to show a description.")
        self.window["-pbar-"].update(visible=False)
        self.window["-pbar2-"].update(visible=False)

        self.populateLibs()
        self.populateAlgs()
        self.populateMode()
        self.populateType()

        # selected values
        self.selected_version = None

    def resetInternalProgressBar(self, total):
        pbar = self.window["-pbar2-"]
        self.pbar2_count = 0
        self.pbar2_updateCount = 0
        self.pbar2_total = total
        pbar.update(max=total, current_count=self.pbar2_count)
        self.window.refresh()

    def incrementInternalProgressBar(self):
        self.pbar2_count += 1
        self.pbar2_updateCount += 1
        # update every 20th of total count
        # updating is very costly in perf
        if self.pbar2_updateCount >= self.pbar2_total // 20:
            self.pbar2_updateCount = 0
            pbar = self.window["-pbar2-"]
            pbar.update(current_count=self.pbar2_count)
            self.window.refresh()

    def handleEvents(self, event, value):

        if type(self.window[event]) == psg.Combo:
            self.setDescription(event, value)

        if event == "-libselect-":
            self.selected_lib = value[event]
            self.libChanged(value[event])

        if event == "-algselect-":
            self.selected_alg = value[event]
            self.algChanged(value[event])

        if event == "-typeselect-":
            self.selected_type = value[event]

        if event == "-modeselect-":
            self.selected_mode = value[event]

        if event == "-versionselect-":
            self.selected_version = value[event]

        if event == "Run":
            self.run()

        if event == "Clear logs":
            self.window["-log-"].update("")

    def populateLibs(self):
        """
        Dynamically add libraries to the Combo item.
        """
        libselect = self.window["-libselect-"]
        values = []
        for libs in Lib:
            values.append(libs.name)
        values.append("Add new...")
        libselect.update(values=values, value=values[0])
        self.selected_lib = values[0]

    def populateAlgs(self):
        """
        Dynamically add algorithms to the Combo item.
        """
        algselect = self.window["-algselect-"]
        values = []
        for algs in Alg:
            values.append(algs.name)
        algselect.update(values=values, value=values[0])
        self.selected_alg = values[0]

    def populateMode(self):
        """
        Dynamically add modes to the Combo item.
        """
        algselect = self.window["-modeselect-"]
        values = ["All"]
        for algs in Mode:
            values.append(algs.name)
        algselect.update(values=values, value=values[0])
        self.selected_mode = values[0]

    def populateType(self, excepted=[]):
        """
        Dynamically add test types to the Combo item. Some types can be explicitly excluded.
        """
        algselect = self.window["-typeselect-"]
        values = ["All"]
        for algs in Type:
            if algs.name in excepted:
                continue
            values.append(algs.name)
        algselect.update(values=values, value=values[0])
        self.selected_type = values[0]

    def setDescription(self, event, value):
        """
        Dynamically display the description of the last modified element.
        """
        txt = "No description available."
        if DESC.get(event) is not None:
            identifier = value[event]
            if DESC[event].get(identifier) is not None:
                txt = DESC[event][identifier]
        dsc = self.window["-desc-"]
        dsc.update(value=txt)

    def libChanged(self, itemName):
        """
        This function is called when the library selection has changed.
        Depending on the library, different versions have to be displayed.
        When no versions are needed, simply remove all the items in the Combo and hide it.

        You might have to adapt this function when adding new libraries.

        :param itemName: The newly selected library's name.
        :type itemName: str
        """
        if itemName == "OpenSSL":
            l = list(getOpenSSLReleases().keys())
            # most recent one on top
            l.sort(reverse=True)
            # add them to the DropDown widget
            select = self.window["-versionselect-"]
            select.update(values=l, value=l[0], visible=True)
            self.window["-versionlabel-"].update(value="Version :")
            self.selected_version = l[0]

        elif itemName == "BouncyCastle":
            l = list(getBouncyCastleReleases().keys())
            # most recent one on top
            l.sort(reverse=True)
            # add them to the DropDown widget
            select = self.window["-versionselect-"]
            select.update(values=l, value=l[0], visible=True)
            self.window["-versionlabel-"].update(value="Version :")
            self.selected_version = l[0]

        elif itemName == "mbedTLS":
            l = list(getMbedTLSReleases().keys())
            # most recent one on top
            l.sort(reverse=True)
            # add them to the DropDown widget
            select = self.window["-versionselect-"]
            select.update(values=l, value=l[0], visible=True)
            self.window["-versionlabel-"].update(value="Version :")
            self.selected_version = l[0]

        else:
            # By default, we consider that there is no version to choose from
            select = self.window["-versionselect-"]
            select.update(values=[], visible=False)
            self.window["-versionlabel-"].update(value="")
            self.selected_version = None

    def algChanged(self, itemName):
        """
        This function is called when the algorithm selection has changed.
        Depending on the algorithm, not all modes or types have to be displayed.
        When no types or modes are needed, simply remove all the items in the Combo and hide them.

        You might have to adapt this function when adding new algorithms/types/modes.

        :param itemName: The newly selected algorithm name.
        :type itemName: str
        """

        self.window["-modeselect-"].update(values=[], visible=False)
        self.window["-modelabel-"].update(value="")
        self.selected_mode = None

        if itemName in ["DH", "ECDH", "PBKDF2", "ECDSA", "RSAES", "RSASSA"]:
            self.window["-typeselect-"].update(values=[], visible=False)
            self.window["-typelabel-"].update(value="")
            self.selected_type = None

        elif itemName in ["SHA1", "SHA2"]:
            self.populateType(excepted=["MMT"])
            self.window["-typeselect-"].update(visible=True)
            self.window["-typelabel-"].update(value="Test type :")

        elif itemName == "HMAC":
            self.populateType(excepted=["KAT", "MCT"])
            self.window["-typeselect-"].update(visible=True)
            self.window["-typelabel-"].update(value="Test type :")

        else:
            self.populateMode()
            self.populateType()
            self.window["-typeselect-"].update(visible=True)
            self.window["-typelabel-"].update(value="Test type :")
            self.window["-modeselect-"].update(visible=True)
            self.window["-modelabel-"].update(value="Mode :")

    def run(self):
        """
        This function is called when the user clicks on the "Run" button.
        Runs the test vectors corresponding to a specific combination of algorithm,
        type of vector and mode of operation for a specific target library.

        You might have to update this function when adding new libraries.
        """
        # get args from the widgets
        # there is always a lib
        lib = strToEnum(Lib, self.selected_lib)
        # there is always an algorithm
        alg = strToEnum(Alg, self.selected_alg)
        # type is optional depending on the algorithm
        type = self.selected_type
        if type is not None:
            if type == "All":
                type = []
                # All the types
                for libs in Type:
                    type.append(libs)
            else:
                type = [strToEnum(Type, type)]
        else:
            type = [None]
        # mode is optional depending on the algorithm
        mode = self.selected_mode
        if mode is not None:
            if mode == "All":
                mode = []
                # All the modes
                for libs in Mode:
                    mode.append(libs)
            else:
                mode = [strToEnum(Mode, mode)]
        else:
            mode = [None]
        # target version is optional depending on the algorithm
        ld = self.selected_version
        if ld is not None:
            # Get the URL associated to that version
            # You might have to change this part when adding new libraries
            if lib == Lib.OpenSSL:
                ld = getOpenSSLReleases()[ld]
            elif lib == Lib.BouncyCastle:
                ld = getBouncyCastleReleases()[ld]
            elif lib == Lib.mbedTLS:
                ld = getMbedTLSReleases()[ld]
            else:
                raise NotImplementedError("Unknown library : {}".format(lib))

        # runTests(lib=lib, alg=alg, type=type, mode=mode, ldpreload=ld, silent=False)
        # Run all the combination of supplied arguments
        pbar = self.window["-pbar-"]
        pbar2 = self.window["-pbar2-"]
        total = len(type)*len(mode)
        count = 0
        pbar.update(max=total, current_count=count, visible=True)
        pbar2.update(visible=True)

        for t in type:
            for m in mode:
                runTests(lib=lib, alg=alg, type=t, mode=m, ldpreload=ld, silent=False, window=self)
                count += 1
                pbar.update(count)
                self.window.refresh()

        # purely visual
        # let the time for the progress bar to fill up completely before removing it
        import time
        time.sleep(0.1)
        pbar.update(current_count=0, visible=False)
        pbar2.update(current_count=0, visible=False)
