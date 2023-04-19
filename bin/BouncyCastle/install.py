#!/usr/bin/env python3
# Author : Florian Picca <florian.picca@oppida.fr>
# Date : December 2020

"""
Script that will download and install any version of BouncyCastle.
Installation is performed in the ./libs folder.
"""

import os
import sys
import hashlib
import requests

def install(data, path):
    """
    Installs the library.
    You might need to change this function.

    :param data: The dowloaded content.
    :param path: The path in which the library will be installed
    """
    # write ZIP to tmp file (needed for extraction)
    tmp_file = os.path.join(path, "bcprov.jar")
    with open(tmp_file, "wb") as f:
        f.write(data)

def buildSymlinks(currentLib, path):
    """
    Updates the symbolic links.
    You might need to change this function.

    :param currentLib: Path to the currentLib symlink source
    :param path: The path in which the library is installed
    """
    lib = os.path.abspath(os.path.join(path, "bcprov.jar"))
    os.symlink(lib, currentLib)

if __name__ == "__main__":
    # Set the current directory to the one the script is currently in
    os.chdir(os.path.dirname(sys.argv[0]))

    PATH = "libs"

    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <url>")
        sys.exit(0)

    if not os.path.exists(PATH):
        os.mkdir(PATH)

    url = sys.argv[1].encode()
    hash = hashlib.sha256(url).hexdigest()

    PATH = os.path.join(PATH, hash)
    oldPath = PATH
    # check if the URL was already downloaded
    if not os.path.exists(PATH):
        os.mkdir(PATH)
        # if not, download and extract it
        content = requests.get(url).content
        # proceed to install the library
        install(content, PATH)

    # Update symbolic links
    PATH = os.path.dirname(PATH)
    currentLib = os.path.join(PATH, "currentLib")
    if os.path.islink(currentLib):
        os.unlink(currentLib)

    buildSymlinks(currentLib, oldPath)