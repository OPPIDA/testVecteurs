#!/usr/bin/env python3
# Author : Florian Picca <florian.picca@oppida.fr>
# Date : December 2020

"""
Script that will download and install any version of OpenSSL.
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
    tmp_file = os.path.join(path, "tmp_file")
    with open(tmp_file, "wb") as f:
        f.write(data)

    # unzip the archive
    import zipfile
    with zipfile.ZipFile(tmp_file, 'r') as zip_ref:
        zip_ref.extractall(path)
        # Get the first directory name so we can move into it later
        name = zip_ref.filelist[0].filename
    os.remove(tmp_file)
    unzipped_path = os.path.join(path, name)

    # Configure
    import subprocess
    config = os.path.join(unzipped_path, "config")
    Configuration = os.path.join(unzipped_path, "Configuration")
    # zipfile loses execution rights when unzipping...
    os.chmod(config, 0o755)
    os.chmod(Configuration, 0o755)
    # important to run ./config from the unzipped directory (cwd=...) otherwise files are created in the same directory as this script
    subprocess.check_output(["./config", f"--prefix={os.path.abspath(unzipped_path)}", f"--openssldir={os.path.abspath(unzipped_path)}", "shared"], cwd=unzipped_path)

    # Building
    subprocess.check_output(["make"], cwd=unzipped_path)

def buildSymlinks(currentLib, currentPath, currentInclude, path):
    """
    Updates the symbolic links.
    You might need to change this function.

    :param currentLib: Path to the currentLib symlink source
    :param currentPath: Path to the currentPath symlink source
    :param currentInclude: Path to the currentInclude symlink source
    :param path: The path in which the library is installed
    """
    lib = os.path.abspath(os.path.join(path, "libcrypto.so"))
    os.symlink(lib, currentLib)
    include = os.path.abspath(os.path.join(path, "include"))
    os.symlink(include, currentInclude)
    os.symlink(os.path.abspath(path), currentPath)


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
    currentPath = os.path.join(PATH, "currentPath")
    currentInclude = os.path.join(PATH, "currentInclude")
    if os.path.islink(currentLib):
        os.unlink(currentLib)
    if os.path.islink(currentPath):
        os.unlink(currentPath)
    if os.path.islink(currentInclude):
        os.unlink(currentInclude)

    # OpenSSL specific
    oldPath = os.path.join(oldPath, os.listdir(oldPath)[0])
    buildSymlinks(currentLib, currentPath, currentInclude, oldPath)
