# Templates

This document explains the structure of the different templates
and what should be edited when adding new libraries.
Templates are separated based on their target language.

## Table of Contents
[C](#c)

[Java](#java)

## C

To test a library written in C it is required to write small programs that do the
cryptographic operations with the library and return the result in a way that is
understandable by the main Python program. This is exactly the purpose of this template.

Instead of writing individual C programs that would be called each time a test vector
is run, a unique program (called "dialoger") is launched at the start of the tests and can handle all vector types.
This choice added a little bit more complexity to the whole project but the gain in performance
is very significant.

The dialoger is an interactive program that waits for user input (commands) on STDIN and
writes the output on STDOUT. Commands follow a simple CSV syntax :

`<COMMAND>,<ARG1>,<ARG2>,...`

Commands are used to differentiate between vector types or simply quit the dialoger.
The interaction with the dialoger is entirely done by the [C_Runner](../../src/Classes/RunnerC.py)
you don't need to do anything.

By default, the template can be compiled and used without errors, the dialoger will simply
return a message indicting that the feature is not implemented.

### Structure of the directory

The minimal structure of the directory is composed of a [makefile](C/makefile) and a directory (src)
containing the source files :

| File                                 | Usage                                                                                                                                |
|--------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------|
| [blockcipher.c](C/src/blockcipher.c) | Should handle AES (or any block cipher) test vectors in any mode except AEAD.                                                        |
| [commands.h](C/src/commands.h)       | This file contains the function definitions needed by the main program. You shouldn't have to modify it.                             |
| [dh.c](C/src/dh.c)                   | Should handle Diffie-Hellman test vectors with or without hashing as post-treatment.                                                 |
| [dialoger.c](C/src/dialoger.c)       | The main program. Will read commands from STDIN and dispatch the test vector to the right function. You shouldn't have to modify it. |
| [ecdh.c](C/src/ecdh.c)               | Should handle Elliptic Curve Diffie-Hellman test vectors.                                                                            |
| [ecdsa.c](C/src/ecdsa.c)             | Should handle Elliptic Curve signature test vectors.                                                                                 |
| [gcm.c](C/src/gcm.c)                 | Should handle AES GCM test vectors.                                                                                                  |
| [hasher.c](C/src/hasher.c)           | Should handle hash functions (SHA1, SHA256, ...) test vectors.                                                                       |
| [hmac.c](C/src/hmac.c)               | Should handle HMAC test vectors with different hash functions.                                                                       |
| [pbkf.c](C/src/pbkdf.c)              | Should handle PBKDF2 test vectors with HMAC-SHA1.                                                                                    |
| [util.c](C/src/util.c)               | Contains helper functions. You shouldn't have to modify it.                                                                          |
| [util.h](C/src/util.h)               | Contains helper function definitions. You shouldn't have to modify it.                                                               |
| [version.c](C/src/version.c)         | Should print the library version obtained at run time.                                                                               |

Compilation is done with the command `make`.
This will create the dialoger named "dialoger.bin" at the root of the directory.
A `build` directory will also be created, containing all the intermediate build files.
Those will not be pushed to GitHub anyway and can be cleared using `make clean`.

Optionally, mainstream libraries like OpenSSL can have multiple versions
that need to be supported by this program. Those versions must be installed in a directory
called `libs` to not interfere with the OS libraries. See [OpenSSL's directory](../OpenSSL)
for example. The different versions of the library are automatically downloaded and installed
using a script called [install.py](../OpenSSL/install.py). The versions' download URL are
kept in a cache file (versions.pickle) to not check the GitHub API every time (there is a rate
limit). Once locally installed, libraries are cached, the installation script knows if a version
is already installed based on a SHA256 hash. The `libs` folder is not and should not be
uploaded to GitHub.

### Adding your code

Like mentioned in the table above, some files do not need to (and should not) be edited.
In the files you can edit, there is always a function which name ends in `_run`. This
is the function that will be called by the dialoger, you do not need to (and should not)
edit it. There are comments in the source code indicating if a file or function should
not be edited.

Only add code to the functions that are needed by your library. If your library does not
provide support for an algorithm of the template, leave it as it is.

Additional files can be added if needed. This is the case when the library to test is just
a small set of functions.

Every compiler warning should be taken into consideration and corrected.

The source code should provide enough documentation to understand what the functions should do.

## Java

The idea for Java is the same as for the C templates.
The Java templates are still new and will change in the future to be like the C template.
Just refer to the source code for more documentation at the moment.