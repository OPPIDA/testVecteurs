# Contributing to TestVectors

This document is targeting developers who want to contribute to the project.
It contains technical documentation about how the project is structured and the role of each part.
More precise documentation can be found directly in the code.

## Table of Contents
[Components](#components)

[Project's files Structure](#projects-files-structure)

[Adding new test vectors](#adding-new-test-vectors)

[Adding support of a new library](#adding-support-of-a-new-library)

## Components

The project is composed of 3 main components. Each is responsible for a specific task.

### Vector

Each individual test vector is represented as a [Vector](src/Classes/Vector.py) class containing all the possible attributes of a test vector (plaintext, key, hash, result, ...). For a complete list and documentation of each attribute, please refer to the documentation in the source code of this class.

Vectors are instantiated from a dictionary by the [parser](#parser). Each key of the dictionary is mapped to an attribute. If the dictionary doesn't contain the key for an attribute, the attribute's value defaults to None.

A vector must be representable as a string because it is printed in case of failure. To do that, each attribute must be added in it's description only if it's used. This is done by overwriting the internal function `__str__`.

If new vectors are added and the already existing attributes are not enough, add new ones and make sure the key is not already used for another attribute. Update the `__str__` function by adding the new attributes.

### Parser

The [parser](src/Classes/Parser.py) is responsible for reading the [test vector files](vecteurs/README.md) and keeping the test vectors that match the parameters given by the user.

The way it does that is by reading all files with the `.json` extension in the directory `vecteurs/` and keeping only vectors in the files that have the same type, same algorithm and same mode.

For performance reasons, the parser also knows if a combination of type, algorithm and mode is valid through it's internal function `_validComb`. If new vector files are added, make sure to modify this function accordingly. This is only used to avoid reading all vector files if we already know that this specific combination doesn't exist.

If a combination is valid, the parser will contain a list off all the test vectors that have to be run against the target library.

Beside the function `_validComb`, you shouldn't have to modify anything in this class if you add new test vector files.

### Runner

The [Runner](src/Classes/Runner.py) is responsible for performing each individual tests and handling the results. It's the component that makes the interface with the target library.

The top level Runner class is responsible for handling the results of each test vector but can't run the tests by itself. The function `handleVector` is called with a single test vector as parameter and a result of type [Result](src/utils.py) is expected.

A runner must be defined for each target library by creating a new subclass of the Runner class. The subclasses must override the function `handleVector` of the top level class so that they handle each vector accordingly.

Other functions must also be overridden by the subclasses :
- `version` must provide the version string of the library tested.
- `compile` must perform helper programs' compilation steps.
- `...` see the [source code](src/Classes/Runner.py) for a complete list.

For example, the [Test_Runner](src/Classes/Runner_Test.py) class runs test vectors against the pycrypto Python module.

To simplify the addition of new libraries written in the C language, a [generic runner](src/Classes/RunnerC.py) handles
all the aspects stated above. The source code must follow the [C templates](bin/Templates/README.md). Addition of new C libraries
can be done directly from the GUI. All the C-based libraries inherit from this generic Runner and do not need to be defined
in a new subclass. They are directly defined in a [configuration file](src/runners.json) in JSON.

A runner is instantiated with a reference to a parser that contains the test vectors and general information on its test vectors (algorithm, type, mode). everything else can be accessed directly from the vector to test.

## Project's Files Structure

The project is composed of several files stored in various directories.

At the root directory should only be markdown files concerning all the project (README, CONTRIBUTING, ...) and the launch scripts ([gui.sh](gui.sh) or [run.sh](run.sh)).

The other files and directories are described bellow :

- bin/ : Directory containing non-python code needed to interface with a library.
    - LibName/ : Directory containing the sources of the program needed to interface with the library.
    See [the templates](bin/Templates/README.md) for more details.
- src/ : Directory containing all the Python source code of this program.
    - main.py : The entry point for the command line version.
    - runners.json : The Runner configuration file.
    - utils.py : A collection of utility functions and enums
    - tests.py : pycrypto implementation of every algorithm, for testing purpose.
    - Classes/ : Directory containing the Python classes described in [components](#components)
    - gui/ : Directory containing the source code of the GUI.
        - App.py : The main application and entry point of the GUI.
        - Views/ : Directory containing all the GUI windows.
            - LibCreateWindow.py : The window allowing to create a new library.
            - RunTestsWindow.py : The window allowing to perform the tests.
- vecteurs/ : Directory containing all the JSON vector files.

## Adding new test vectors

Adding new vectors to an already supported algorithm, mode and type is as simple as adding new JSON entries in the already existing file and that's all.

Adding new vectors for a new algorithm, mode or type requires creating a new file in the `vecteurs/` directory with the structure described [here](vecteurs/README.md).

You'll have to add your new algorithm, mode or type identifier to the corresponding enums defined in [utils.py](src/utils.py). Allowed user inputs are based on them.

Update the `_validComb` function of the Parser class if needed. Update the `handleVector` function of every subclass of the Runner class to handle your new vectors accordingly.

Update the `AlgChanged` function of the [RunTestsView](src/gui/Views/RunTestsView.py) class and the `DESC` variable.

## Adding support of a new library

### C-based library

Just do it from the GUI.
This will create all the necessary files for you.
You'll only have to write C code for the functions supported by the library to test.
See [the templates](bin/Templates/README.md) for more details on the C template.

### Other languages

This is what requires the most work.

At the moment, there is no way to add new libraries that are not C-based from the GUI (but it will someday).
Here are steps required.

You'll first have to create a new subclass of the Runner class. If the library is not directly accessible in Python, create a new directory in `bin/` with the name of your library. Add this name to the "Lib" enum in [utils.py](src/utils.py). Allowed user inputs are based on them.

In your new runner subclass, implement the function `handleVector`.
You might want to write a dedicated function for each test vector operation (encryption, decryption, key exchange, ...). Don't hesitate to inspire you from the already written runners.

If your library is written in different language than Python, you'll have to write external programs in that language that will do the desired operations using the library and output the results. You'll find templates for the currently implemented algorithms in the `bin/Templates/<language>` directory.

It is very important when writing external programs to only write on STDOUT the result you want to retrieve and nothing else. That's because the `runProc` function in [utils.py](src/utils.py) returns the STDOUT output of the program it ran. You should read the documentation contained in the source code of each template.

Update the [gitignore](.gitignore) file to not add intermediate build files (.o, ...), binaries and content of the `libs/` folder to the gitlab. They are not needed, your runner should compile the sources by itself if the binaries are not present (look at the `compile` function of [C_Runner](src/Classes/RunnerC.py) or [BouncyCastle_Runner](src/Classes/Runner_BouncyCastle.py)).