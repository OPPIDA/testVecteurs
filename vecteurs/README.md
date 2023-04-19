# Test Vectors

Test vectors usually come in many different formats and files so it's very difficult to parse them.
That's why our test vectors have been modified to follow some rules.

## File format
Each vector file must be a valid JSON representation of the test vectors.
Strings must be represented in hexadecimal without the prefix '0x'.
When an attribute is not used by the test, the value 'null' should be used.

### File Structure
```
{
    "type" : "KAT",
    "alg" : "AES128",
    "mode" : "CBC"
    "vectors" : [
        {
            ...
        },
        ...
    ]
}
```

Each file contains 4 fields :
- type : The type of tests. Must be a string representing a valid [Type](../src/utils.py) object or null.
- alg : The target algorithm. Must be a string representing a valid [Alg](../src/utils.py) object or null.
- mode : The mode of the block cipher. Must be a string representing a valid [Mode](../src/utils.py) object or null if the algorithm doesn't use modes of operation.
- vectors : A list of test vectors. The structure of a test vector is described bellow.

It's important to fill the first 3 fields correctly because it's based on them that the parser will decide if a specific vector file should be included in the tests to perform, based on the choice of the user.

### Vector Structure

```
{
  "pt": "00000000000000000000000000000000",
  "iv": "00000000000000000000000000000000",
  "key": "fffffffffffffffffffffffffffffff8",
  "expected": "OK",
  "operation": "ENCR",
  "ct": "5a4d404d8917e353e92a21072c3b2305"
}
```

Each vector is represented by a JSON dictionary containing only the attributes necessary for each type of vector. The example above is an example test vector for AES128-CBC encryption.

Each vector must contain at least the following 2 attributes :
- **expected** : The expected result of running this test. Must be a string representing a valid [Result](../src/utils.py) object.
- **operation** : The operation to perform with this vector. Must be a string representing a valid [Operation](../src/utils.py) object.

All other attributes are optional and strongly depend on the algorithm, mode and type they're tied to. For complete documentation on all the possible attributes, refer to the documentation of the [Vector](../src/Classes/Vector.py) Class.