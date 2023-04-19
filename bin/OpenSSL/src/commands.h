// Author : Florian Picca <florian.picca@oppida.fr>
// Date : July 2020
#ifndef COMMANDS_H
#define COMMANDS_H
//Do not put the statically defined function here

/* Arguments in order :
        - key : hex string representing the key
        - message : hex string representing the message to hash
        - hash name : string representing the hash's name : SHA1, SHA224, SHA256, SHA384, SHA512 others are supported as well (MD5, SHA3-512, ...)
*/
void hmac_run(int argc,char *argv[]);

/* Arguments in order :
        - password : The password in hexadecimal
        - salt : The salt in hexadecimal
        - iterations : The number of iterations
        - dklen : The output key length
        - hash name : The name of the hash function to use to derive sk
*/
void pbkdf_run(int argc,char *argv[]);

/*
Prints the target library version obtained at run time.
*/
void print_version();

/* Arguments in order :
        - message : hex string representing the message to hash
        - hash name : string representing the hash's name : SHA1, SHA224, SHA256, SHA384, SHA512 others are supported as well (MD5, SHA3-512, ...)
        - MCT : "MCT" if an MCT test is required, empty otherwise
*/
void hasher_run(int argc,char *argv[]);

/* Arguments in order :
        - message : The message to encrypt/decrypt in hexadecimal
        - key : The key of the bloc cipher in hexadecimal
        - iv : The IV of the bloc cipher in hexadecimal
        - header : The additionnal data in hexadecimal
        - tag : The tag in hexadecimal
        - cipher : The name of the cipher to use
        - E/D : "E" for encryption, "D" for decryption
*/
void gcm_run(int argc,char *argv[]);

/* Arguments in order :
        - curve name : The name of the curve : P-192, P-224, P-256, P-384, P-521
        - hash : The precomputed hash of the message to sign in hexadecimal form
        - d : The private key in hexadecimal form
        - k : The random value used in the signature to produce r in hexadecimal form
*/
void ecdsa_run(int argc,char *argv[]);

/* Arguments in order :
        - curve name : The name of the curve : P-192, P-224, P-256, P-384, P-521
        - da : A's private key in hexadecimal form
        - xb : B's public key's X coordinate in hexadecimal form
        - yb : B's public key's Y coordinate in hexadecimal form
*/
void ecdh_run(int argc,char *argv[]);

/* Arguments in order :
        - p : The group's prime modulus in hexadecimal form
        - g : The group's generator in hexadecimal form
        - da : A's private value in hexadecimal form
        - db : B's private value in hexadecimal form
        - hash name : The name of the hash function to use to derive sk
*/
void dh_run(int argc,char *argv[]);

/* Arguments in order :
        - message : The message to encrypt/decrypt in hexadecimal
        - key : The key of the bloc cipher in hexadecimal
        - iv : The IV of the bloc cipher in hexadecimal
        - cipher : The name of the cipher to use
        - E/D : "E" for encryption, "D" for decryption
        - MCT : "MCT" if an MCT test is required, empty otherwise
*/
void blockcipher_run(int argc,char *argv[]);

/* Arguments in order :
        - n : The modulus in hexadecimal
        - e : The public exponent in hexadecimal
        - d : The private exponent in hexadecimal
        - message : The message to encrypt/decrypt in hexadecimal
        - signature : The signature to verify in hexadecimal
        - hashname : The name of the hash function to use for signing
        - padding : The name of the padding scheme
        - operation : "E" for encryption, "D" for decryption, "S" for signature, "V" for verification
*/
void rsa_run(int argc,char *argv[]);

#endif