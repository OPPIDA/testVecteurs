// Authors : Mikael Benhaiem <mikael.benhaiem@oppida.fr>, Florian Picca <florian.picca@oppida.fr>
// Date : October 2019
#include "util.h"

static int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext, char *modeName);
static int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext, char *modeName);
static int encryptMCT(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext, char *modeName);
static int decryptMCT(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext, char *modeName);

// Do not edit this function unless you know what you are doing
void blockcipher_run(int argc,char *argv[])
{
    if (argc != 7) {
        handleErrors("Invalid argument number.");
    }

    unsigned char *message = htos((unsigned char*)argv[1]);
    int message_len = strlen(argv[1])/2;
    unsigned char *key = htos((unsigned char*)argv[2]);
    unsigned char *iv = htos((unsigned char*)argv[3]);
    // Output can be bigger then input in case of encryption but only at maximum 1 block length
    // The +512 is just the max bloc length, just to be sure
    unsigned char output[message_len+512];
    int output_len;
    unsigned char *output_hex;

    if (!strcmp(argv[5], "E")) {
        if (!strcmp(argv[6], "MCT")) {
            output_len = encryptMCT(message, message_len, key, iv, output, argv[4]);
        }
        else {
            output_len = encrypt(message, message_len, key, iv, output, argv[4]);
        }
    }
    else if (!strcmp(argv[5], "D")) {
        if (!strcmp(argv[6], "MCT")) {
            output_len = decryptMCT(message, message_len, key, iv, output, argv[4]);
        }
        else {
            output_len = decrypt(message, message_len, key, iv, output, argv[4]);
        }
    }
    else handleErrors("'E' or 'D' expected");

    if (output_len != NOT_IMPLEMENTED_ERROR) {
        output_hex = stoh(output, output_len);
        printf("%s\n", output_hex);
        free(output_hex);
    }
    else {
        skip();
    }

    // free
    free(message);
    free(key);
    free(iv);
}

/*
This function encrypts the plaintext with the key and iv.
iv can be empty.
The cipher is chosen by it's name.
cipher names follow the OpenSSl syntax in lower case : aes-256-gcm, aes-128-cfb8, aes-192-cbc, ...
The result is stored in ciphertext (already allocated) and the function returns the length of the result.
*/
static int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext, char *modeName)
{
    return NOT_IMPLEMENTED_ERROR;
}


/*
This function decrypts the ciphertext with the key and iv.
iv can be empty.
The cipher is chosen by it's name.
cipher names follow the OpenSSl syntax in lower case : aes-256-gcm, aes-128-cfb8, aes-192-cbc, ...
The result is stored in plaintext (already allocated) and the function returns the length of the result.
*/
static int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext, char *modeName)
{
    return NOT_IMPLEMENTED_ERROR;
}

/*
This function encrypts 1000 times the plaintext with the key and iv.
iv can be empty.
The cipher is chosen by it's name.
cipher names follow the OpenSSl syntax in lower case : aes-256-gcm, aes-128-cfb8, aes-192-cbc, ...
The result is stored in ciphertext (already allocated) and the function returns the length of the result.
*/
static int encryptMCT(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext, char *modeName)
{
    return NOT_IMPLEMENTED_ERROR;
}

/*
This function decrypts 1000 times the ciphertext with the key and iv.
iv can be empty.
The cipher is chosen by it's name.
cipher names follow the OpenSSl syntax in lower case : aes-256-gcm, aes-128-cfb8, aes-192-cbc, ...
The result is stored in plaintext (already allocated) and the function returns the length of the result.
*/
static int decryptMCT(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext, char *modeName)
{
    return NOT_IMPLEMENTED_ERROR;
}