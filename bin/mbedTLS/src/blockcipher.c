// Author : Florian Picca <florian.picca@oppida.fr>
// Date : September 2020
#include "util.h"
#include <mbedtls/aes.h>

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

static int encdec(unsigned char *input, int input_len, unsigned char *key, unsigned char *iv, unsigned char *output, char *modeName, int mode) {
    unsigned int keylen = 0;
    if (strstr(modeName, "128") != NULL) {keylen = 128;}
    if (strstr(modeName, "192") != NULL) {keylen = 192;}
    if (strstr(modeName, "256") != NULL) {keylen = 256;}

    mbedtls_aes_context ctx;
    if (mbedtls_aes_setkey_enc(&ctx, key, keylen) != 0) {handleErrors("invalid key length");}

    // ECB
    if (strstr(modeName, "ecb") != NULL) {
        if (mode == MBEDTLS_AES_DECRYPT) {
            if (mbedtls_aes_setkey_dec(&ctx, key, keylen) != 0) {handleErrors("invalid key length");}
        }
        int i;
        for (i=0; i<input_len; i+=16) {
            mbedtls_aes_crypt_ecb(&ctx,  mode, input+i, output+i);
        }
    }
    // OFB
    else if (strstr(modeName, "ofb") != NULL) {
        // Always use encrypt context
        size_t iv_off = 0;
        mbedtls_aes_crypt_ofb(&ctx,  input_len, &iv_off, iv, input, output);
    }
    // CTR
    else if (strstr(modeName, "ctr") != NULL) {
        // Always use encrypt context
        size_t nc_off = 0;
        unsigned char stream_block[16];
        mbedtls_aes_crypt_ctr(&ctx,  input_len, &nc_off, iv, stream_block, input, output);
    }
    // CFB8
    else if (strstr(modeName, "cfb8") != NULL) {
        // Always use encrypt context
        mbedtls_aes_crypt_cfb8(&ctx, mode, input_len, iv, input, output);
    }
    // CFB128
    else if (strstr(modeName, "cfb") != NULL) {
        // Always use encrypt context
        size_t iv_off = 0;
        mbedtls_aes_crypt_cfb128(&ctx, mode, input_len, &iv_off, iv, input, output);
    }
    // CBC
    else if (strstr(modeName, "cbc") != NULL) {
        if (mode == MBEDTLS_AES_DECRYPT) {
            if (mbedtls_aes_setkey_dec(&ctx, key, keylen) != 0) {handleErrors("invalid key length");}
        }
        mbedtls_aes_crypt_cbc(&ctx, mode, input_len, iv, input, output);
    }
    return input_len;
}


/*
This function encrypts the plaintext with the key and iv.
iv can be empty.
The cipher is chosen by it's name.
cipher names follow the OpenSSl syntax in lower case : aes-256-gcm, aes-128-cfb8, aes-192-cbc, ...
The result is stored in ciphertext and the function returns the length of the result.
*/
static int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext, char *modeName)
{
    return encdec(plaintext, plaintext_len, key, iv, ciphertext, modeName, MBEDTLS_AES_ENCRYPT);
}


/*
This function decrypts the ciphertext with the key and iv.
iv can be empty.
The cipher is chosen by it's name.
cipher names follow the OpenSSl syntax in lower case : aes-256-gcm, aes-128-cfb8, aes-192-cbc, ...
The result is stored in plaintext and the function returns the length of the result.
*/
static int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext, char *modeName)
{
    return encdec(ciphertext, ciphertext_len, key, iv, plaintext, modeName, MBEDTLS_AES_DECRYPT);
}

/*
This function encrypts 1000 times the plaintext with the key and iv.
iv can be empty.
The cipher is chosen by it's name.
cipher names follow the OpenSSl syntax in lower case : aes-256-gcm, aes-128-cfb8, aes-192-cbc, ...
The result is stored in ciphertext and the function returns the length of the result.
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
The result is stored in plaintext and the function returns the length of the result.
*/
static int decryptMCT(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext, char *modeName)
{
    return NOT_IMPLEMENTED_ERROR;
}