// Authors : Mikael Benhaiem <mikael.benhaiem@oppida.fr>, Florian Picca <florian.picca@oppida.fr>
// Date : October 2019
#include "util.h"
#include <openssl/evp.h>

static int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext, char *modeName);
static int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext, char *modeName);
static int encryptMCT(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext, char *modeName);
static int decryptMCT(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext, char *modeName);

/* Arguments in order :
        - message : The message to encrypt/decrypt in hexadecimal
        - key : The key of the bloc cipher in hexadecimal
        - iv : The IV of the bloc cipher in hexadecimal
        - cipher : The name of the cipher to use
        - E/D : "E" for encryption, "D" for decryption
        - MCT : "MCT" if an MCT test is required, empty otherwise
*/
void blockcipher_run(int argc,char *argv[])
{
    if (argc != 7) {
        handleErrors("Invalid argument number.");
    }

    OpenSSL_add_all_algorithms();

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

    output_hex = stoh(output, output_len);

    printf("%s\n", output_hex);

    // free
    free(output_hex);
    free(message);
    free(key);
    free(iv);
}

/*
This function encrypts the plaintext with the key and iv.
iv can be empty.
The cipher is chosen by it's name (https://github.com/openssl/openssl/blob/648b53b88ea55b4c2f2c8c57d041075731db5f95/crypto/objects/obj_dat.h#L2306).
The result is stored in ciphertext and the function returns the length of the result.
*/
static int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext, char *modeName)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    const EVP_CIPHER *cipher = NULL;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors("Cipher_ctx_new(Encrypt)");

    if (NULL == (cipher = EVP_get_cipherbyname(modeName))) handleErrors("Invalid cipher name");
    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if(1 != EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv)) handleErrors("EncryptInit");

	EVP_CIPHER_CTX_set_padding(ctx,0);

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) handleErrors("EncryptUpdate");
    ciphertext_len = len;

    /* Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors("EncryptFinal");
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}


/*
This function decrypts the ciphertext with the key and iv.
iv can be empty.
The cipher is chosen by it's name (https://github.com/openssl/openssl/blob/648b53b88ea55b4c2f2c8c57d041075731db5f95/crypto/objects/obj_dat.h#L2306).
The result is stored in plaintext and the function returns the length of the result.
*/
static int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext, char *modeName)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    const EVP_CIPHER *cipher = NULL;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors("Cipher_ctx_new(Decrypt)");

    if (NULL == (cipher = EVP_get_cipherbyname(modeName))) handleErrors("Invalid cipher name");
    /* Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */

	if(1 != EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv)) handleErrors("DecryptInit");

	EVP_CIPHER_CTX_set_padding(ctx,0);

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) handleErrors("DecryptUpdate");
    plaintext_len = len;

    /* Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors("DecryptFinal");
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

/*
This function encrypts 1000 times the plaintext with the key and iv.
iv can be empty.
The cipher is chosen by it's name (https://github.com/openssl/openssl/blob/648b53b88ea55b4c2f2c8c57d041075731db5f95/crypto/objects/obj_dat.h#L2306).
The result is stored in ciphertext and the function returns the length of the result.
*/
static int encryptMCT(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext, char *modeName)
{
    int i;
    int plen = plaintext_len;

    // iv length is the same as plaintext_len except for CFB8
    unsigned char tmp[plen];
    unsigned char iv_tmp[plen];
    unsigned char p[plen];
    unsigned char cfb_iv[16];

    memcpy(iv_tmp, iv, plen);
    memcpy(p, plaintext, plen);

    EVP_CIPHER_CTX *ctx;
    int len;
    const EVP_CIPHER *cipher = NULL;

    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors("Cipher_ctx_new(Encrypt)");

    if (NULL == (cipher = EVP_get_cipherbyname(modeName))) handleErrors("Invalid cipher name");

    if(1 != EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv)) handleErrors("EncryptInit");

	EVP_CIPHER_CTX_set_padding(ctx,0);

    for (i = 0; i < 1000; i++) {

        if(1 != EVP_EncryptUpdate(ctx, tmp, &len, p, plen)) handleErrors("EncryptUpdate");
        plen = len;

        if(1 != EVP_EncryptFinal_ex(ctx, tmp + len, &len)) handleErrors("EncryptFinal");
        plen += len;

        //printf("tmp: %s, p: %s\n", stoh(tmp, plen), stoh(p, plen));

        // In case of ECB
        if (strstr(modeName, "ecb") != NULL) {
            // there is no IV
            memcpy(p, tmp, plen);
        }
        // In case of CFB8
        else if (strstr(modeName, "cfb8") != NULL) {
            // First consume the initial IV byte by byte
            if (i < 16) memcpy(p, &iv[i], 1);
            else memcpy(p, &cfb_iv[i%16], 1);
            // populate cfb_iv on the fly
            memcpy(&cfb_iv[i%16], tmp, 1);
        }
        // Other modes
        else {
            memcpy(p, iv_tmp, plen);
            memcpy(iv_tmp, tmp, plen);
        }
    }
    memcpy(ciphertext, tmp, plen);

    EVP_CIPHER_CTX_free(ctx);

    return plen;
}

/*
This function decrypts 1000 times the ciphertext with the key and iv.
iv can be empty.
The cipher is chosen by it's name (https://github.com/openssl/openssl/blob/648b53b88ea55b4c2f2c8c57d041075731db5f95/crypto/objects/obj_dat.h#L2306).
The result is stored in plaintext and the function returns the length of the result.
*/
static int decryptMCT(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext, char *modeName)
{
    int i;
    int plen = ciphertext_len;

    // iv length is the same as plaintext_len except for CFB8
    unsigned char tmp[plen];
    unsigned char iv_tmp[plen];
    unsigned char p[plen];
    unsigned char cfb_iv[16];

    memcpy(iv_tmp, iv, plen);
    memcpy(p, ciphertext, plen);

    EVP_CIPHER_CTX *ctx;
    int len;
    const EVP_CIPHER *cipher = NULL;

    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors("Cipher_ctx_new(Encrypt)");

    if (NULL == (cipher = EVP_get_cipherbyname(modeName))) handleErrors("Invalid cipher name");

    if(1 != EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv)) handleErrors("EncryptInit");

	EVP_CIPHER_CTX_set_padding(ctx,0);

    for (i = 0; i < 1000; i++) {
        if(1 != EVP_DecryptUpdate(ctx, tmp, &len, p, plen)) handleErrors("EncryptUpdate");
        plen = len;

        if(1 != EVP_DecryptFinal_ex(ctx, tmp + len, &len)) handleErrors("EncryptFinal");
        plen += len;

        // In case of ECB
        if (strstr(modeName, "ecb") != NULL) {
            // there is no IV
            memcpy(p, tmp, plen);
        }
        // In case of CFB8
        else if (strstr(modeName, "cfb8") != NULL) {
            // First consume the initial IV byte by byte
            if (i < 16) memcpy(p, &iv[i], 1);
            else memcpy(p, &cfb_iv[i%16], 1);
            // populate cfb_iv on the fly
            memcpy(&cfb_iv[i%16], tmp, 1);
        }
        // Other modes
        else {
            memcpy(p, iv_tmp, plen);
            memcpy(iv_tmp, tmp, plen);
        }

    }
    memcpy(plaintext, tmp, plen);

    EVP_CIPHER_CTX_free(ctx);

    return plen;
}