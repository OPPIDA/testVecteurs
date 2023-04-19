// Author : Florian Picca <florian.picca@oppida.fr>
// Date : January 2020
#include "util.h"
#include <openssl/evp.h>

static int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *aad, int aad_len, unsigned char *key, unsigned char *iv, int iv_len, unsigned char *ciphertext, unsigned char *tag, int tag_len, char *modeName);
static int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad, int aad_len, unsigned char *tag, int tag_len, unsigned char *key, unsigned char *iv, int iv_len, unsigned char *plaintext, char *modeName);


/* Arguments in order :
        - message : The message to encrypt/decrypt in hexadecimal
        - key : The key of the bloc cipher in hexadecimal
        - iv : The IV of the bloc cipher in hexadecimal
        - header : The additionnal data in hexadecimal
        - tag : The tag in hexadecimal
        - cipher : The name of the cipher to use
        - E/D : "E" for encryption, "D" for decryption
*/
void gcm_run(int argc,char *argv[])
{
    if (argc != 8) {
        handleErrors("Invalid argument number.");
    }

    OpenSSL_add_all_algorithms();

    unsigned char *message = htos((unsigned char*)argv[1]);
    int message_len = strlen(argv[1])/2;
    unsigned char *key = htos((unsigned char*)argv[2]);
    unsigned char *iv = htos((unsigned char*)argv[3]);
    int iv_len = strlen(argv[3])/2;
    unsigned char *header = htos((unsigned char*)argv[4]);
    int header_len = strlen(argv[4])/2;
    unsigned char *tag = htos((unsigned char*)argv[5]);
    int tag_len = strlen(argv[5])/2;
    // Output can be bigger then input in case of encryption but only at maximum 1 block length
    // The +512 is just the max bloc length, just to be sure
    unsigned char output[message_len+512];
    int output_len;
    unsigned char *output_hex;
    unsigned char ICV[tag_len];
    unsigned char *ICV_hex;

    if (!strcmp(argv[7], "E")) {
        output_len = encrypt(message, message_len, header, header_len, key, iv, iv_len, output, ICV, tag_len, argv[6]);
        output_hex = stoh(output, output_len);
        ICV_hex = stoh(ICV, tag_len);

        printf("%s,%s\n", output_hex, ICV_hex);
        free(ICV_hex);
        free(output_hex);
    }
    else if (!strcmp(argv[7], "D")) {
        output_len = decrypt(message, message_len, header, header_len, tag, tag_len, key, iv, iv_len, output, argv[6]);
        if (output_len > 0) {
            output_hex = stoh(output, output_len);
            printf("%s\n", output_hex);
            free(output_hex);
        }
        else if (output_len == 0) {
            //not an error but there was no cipher to begin with
            printf("good\n");
        }
        else {
            //not an error but an invalid MAC
            printf("fail\n");
        }

    }
    else handleErrors("'E' or 'D' expected");

    // free
    free(message);
    free(key);
    free(iv);
}

static int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *aad, int aad_len, unsigned char *key, unsigned char *iv, int iv_len, unsigned char *ciphertext, unsigned char *tag, int tag_len, char *modeName)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    const EVP_CIPHER *cipher = NULL;


    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors("EVP_CIPHER_CTX_new");


    if (NULL == (cipher = EVP_get_cipherbyname(modeName))) handleErrors("Invalid cipher name");

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL))
        handleErrors("EVP_EncryptInit_ex");

    /*
     * Set IV length if default 12 bytes (96 bits) is not appropriate
     */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrors("EVP_CIPHER_CTX_ctrl");

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors("EVP_EncryptInit_ex");

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrors("EVP_EncryptUpdate AAD");

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors("EVP_EncryptUpdate msg");
    ciphertext_len = len;

    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors("EVP_EncryptFinal_ex");
    ciphertext_len += len;

    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_len, tag))
        handleErrors("get tag");

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

static int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad, int aad_len, unsigned char *tag, int tag_len, unsigned char *key, unsigned char *iv, int iv_len, unsigned char *plaintext, char *modeName)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;
    const EVP_CIPHER *cipher = NULL;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors("EVP_CIPHER_CTX_new");

    if (NULL == (cipher = EVP_get_cipherbyname(modeName))) handleErrors("Invalid cipher name");

    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL))
        handleErrors("EVP_DecryptInit_ex");

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrors("EVP_CIPHER_CTX_ctrl");

    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors("EVP_DecryptInit_ex");

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrors("EVP_DecryptUpdate AAD");

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors("EVP_DecryptUpdate msg");
    plaintext_len = len;

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len, tag))
        handleErrors("EVP_CIPHER_CTX_ctrl");

    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0) {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    } else {
        /* Verify failed */
        return -1;
    }
}