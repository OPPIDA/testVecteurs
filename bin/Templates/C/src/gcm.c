// Author : Florian Picca <florian.picca@oppida.fr>
// Date : January 2020
#include "util.h"

static int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *aad, int aad_len, unsigned char *key, unsigned char *iv, int iv_len, unsigned char *ciphertext, unsigned char *tag, int tag_len, char *modeName);
static int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad, int aad_len, unsigned char *tag, int tag_len, unsigned char *key, unsigned char *iv, int iv_len, unsigned char *plaintext, char *modeName);

// Do not edit this function unless you know what you are doing
void gcm_run(int argc,char *argv[])
{
    if (argc != 8) {
        handleErrors("Invalid argument number.");
    }

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
        if (output_len == NOT_IMPLEMENTED_ERROR) {
            skip();
            goto end;
        }
        output_hex = stoh(output, output_len);
        ICV_hex = stoh(ICV, tag_len);

        printf("%s,%s\n", output_hex, ICV_hex);
        free(ICV_hex);
        free(output_hex);
    }
    else if (!strcmp(argv[7], "D")) {
        output_len = decrypt(message, message_len, header, header_len, tag, tag_len, key, iv, iv_len, output, argv[6]);
        if (output_len == NOT_IMPLEMENTED_ERROR) {
            skip();
            goto end;
        }
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
end:
    // free
    free(message);
    free(key);
    free(iv);
}

/*
This function encrypts the plaintext with the key, nonce and additional data.
The cipher is chosen by it's name.
cipher names follow the OpenSSl syntax in lower case : aes-256-gcm, aes-128-gcm, ...
The result is stored in ciphertext, the ICV in tag, the ICV length in tag_len and the function returns the length of the result.
*/
static int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *aad, int aad_len, unsigned char *key, unsigned char *iv, int iv_len, unsigned char *ciphertext, unsigned char *tag, int tag_len, char *modeName)
{
    return NOT_IMPLEMENTED_ERROR;
}

/*
This function decrypts the ciphertext with the key, nonce, tag and additional data..
iv can be empty.
The cipher is chosen by it's name.
cipher names follow the OpenSSl syntax in lower case : aes-256-gcm, aes-128-gcm, ...
The result is stored in plaintext and the function returns the length of the result.
*/
static int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad, int aad_len, unsigned char *tag, int tag_len, unsigned char *key, unsigned char *iv, int iv_len, unsigned char *plaintext, char *modeName)
{
    return NOT_IMPLEMENTED_ERROR;
}