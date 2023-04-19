// Author : Florian Picca <florian.picca@oppida.fr>
// Date : September 2020
#include "util.h"
#include <openssl/evp.h>


static int pkcs1v15Verify(unsigned char *n, unsigned char *e, char *hashName, unsigned char *hash, unsigned char *signature);

// Do not edit this function unless you know what you are doing
void rsa_run(int argc,char *argv[])
{
    if (argc != 9) {
        handleErrors("Invalid argument number.");
    }
    unsigned char *n_hex = (unsigned char *)argv[1];
    unsigned char *e_hex = (unsigned char *)argv[2];
    //unsigned char *d_hex = (unsigned char *)argv[3];
    // In case of signatures (sign and verify) this is the hash value of the message
    unsigned char *message_hex = (unsigned char *)argv[4];
    unsigned char *signature_hex = (unsigned char *)argv[5];
    char *hashName = argv[6];
    char *paddingName = argv[7];
    // E/D/S/V
    char *operation = argv[8];

    if (!strcmp(operation, "E")) {
    }
    else if (!strcmp(operation, "D")) {
    }
    else if (!strcmp(operation, "S")) {
    }
    else if (!strcmp(operation, "V")) {
        if (!strcmp(paddingName, "PKCS1v1.5")) {
            int res = pkcs1v15Verify(n_hex, e_hex, hashName, message_hex, signature_hex);

            if (res == NOT_IMPLEMENTED_ERROR) {
                skip();
            }
            else {
                if (res) {
                    printf("good\n");
                }
                else {
                    printf("fail\n");
                }
            }
        }
    }
    else {
        handleErrors("Unknown operation. Must be one of E/D/S/V.");
    }
}

// Return 1 if successful, 0 otherwise
static int pkcs1v15Verify(unsigned char *n, unsigned char *e, char *hashName, unsigned char *hash, unsigned char *signature) {

    // Convert inputs from hex to byte string
    /*
    unsigned char *n_bin = htos(n);
    size_t n_len = strlen((char *)n)/2;
    unsigned char *e_bin = htos(e);
    size_t e_len = strlen((char *)e)/2;
    unsigned char *hash_bin = htos(hash);
    size_t hash_len = strlen((char *)hash)/2;
    unsigned char *signature_bin = htos(signature);

    free(n_bin);
    free(e_bin);
    free(hash_bin);
    free(signature_bin);
    */
    return NOT_IMPLEMENTED_ERROR;
}