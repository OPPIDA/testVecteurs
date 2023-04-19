// Author : Florian Picca <florian.picca@oppida.fr>
// Date : October 2019
#include "util.h"

static int derive(unsigned char *password, unsigned int password_len, unsigned char* salt, unsigned int salt_len, unsigned int iterations, unsigned int dklen, unsigned char*digest, char* hash_name);

// Do not edit this function unless you know what you are doing
void pbkdf_run(int argc,char *argv[])
{
    if (argc != 6) {
        handleErrors("Invalid argument number.");
    }

    unsigned char *password = htos((unsigned char*)argv[1]);
    unsigned int password_len = strlen(argv[1])/2;
    unsigned char *salt = htos((unsigned char*)argv[2]);
    unsigned int salt_len = strlen(argv[2])/2;
    unsigned int iterations = atoi(argv[3]);
    unsigned int dklen = atoi(argv[4]);
    char *hash_name = argv[5];
    unsigned char digest[dklen];

    int success = derive(password, password_len, salt, salt_len, iterations, dklen, digest, hash_name);

    if (success != NOT_IMPLEMENTED_ERROR) {
        unsigned char *hex = stoh(digest, dklen);
        printf("%s\n", hex);
        free(hex);
    }
    else {
        skip();
    }
    free(password);
    free(salt);
}

/*
This function derives keys from passwords using PBKF2 given a password, salt, number of iterations and output key size.
hash names follow the format of OpenSSL : SHA1, SHA256, SHA384, ...
The result is stored in digest.
*/
static int derive(unsigned char *password, unsigned int password_len, unsigned char* salt, unsigned int salt_len, unsigned int iterations, unsigned int dklen, unsigned char*digest, char* hash_name) {
    return NOT_IMPLEMENTED_ERROR;
}