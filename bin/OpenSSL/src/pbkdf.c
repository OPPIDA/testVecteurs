// Author : Florian Picca <florian.picca@oppida.fr>
// Date : October 2019
#include "util.h"
#include <openssl/evp.h>

static void derive(unsigned char *password, unsigned int password_len, unsigned char* salt, unsigned int salt_len, unsigned int iterations, unsigned int dklen, unsigned char*digest, char* hash_name);

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

    derive(password, password_len, salt, salt_len, iterations, dklen, digest, hash_name);

    unsigned char *hex = stoh(digest, dklen);

    printf("%s\n", hex);

    //free
    free(hex);
    free(password);
    free(salt);
}

static void derive(unsigned char *password, unsigned int password_len, unsigned char* salt, unsigned int salt_len, unsigned int iterations, unsigned int dklen, unsigned char*digest, char* hash_name) {

    OpenSSL_add_all_digests();

    const EVP_MD* md = NULL;
    if (NULL == (md = EVP_get_digestbyname(hash_name))) handleErrors("Invalid hash name");

    if (1 != PKCS5_PBKDF2_HMAC((const char*)password, password_len, salt, salt_len, iterations, md, dklen, digest)) handleErrors("Hash computation failed");

}