// Author : Florian Picca <florian.picca@oppida.fr>
// Date : September 2020
#include "util.h"
#include <mbedtls/md.h>

static int digest_message(const unsigned char *message, size_t messageLen,const unsigned char *key, size_t keyLen, unsigned char **digest, size_t *digestLen,char *hashName);

// Do not edit this function unless you know what you are doing
void hmac_run(int argc,char *argv[])
{
    if(argc != 4)
    {
        handleErrors("Invalid argument number.");
    }

    // convert args to byte string

    unsigned char *key = htos((unsigned char*)argv[1]);
    unsigned int keyLen = strlen(argv[1])/2;
    unsigned char *msg = htos((unsigned char*)argv[2]);
    unsigned int msgLen = strlen(argv[2])/2;

    unsigned char *digest;
    size_t digestLen;

    int success = digest_message(msg, msgLen, key, keyLen, &digest, &digestLen, argv[3]);

    if (success != NOT_IMPLEMENTED_ERROR) {
        unsigned char *hexdigest = stoh(digest, digestLen);
        printf("%s\n", hexdigest);
        free(hexdigest);
        free(digest);
    }
    else {
        skip();
    }
    //free
    free(msg);
    free(key);
}

/*
 This function computes HMAC tags for a given key, message and hash function.
 hash names follow the format of OpenSSL : SHA1, SHA256, SHA384, ...
 The result is stored in digest and it's size in digestLen.
*/
static int digest_message(const unsigned char *message, size_t messageLen,const unsigned char *key, size_t keyLen, unsigned char **digest, size_t *digestLen,char *hashName)
{
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_string(hashName);
    if (md_info == NULL) {handleErrors("mbedtls_md_info_from_string");}
    *digestLen = mbedtls_md_get_size(md_info);
    *digest = malloc(*digestLen);
	if (mbedtls_md_hmac(md_info, key, keyLen, message, messageLen, *digest) != 0) {handleErrors("mbedtls_md");}
	return 0;
}