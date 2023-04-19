// Authors : Mikael Benhaiem <mikael.benhaiem@oppida.fr>, Florian Picca <florian.picca@oppida.fr>
// Date : October 2019
#include "util.h"
#include <openssl/evp.h>

/*
 This function computes HMAC tags for a given key, message and hash function.
 The result is stored in digest and it's size in digestLen.
*/
static void digest_message(const unsigned char *message, size_t messageLen,const unsigned char *key, size_t keyLen, unsigned char **digest, size_t *digestLen,char *hashName);


void hmac_run(int argc,char *argv[])
{
    if(argc != 4)
    {
        handleErrors("Invalid argument number.");
    }

    OpenSSL_add_all_digests();

    // convert args to byte string

    unsigned char *key = htos((unsigned char*)argv[1]);
    unsigned int keyLen = strlen(argv[1])/2;
    unsigned char *msg = htos((unsigned char*)argv[2]);
    unsigned int msgLen = strlen(argv[2])/2;

    unsigned char *digest;
    size_t digestLen;

    digest_message(msg, msgLen, key, keyLen, &digest, &digestLen, argv[3]);

    unsigned char *hexdigest = stoh(digest, digestLen);

    printf("%s\n", hexdigest);

    //free
    OPENSSL_free(digest);
    free(msg);
    free(key);
    free(hexdigest);
}

static void digest_message(const unsigned char *message, size_t messageLen,const unsigned char *key, size_t keyLen, unsigned char **digest, size_t *digestLen,char *hashName)
{
    EVP_MD_CTX *mdctx;
    const EVP_MD* md = NULL;
    EVP_PKEY *pkey = NULL;
    
    if(!(mdctx = EVP_MD_CTX_create())) handleErrors("EVP_MD_CTX_create");

    if (NULL == (md = EVP_get_digestbyname(hashName))) handleErrors("Invalid hash name");

    if(!(pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, keyLen))) handleErrors("EVP_PKEY_new_mac_key");
        
    if(1 != EVP_DigestInit_ex(mdctx, md, NULL)) handleErrors("DigestInit_ex");
    
    if(1 != EVP_DigestSignInit(mdctx, NULL, md, NULL, pkey)) handleErrors("EVP_DigestSignInit");

    if(1 != EVP_DigestSignUpdate(mdctx, message, messageLen)) handleErrors("EVP_DigestSignUpdate");

    if(1 != EVP_DigestSignFinal(mdctx, NULL, digestLen)) handleErrors("EVP_DigestSignFinal");
        
    if((*digest = (unsigned char *)OPENSSL_malloc(sizeof(unsigned char) * (*digestLen))) == NULL) handleErrors("malloc");
		
    if(1 != EVP_DigestSignFinal(mdctx, *digest, digestLen)) handleErrors("EVP_DigestSignFinal2");

    EVP_MD_CTX_destroy(mdctx);
}