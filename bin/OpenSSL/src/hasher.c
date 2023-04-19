// Authors : Mikael Benhaiem <mikael.benhaiem@oppida.fr>, Florian Picca <florian.picca@oppida.fr>
// Date : October 2019
#include "util.h"
#include <openssl/evp.h>
#include <openssl/sha.h>

static void digest_message(const unsigned char *message, size_t message_len, unsigned char **digest, unsigned int *digest_len,char *hashName);
static void digest_messageMCT(const unsigned char *message, size_t message_len, char *hashName);

/* Arguments in order :
        - message : hex string representing the message to hash
        - hash name : string representing the hash's name : SHA1, SHA224, SHA256, SHA384, SHA512 others are supported as well (MD5, SHA3-512, ...)
        - MCT : "MCT" if an MCT test is required, empty otherwise
*/
void hasher_run(int argc,char *argv[])
{
    if (argc != 4) {
        handleErrors("Invalid argument number.");
    }

    OpenSSL_add_all_digests();

    // Convert input as hex to byte string
    unsigned char *msg = htos((unsigned char*)argv[1]);

    // Normal hash
    if (!strcmp(argv[3], "")) {
         unsigned char *digest;
        unsigned int digest_len;
        digest_message(msg, strlen(argv[1])/2, &digest, &digest_len, argv[2]);

        // Convert the resulting hash to hex and print it
        unsigned char *hexdigest = stoh(digest, digest_len);
        printf("%s\n", hexdigest);

        //free malloc'ed variables
        free(hexdigest);
        OPENSSL_free(digest);
    }
    // MCT
    else if (!strcmp(argv[3], "MCT")) {
        digest_messageMCT(msg,  strlen(argv[1])/2, argv[2]);
    }
    else handleErrors("Invalid last argument, must be 'MCT' or empty.");

    //free malloc'ed variables
    free(msg);
}

/*
This function hashes the message using a given hash function and the result is written in digest
*/
static void digest_message(const unsigned char *message, size_t message_len, unsigned char **digest, unsigned int *digest_len,char *hashName)
{
		EVP_MD_CTX *mdctx;
	const EVP_MD* md = NULL;

	if((mdctx = EVP_MD_CTX_create()) == NULL)
		handleErrors("MD_CTX_create");

	md = EVP_get_digestbyname(hashName);

	if(1 != EVP_DigestInit_ex(mdctx, md, NULL))
		handleErrors("DigestInit_ex");

	if(1 != EVP_DigestUpdate(mdctx, message, message_len))
		handleErrors("DigestUpdate");

	if((*digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(md))) == NULL)
		handleErrors("malloc");

	if(1 != EVP_DigestFinal_ex(mdctx, *digest, digest_len))
		handleErrors("DigestFinal_ex");

	EVP_MD_CTX_destroy(mdctx);
}

/*
This function performs MCT test starting with the message, using a given hash function and prints all the checkpoint values on STDOUT.
*/
static void digest_messageMCT(const unsigned char *message, size_t message_len, char *hashName)
{
	EVP_MD_CTX *mdctx;
	const EVP_MD* md = NULL;

	if((mdctx = EVP_MD_CTX_create()) == NULL)
		handleErrors("MD_CTX_create");

	md = EVP_get_digestbyname(hashName);

    // Init the digest with the given message
	unsigned char *digest;
	unsigned int digest_len;

	if((digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(md))) == NULL)
		handleErrors("malloc");

	// The seed struct, 3 messages of length message_len in a row
	struct seed {
	    unsigned char s1[message_len];
	    unsigned char s2[message_len];
	    unsigned char s3[message_len];
	};

	// Init the digest with the given message
	//digest = (unsigned char*)message;
	memcpy(digest, message, EVP_MD_size(md));

    // 100 checkpoints
	int i, j;
	struct seed s;
	for (i= 0; i<100; i++) {
	    // the seed is initialized with the last digest repeated 3 times
	    memcpy(s.s1, digest, message_len);
	    memcpy(s.s2, digest, message_len);
	    memcpy(s.s3, digest, message_len);

        // checkpoint every 1000 iterations
        for (j= 0; j<1000; j++) {

            // compute the hash of seed (3 strings in a row) and put it in digest
            if (1 != EVP_DigestInit_ex(mdctx, md, NULL)) handleErrors("DigestInit_ex");
            if (1 != EVP_DigestUpdate(mdctx, (unsigned char *)&s, sizeof(s))) handleErrors("DigestUpdate");
            if (1 != EVP_DigestFinal_ex(mdctx, digest, &digest_len)) handleErrors("DigestFinal_ex");

            // rotate the seed
            memcpy(s.s1, s.s2, message_len);
	        memcpy(s.s2, s.s3, message_len);
	        memcpy(s.s3, digest, message_len);

        }

        // print the checkpoint
        unsigned char *hexdigest = stoh(digest, digest_len);
        printf("%s\n", hexdigest);
        free(hexdigest);

	}

    // free
	EVP_MD_CTX_destroy(mdctx);
}