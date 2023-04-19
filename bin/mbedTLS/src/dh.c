// Author : Florian Picca <florian.picca@oppida.fr>
// Date : October 2019
#include "util.h"

static int dh_exchange(unsigned char *p, unsigned char *g, unsigned char *da, unsigned char *db, unsigned char **ya, unsigned char **yb, unsigned char **sk);
static int digest_message(const unsigned char *message, size_t message_len, unsigned char **digest, unsigned int *digest_len,char *hashName);

// Do not edit this function unless you know what you are doing
void dh_run(int argc,char *argv[])
{
    if (argc != 6) {
        handleErrors("Invalid argument number.");
    }

    unsigned char *sk, *ya, *yb;
    int success = dh_exchange((unsigned char*)argv[1], (unsigned char*)argv[2], (unsigned char*)argv[3], (unsigned char*)argv[4], &ya, &yb, &sk);

    if (success != NOT_IMPLEMENTED_ERROR) {
        if (!strcmp(argv[5], "")) {
            printf("%s %s %s\n", ya, yb, sk);
        }
        else {
            // Hash sk with the given hashfunction

            unsigned char *digest = NULL;
            unsigned char *msg = htos(sk);
            unsigned int digest_len;
            digest_message(msg, strlen((char*)sk)/2, &digest, &digest_len, argv[5]);

            // Convert the resulting hash to hex and print it
            unsigned char *hexdigest = stoh(digest, digest_len);
            printf("%s %s %s %s\n", ya, yb, sk, hexdigest);

            // free
            free(msg);
            free(hexdigest);
            free(digest);
        }
        // free
        free(sk);
        free(ya);
        free(yb);
    }
    else {
        skip();
    }
}

/*
This function simulates a DH exchange given the group's parameters and the two parties' private keys in hexadecimal.
A's public key is stored in ya in hexadecimal.
B's public key is stored in yb in hexadecimal.
The shared key is stored in sk in hexadecimal.
*/
static int dh_exchange(unsigned char *p, unsigned char *g, unsigned char *da, unsigned char *db, unsigned char **ya, unsigned char **yb, unsigned char **sk)
{
    return NOT_IMPLEMENTED_ERROR;
}

/*
This function hashes the message using a given hash function and the result is written in digest
Copied from hasher.c
*/
static int digest_message(const unsigned char *message, size_t message_len, unsigned char **digest, unsigned int *digest_len,char *hashName)
{
	return NOT_IMPLEMENTED_ERROR;
}