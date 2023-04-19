// Author : Florian Picca <florian.picca@oppida.fr>
// Date : October 2019
#include "util.h"

static int ecdh_exchange(char *curvename, unsigned char *da, unsigned char *xb, unsigned char *yb, unsigned char **xa, unsigned char **ya, unsigned char **sk);

// Do not edit this function unless you know what you are doing
void ecdh_run(int argc,char *argv[])
{
    if (argc != 5) {
        handleErrors("Invalid argument number.");
    }

    unsigned char *sk, *ya, *xa;
    int success = ecdh_exchange(argv[1], (unsigned char*)argv[2], (unsigned char*)argv[3], (unsigned char*)argv[4], &xa, &ya, &sk);

    if (success != NOT_IMPLEMENTED_ERROR) {
        printf("%s %s %s\n", xa, ya, sk);

        // free
        free(sk);
        free(ya);
        free(xa);
    }
    else {
        skip();
    }
}

/*
This function simulates an ECDH exchange given A's private key (da) and B's public key (xb, yb) in hexadecimal.
The coordinates of A's public key are stored in (xa, xb) in hexadecimal.
The shared key is stored in sk in hexadecimal.
*/
static int ecdh_exchange(char *curvename, unsigned char *da, unsigned char *xb, unsigned char *yb, unsigned char **xa, unsigned char **ya, unsigned char **sk)
{
    return NOT_IMPLEMENTED_ERROR;
}
