// Author : Florian Picca <florian.picca@oppida.fr>
// Date : April 2020
#include "util.h"

static int ecdsa_sign(char *curvename, unsigned char *k, unsigned char *d, unsigned char *hash,  unsigned char **r,  unsigned char **s);

// Do not edit this function unless you know what you are doing
void ecdsa_run(int argc,char *argv[])
{
    if (argc != 5) {
        handleErrors("Invalid argument number.");
    }

    char *curvename = argv[1];
    unsigned char* Msg = (unsigned char*)argv[2];
    unsigned char* d = (unsigned char*)argv[3];
    unsigned char* k = (unsigned char*)argv[4];

    unsigned char *r, *s;

    int success = ecdsa_sign(curvename, k, d, Msg, &r, &s);

    if (success != NOT_IMPLEMENTED_ERROR) {
         printf("%s %s\n", r, s);

        // free
        free(r);
        free(s);
    }
    else {
        skip();
    }
}


static int ecdsa_sign(char *curvename, unsigned char *k, unsigned char *d, unsigned char *hash,  unsigned char **r,  unsigned char **s) {
    return NOT_IMPLEMENTED_ERROR;
}