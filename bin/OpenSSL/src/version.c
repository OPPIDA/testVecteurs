// Author : Florian Picca <florian.picca@oppida.fr>
// Date : December 2019

#include <openssl/ssl.h>
#include <stdio.h>

void print_version()
{
    printf("%s\n", SSLeay_version(SSLEAY_VERSION));
}