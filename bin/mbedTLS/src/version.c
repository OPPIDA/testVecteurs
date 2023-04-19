// Author : Florian Picca <florian.picca@oppida.fr>
// Date : December 2019
#include <stdio.h>
#include <mbedtls/version.h>

/*
This function prints the version of the library being tested.
The version number must be retrieved at run time to be certain that the version number displayed during the tests
is the real one and not the one from compile time or hardcoded.
If there is no need for this, leave it as it is.
*/
void print_version()
{
    char version[20];
    mbedtls_version_get_string_full(version);
    printf("%s\n", version);
}