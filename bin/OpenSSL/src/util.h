// Author : Florian Picca <florian.picca@oppida.fr>
// Date : October 2019
#ifndef UTIL_H
#define UTIL_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
//Error code indicating an unimplemented feature
#define NOT_IMPLEMENTED_ERROR -1337

/*
This function converts an hexadecimal string into a byte string and returns a pointer to the newly created byte string.
You have to call free() on the created string when you don't need it anymore.

Arguments :
    - hexstring : A pointer to the hex string to convert.
*/
unsigned char *htos(unsigned char *hexString);
/*
This function converts a byte string into it's hexadecimal representation and returns a pointer to the newly created hex string.
You have to call free() on the created string when you don't need it anymore.

Arguments :
    - string : A pointer to the byte string to convert.
    - len : The length of the byte string (the string can contain null bytes)
*/
unsigned char *stoh(unsigned char *string, int len);
/*
This function prints an error message on stderr. The program terminates immediately.
*/
void handleErrors(char *error);

/*
This function prints a message on stderr. Can be used to debug where the errors come from.
*/
void logMsg(char *msg);

/*
This function prints the NOT_IMPLEMENTED_ERROR on stdout.
Tells the python runner a feature hasn't been implemented without terminating.
*/
void skip();

#endif