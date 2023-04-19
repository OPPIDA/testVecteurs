// Author : Florian Picca <florian.picca@oppida.fr>
// Date : October 2019
#include "util.h"
#include <stdlib.h>
/*
Converts a hex string into a real string.
*/
unsigned char *htos(unsigned char *hexString)
{
    unsigned int nbChars = strlen((char *)hexString);
    if (nbChars % 2 != 0) {
        handleErrors("Hexadecimal string is not a multiple of 2 !");
    }
    unsigned char *hex = malloc(((sizeof(char) * nbChars)/2)+1);
    if (hex == NULL) {
        handleErrors("htos malloc failed");
    }
    char subHexText[2];
    unsigned long i;
    for(i = 0;i < nbChars/2;i++)
    {
        memcpy(subHexText,&hexString[i*2],2);
        sscanf(subHexText,"%2hhx", &hex[i]);
    }
    
    return hex;
}

unsigned char *stoh(unsigned char *string, int len)
{
    int size = (sizeof(char) * len * 2)+1;
    unsigned char *hex = malloc(size);
    if (hex == NULL) {
        handleErrors("stoh malloc failed");
    }
    unsigned int i,j;
    memset(hex,0, size);
    for(i=0,j=0;i<len;i++,j+=2)
    {
        sprintf((char*)hex+j,"%02x",string[i]);
    }
    hex[j]='\0'; /*adding NULL in the end*/

    return hex;
}

void handleErrors(char *error)
{
	fprintf(stderr, "Error : %s\n",error);
    exit(EXIT_FAILURE);
}

void logMsg(char *msg)
{
	fprintf(stderr, "%s\n",msg);
}

void skip()
{
    printf("NOT_IMPLEMENTED\n");
}