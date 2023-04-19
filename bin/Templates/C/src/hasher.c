// Authors : Mikael Benhaiem <mikael.benhaiem@oppida.fr>, Florian Picca <florian.picca@oppida.fr>
// Date : October 2019
#include "util.h"

static int digest_message(const unsigned char *message, size_t message_len, unsigned char **digest, unsigned int *digest_len,char *hashName);
static int digest_messageMCT(const unsigned char *message, size_t message_len, char *hashName);

// Do not edit this function unless you know what you are doing
void hasher_run(int argc,char *argv[])
{
    if (argc != 4) {
        handleErrors("Invalid argument number.");
    }

    // Convert input as hex to byte string
    unsigned char *msg = htos((unsigned char*)argv[1]);

    // Normal hash
    if (!strcmp(argv[3], "")) {
        unsigned char *digest;
        unsigned int digest_len;
        int success = digest_message(msg, strlen(argv[1])/2, &digest, &digest_len, argv[2]);
        if (success == NOT_IMPLEMENTED_ERROR) {
            skip();
            goto end;
        }
        // Convert the resulting hash to hex and print it
        unsigned char *hexdigest = stoh(digest, digest_len);
        printf("%s\n", hexdigest);

        //free malloc'ed variables
        free(hexdigest);
        free(digest);
    }
    // MCT
    else if (!strcmp(argv[3], "MCT")) {
        int success = digest_messageMCT(msg,  strlen(argv[1])/2, argv[2]);
        if (success == NOT_IMPLEMENTED_ERROR) {
            skip();
            goto end;
        }
    }
    else handleErrors("Invalid last argument, must be 'MCT' or empty.");
end:
    //free malloc'ed variables
    free(msg);
}

/*
This function hashes the message using a given hash function and the result is written in digest.
This function must allocate the digest buffer.
hash names follow the format of OpenSSL : SHA1, SHA256, SHA384, ...
*/
static int digest_message(const unsigned char *message, size_t message_len, unsigned char **digest, unsigned int *digest_len,char *hashName)
{
	return NOT_IMPLEMENTED_ERROR;
}

/*
This function performs MCT test starting with the message, using a given hash function and prints all the checkpoint values on STDOUT.
hash names follow the format of OpenSSL : SHA1, SHA256, SHA384, ...
There are 100 checkpoint, a checkpoint is reached after 1 000 iterations.
*/
static int digest_messageMCT(const unsigned char *message, size_t message_len, char *hashName)
{
    return NOT_IMPLEMENTED_ERROR;
}