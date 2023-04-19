// Author : Florian Picca <florian.picca@oppida.fr>
// Date : July 2020
#include "util.h"
#include "commands.h"
#include <stdio.h>
#include <string.h>

int parseArgs(char * line, char *args[]) {
    // Add args to the array
    int i = 0;
    while ( i < 20 && (args[i] = strsep(&line,",")) != NULL) { i++; }
    return i;
}


int main(int argc,char *argv[])
{
    char *line = NULL;
    size_t len = 0;
    char *args[20] = {NULL};

    //commands : QUIT VERSION PBKDF HMAC HASHER GCM ECDSA ECDH DH BLOCKCIPHER RSA

    while (1) {
        //Read user input
        if (getline(&line, &len, stdin) == -1) { handleErrors("getline"); }
        line[strcspn(line, "\n")] = 0;
        // quit command
        if (strcmp(line, "QUIT") == 0) { break; }

        // Parse args
        // Copy the line buffer first
        char *line_copy = strdup(line);
        int num_args = parseArgs(line_copy, args);
        //Replace #
        for (int i=0; i<num_args; i++) {
            if (strcmp(args[i], "#") == 0) {
                args[i] = "\0";
            }
        }

        // commands
        if (strcmp(args[0], "VERSION") == 0) { print_version(); }
        if (strcmp(args[0], "PBKDF") == 0) { pbkdf_run(num_args, args); }
        if (strcmp(args[0], "HMAC") == 0) { hmac_run(num_args, args); }
        if (strcmp(args[0], "HASHER") == 0) { hasher_run(num_args, args); }
        if (strcmp(args[0], "GCM") == 0) { gcm_run(num_args, args); }
        if (strcmp(args[0], "ECDSA") == 0) { ecdsa_run(num_args, args); }
        if (strcmp(args[0], "ECDH") == 0) { ecdh_run(num_args, args); }
        if (strcmp(args[0], "DH") == 0) { dh_run(num_args, args); }
        if (strcmp(args[0], "BLOCKCIPHER") == 0) { blockcipher_run(num_args, args); }
        if (strcmp(args[0], "RSA") == 0) { rsa_run(num_args, args); }

        printf(">\n");
        fflush(stdout);
        free(line_copy);
    }
    free(line);
    return 0;
}