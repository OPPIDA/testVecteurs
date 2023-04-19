// Author : Florian Picca <florian.picca@oppida.fr>
// Date : September 2020
#include "util.h"
#include <mbedtls/rsa.h>
#include <mbedtls/bignum.h>
#include <mbedtls/md.h>


static int pkcs1v15Verify(unsigned char *n, unsigned char *e, char *hashName, unsigned char *hash, unsigned char *signature);

// Do not edit this function unless you know what you are doing
void rsa_run(int argc,char *argv[])
{
    if (argc != 9) {
        handleErrors("Invalid argument number.");
    }
    unsigned char *n_hex = (unsigned char *)argv[1];
    unsigned char *e_hex = (unsigned char *)argv[2];
    unsigned char *d_hex = (unsigned char *)argv[3];
    // In case of signatures (sign and verify) this is the hash value of the message
    unsigned char *message_hex = (unsigned char *)argv[4];
    unsigned char *signature_hex = (unsigned char *)argv[5];
    char *hashName = argv[6];
    char *paddingName = argv[7];
    // E/D/S/V
    char *operation = argv[8];

    if (!strcmp(operation, "E")) {
    }
    else if (!strcmp(operation, "D")) {
    }
    else if (!strcmp(operation, "S")) {
    }
    else if (!strcmp(operation, "V")) {
        if (!strcmp(paddingName, "PKCS1v1.5")) {
            int res = pkcs1v15Verify(n_hex, e_hex, hashName, message_hex, signature_hex);

            if (res == NOT_IMPLEMENTED_ERROR) {
                skip();
            }
            else {
                if (res) {
                    printf("good\n");
                }
                else {
                    printf("fail\n");
                }
            }
        }
    }
    else {
        handleErrors("Unknown operation. Must be one of E/D/S/V.");
    }
}

// Return 1 if successful, 0 otherwise
static int pkcs1v15Verify(unsigned char *n, unsigned char *e, char *hashName, unsigned char *hash, unsigned char *signature) {

    // Convert inputs from hex to byte string
    unsigned char *n_bin = htos(n);
    size_t n_len = strlen((char *)n)/2;
    unsigned char *e_bin = htos(e);
    size_t e_len = strlen((char *)e)/2;
    unsigned char *hash_bin = htos(hash);
    size_t hash_len = strlen((char *)hash)/2;
    unsigned char *signature_bin = htos(signature);

    mbedtls_mpi N, E;

    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&E);
    mbedtls_mpi_read_binary(&N, n_bin, n_len);
    mbedtls_mpi_read_binary(&E, e_bin, e_len);

    mbedtls_rsa_context ctx;

#if MBEDTLS_VERSION_NUMBER < 0x03000000
    mbedtls_rsa_init(&ctx, MBEDTLS_RSA_PKCS_V15, 0);
#else
    mbedtls_rsa_init(&ctx);
#endif
    
    // construct public key object
    if (mbedtls_rsa_import(&ctx, &N, NULL, NULL, NULL, &E) != 0) {handleErrors("mbedtls_rsa_import");}

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_string(hashName);
    if (md_info == NULL) {handleErrors("mbedtls_md_info_from_string");}
    mbedtls_md_type_t type = mbedtls_md_get_type(md_info);


    //verify signature using PKCS1v1.5 by default
#if MBEDTLS_VERSION_NUMBER < 0x03000000
    int ret = mbedtls_rsa_rsassa_pkcs1_v15_verify(&ctx, NULL, NULL, MBEDTLS_RSA_PUBLIC, type, hash_len, hash_bin, signature_bin);
#else
    int ret = mbedtls_rsa_rsassa_pkcs1_v15_verify(&ctx, type, hash_len, hash_bin, signature_bin);
#endif

    mbedtls_rsa_free(&ctx);
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&E);
    free(n_bin);
    free(e_bin);
    free(hash_bin);
    free(signature_bin);
    if (ret == 0) {return 1;}
    return 0;
}