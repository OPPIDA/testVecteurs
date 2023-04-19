// Author : Florian Picca <florian.picca@oppida.fr>
// Date : October 2019
#include "util.h"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>

static void ecdh_exchange(char *curvename, unsigned char *da, unsigned char *xb, unsigned char *yb, unsigned char **xa, unsigned char **ya, unsigned char **sk);

/* Arguments in order :
        - curve name : The name of the curve : P-192, P-224, P-256, P-384, P-521
        - da : A's private key in hexadecimal form
        - xb : B's public key's X coordinate in hexadecimal form
        - yb : B's public key's Y coordinate in hexadecimal form
*/
void ecdh_run(int argc,char *argv[])
{
    if (argc != 5) {
        handleErrors("Invalid argument number.");
    }

    unsigned char *sk, *ya, *xa;
    ecdh_exchange(argv[1], (unsigned char*)argv[2], (unsigned char*)argv[3], (unsigned char*)argv[4], &xa, &ya, &sk);

    printf("%s %s %s\n", xa, ya, sk);

    // free
    free(sk);
    free(ya);
    free(xa);
}

/*
This function simulates an ECDH exchange given A's private key (da) and B's public key (xb, yb) in hexadecimal.
The coordinates of A's public key are stored in (xa, xb) in hexadecimal.
The shared key is stored in sk in hexadecimal.
*/
static void ecdh_exchange(char *curvename, unsigned char *da, unsigned char *xb, unsigned char *yb, unsigned char **xa, unsigned char **ya, unsigned char **sk)
{
    // choose the right curve depending on the name
    int curveid = 0;
    if (!strcmp(curvename, "secp192r1")) curveid = NID_X9_62_prime192v1;
    else if (!strcmp(curvename, "secp224r1")) curveid = NID_secp224r1;
    else if (!strcmp(curvename, "secp256r1")) curveid = NID_X9_62_prime256v1;
    else if (!strcmp(curvename, "secp384r1")) curveid = NID_secp384r1;
    else if (!strcmp(curvename, "secp521r1")) curveid = NID_secp521r1;
    else if (!strcmp(curvename, "brainpoolP256r1")) curveid = NID_brainpoolP256r1;
    else if (!strcmp(curvename, "brainpoolP384r1")) curveid = NID_brainpoolP384r1;
    else if (!strcmp(curvename, "brainpoolP512r1")) curveid = NID_brainpoolP512r1;
    else handleErrors("Invalid curve name");

    // Create an Elliptic Curve and a Key object
    EC_KEY *Akey, *Bkey = NULL;
    EC_GROUP *curve = NULL;
	if (NULL == (Akey = EC_KEY_new_by_curve_name(curveid))) handleErrors("EC creation failed");
	if (NULL == (Bkey = EC_KEY_new_by_curve_name(curveid))) handleErrors("EC creation failed");
	if(NULL == (curve = EC_GROUP_new_by_curve_name(curveid))) handleErrors("curve creation failed");

    // Convert arguments to bignums
	BIGNUM *bda = NULL;
	if (0 == BN_hex2bn(&bda, (char*)da)) handleErrors("da convertion to bignum failed");
	BIGNUM *bxb = NULL;
	if (0 == BN_hex2bn(&bxb, (char*)xb)) handleErrors("xb convertion to bignum failed");
	BIGNUM *byb = NULL;
	if (0 == BN_hex2bn(&byb, (char*)yb)) handleErrors("yb convertion to bignum failed");

    // Construct A's private and public key
    EC_POINT *Apub = NULL;
    if (NULL == (Apub = EC_POINT_new(curve))) handleErrors("Apub initialisation failed");
    if (1 != EC_KEY_set_private_key(Akey, bda)) handleErrors("Aprv setup failed");
    if (1 != EC_POINT_mul(curve, Apub, bda, NULL, NULL, NULL)) handleErrors("Apub computation failed");

    // Extract the coordinates from A's public key
    BIGNUM *bxa = NULL;
    if (NULL == (bxa = BN_new())) handleErrors("xa initialisation failed");
    BIGNUM *bya = NULL;
    if (NULL == (bya = BN_new())) handleErrors("ya initialisation failed");
    // use EC_POINT_get_affine_coordinates_GFp for backwards compatibility
    if (1 != EC_POINT_get_affine_coordinates_GFp(curve, Apub, bxa, bya, NULL)) handleErrors("getting coordinates of Apub failed");
    *xa = (unsigned char*)BN_bn2hex(bxa);
    *ya = (unsigned char*)BN_bn2hex(bya);

    // generate B's public key from the given coordinates
    EC_POINT *Bpub = NULL;
    if (NULL == (Bpub = EC_POINT_new(curve))) handleErrors("Bpub initialisation failed");
    // use EC_POINT_set_affine_coordinates_GFp for backwards compatibility
    if (1 != EC_POINT_set_affine_coordinates_GFp(curve, Bpub, bxb, byb, NULL)) handleErrors("setting coordinates of Bpub failed");

    /* Calculate the size of the buffer for the shared secret */
    unsigned char *sk_bin = NULL;
	int field_size = EC_GROUP_get_degree(EC_KEY_get0_group(Akey));
	int sk_len = (field_size+7)/8;

	/* Allocate the memory for the shared secret */
	if(NULL == (sk_bin = OPENSSL_malloc(sk_len))) handleErrors("failed to allocate sk");

	/* Derive the shared secret */
	if (0 >= (sk_len = ECDH_compute_key(sk_bin, sk_len, Bpub, Akey, NULL))) handleErrors("sk computation failed");

    // convert sk to hex
    *sk = stoh(sk_bin, sk_len);

    // free
    OPENSSL_free(sk_bin);
    BN_free(bda);
    BN_free(bxa);
    BN_free(bya);
    BN_free(bxb);
    BN_free(byb);
    EC_POINT_free(Bpub);
    EC_POINT_free(Apub);
    EC_KEY_free(Akey);
    EC_KEY_free(Bkey);
}
