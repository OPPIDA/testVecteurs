// Author : Florian Picca <florian.picca@oppida.fr>
// Date : October 2019
#include "util.h"
#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/sha.h>

// Because some functions where not present in older OpenSSL versions
#if OPENSSL_VERSION_NUMBER < 0x10101000L
const BIGNUM *DH_get0_pub_key(const DH *dh);
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L
int DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g);
int DH_set0_key(DH *dh, BIGNUM *pub_key, BIGNUM *priv_key);
void DH_get0_key(const DH *dh, const BIGNUM **pub_key, const BIGNUM **priv_key);
#endif

static void dh_exchange(unsigned char *p, unsigned char *g, unsigned char *da, unsigned char *db, unsigned char **ya, unsigned char **yb, unsigned char **sk);
static void digest_message(const unsigned char *message, size_t message_len, unsigned char **digest, unsigned int *digest_len,char *hashName);

/* Arguments in order :
        - p : The group's prime modulus in hexadecimal form
        - g : The group's generator in hexadecimal form
        - da : A's private value in hexadecimal form
        - db : B's private value in hexadecimal form
        - hash name : The name of the hash function to use to derive sk
*/
void dh_run(int argc,char *argv[])
{
    if (argc != 6) {
        handleErrors("Invalid argument number.");
    }

    unsigned char *sk, *ya, *yb;
    dh_exchange((unsigned char*)argv[1], (unsigned char*)argv[2], (unsigned char*)argv[3], (unsigned char*)argv[4], &ya, &yb, &sk);

    if (!strcmp(argv[5], "")) {
        printf("%s %s %s\n", ya, yb, sk);
    }
    else {
        // Hash sk with the given hashfunction
        OpenSSL_add_all_digests();

        unsigned char *digest = NULL;
        unsigned char *msg = htos(sk);
        unsigned int digest_len;
        digest_message(msg, strlen((char*)sk)/2, &digest, &digest_len, argv[5]);

        // Convert the resulting hash to hex and print it
        unsigned char *hexdigest = stoh(digest, digest_len);
        printf("%s %s %s %s\n", ya, yb, sk, hexdigest);

        // free
        free(msg);
        free(hexdigest);
        OPENSSL_free(digest);
    }

    // free
    free(sk);
    free(ya);
    free(yb);
}

/*
This function simulates a DH exchange given the group's parameters and the two parties' private keys in hexadecimal.
A's public key is stored in ya in hexadecimal.
B's public key is stored in yb in hexadecimal.
The shared key is stored in sk in hexadecimal.
*/
static void dh_exchange(unsigned char *p, unsigned char *g, unsigned char *da, unsigned char *db, unsigned char **ya, unsigned char **yb, unsigned char **sk)
{

    //convert arguments to bignums
    BIGNUM *bp = NULL;
	if (0 == BN_hex2bn(&bp, (char*)p)) handleErrors("p convertion to bignum failed");
	BIGNUM *bg = NULL;
	if (0 == BN_hex2bn(&bg, (char*)g)) handleErrors("g convertion to bignum failed");
	BIGNUM *bda = NULL;
	if (0 == BN_hex2bn(&bda, (char*)da)) handleErrors("da convertion to bignum failed");
	BIGNUM *bdb = NULL;
	if (0 == BN_hex2bn(&bdb, (char*)db)) handleErrors("db convertion to bignum failed");

	// Setting A's private key
    DH *Akey;
    if(NULL == (Akey = DH_new())) handleErrors("Akey initialisation failed");
    if (1 != DH_set0_pqg(Akey, bp, NULL, bg)) handleErrors("setting p and g for Apub failed");
    if (1 != DH_set0_key(Akey, BN_new(), bda)) handleErrors("setting A's private key failed");

    // Computing A's public key
    if (1 != DH_generate_key(Akey)) handleErrors("computing ya failed");
    BIGNUM *bya = NULL;
    if (NULL == (bya = (BIGNUM *)DH_get0_pub_key(Akey))) handleErrors("failed to get bya");
    *ya = (unsigned char*)BN_bn2hex(bya);

    // Setting B's private key
    DH *Bkey;
    if(NULL == (Bkey = DH_new())) handleErrors("Bkey initialisation failed");
    if (1 != DH_set0_pqg(Bkey, bp, NULL, bg)) handleErrors("setting p and g for Bpub failed");
    if (1 != DH_set0_key(Bkey, BN_new(), bdb)) handleErrors("setting B's private key failed");

    // Computing B's public key
    if (1 != DH_generate_key(Bkey)) handleErrors("computing yb failed");
    BIGNUM *byb = NULL;
    if (NULL == (byb = (BIGNUM *)DH_get0_pub_key(Bkey))) handleErrors("failed to get byb");
    *yb = (unsigned char*)BN_bn2hex(byb);

    // Compute the shared key
    unsigned char *secret = NULL;
    if(NULL == (secret = OPENSSL_malloc(sizeof(unsigned char) * (DH_size(Akey))))) handleErrors("sk malloc failed");
    int secret_size = 0;
    if(0 >= (secret_size = DH_compute_key(secret, byb, Akey))) handleErrors("sk computation failed");

    *sk = stoh(secret, secret_size);

    //free
    BN_free(bp);
    BN_free(bg);
    //BN_free(bda);
    //BN_free(bdb);
    BN_free(bya);
    BN_free(byb);
    OPENSSL_free(secret);
}

/*
This function hashes the message using a given hash function and the result is written in digest
Copied from hasher.c
*/
static void digest_message(const unsigned char *message, size_t message_len, unsigned char **digest, unsigned int *digest_len,char *hashName)
{
		EVP_MD_CTX *mdctx;
	const EVP_MD* md = NULL;

	if((mdctx = EVP_MD_CTX_create()) == NULL)
		handleErrors("MD_CTX_create");

	md = EVP_get_digestbyname(hashName);

	if(1 != EVP_DigestInit_ex(mdctx, md, NULL))
		handleErrors("DigestInit_ex");

	if(1 != EVP_DigestUpdate(mdctx, message, message_len))
		handleErrors("DigestUpdate");

	if((*digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(md))) == NULL)
		handleErrors("malloc");

	if(1 != EVP_DigestFinal_ex(mdctx, *digest, digest_len))
		handleErrors("DigestFinal_ex");

	EVP_MD_CTX_destroy(mdctx);
}

// Because some functions where not present in older OpenSSL versions
#if OPENSSL_VERSION_NUMBER < 0x10101000L

#include <string.h>
#include <openssl/engine.h>

 const BIGNUM *DH_get0_pub_key(const DH *dh)
 {
    //logMsg("My DH_get0_pub_key function");
     const BIGNUM *pv = NULL;
     const BIGNUM *pb = NULL;
     DH_get0_key(dh, &pb, &pv);
     return pb;
 }

#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L

int DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g)
 {
    //logMsg("My DH_set0_pqg function");
    /* If the fields p and g in d are NULL, the corresponding input
     * parameters MUST be non-NULL.  q may remain NULL.
     */
    if ((dh->p == NULL && p == NULL)
        || (dh->g == NULL && g == NULL))
        return 0;

    if (p != NULL) {
        BN_free(dh->p);
        dh->p = p;
    }
    if (q != NULL) {
        BN_free(dh->q);
        dh->q = q;
    }
    if (g != NULL) {
        BN_free(dh->g);
        dh->g = g;
    }

    if (q != NULL) {
        dh->length = BN_num_bits(q);
    }

    return 1;
 }

 int DH_set0_key(DH *dh, BIGNUM *pub_key, BIGNUM *priv_key)
 {
    /* If the field pub_key in dh is NULL, the corresponding input
     * parameters MUST be non-NULL.  The priv_key field may
     * be left NULL.
     */
    //logMsg("My DH_set0_key function");
    if (dh->pub_key == NULL && pub_key == NULL)
        return 0;

    if (pub_key != NULL) {
        BN_free(dh->pub_key);
        dh->pub_key = pub_key;
    }
    if (priv_key != NULL) {
        BN_free(dh->priv_key);
        dh->priv_key = priv_key;
    }

    return 1;
 }

 void DH_get0_key(const DH *dh, const BIGNUM **pub_key, const BIGNUM **priv_key)
 {
    //logMsg("My DH_get0_key function");
    if (pub_key != NULL)
        *pub_key = dh->pub_key;
    if (priv_key != NULL)
        *priv_key = dh->priv_key;
 }

#endif