// Author : Florian Picca <florian.picca@oppida.fr>
// Date : April 2020
// Based on : https://github.com/openssl/openssl/blob/fda127beb2b3c029741573b0dd931295b3446fd2/test/ecdsatest.c
#include "util.h"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/ecdsa.h>

// Function declaration
static void ecdsa_sign(char *curvename, unsigned char *k, unsigned char *d, unsigned char *hash,  unsigned char **r,  unsigned char **s);
static int fakeRNG(unsigned char *buf, int num);
static int change_rand(void);
static int restore_rand(void);

// Important global variables
static int use_fake_rng = 0;
static RAND_METHOD fake_method;
static const RAND_METHOD *original_method;
static unsigned char *RNG_state[2];

// Because some functions where not present in older OpenSSL versions
#if OPENSSL_VERSION_NUMBER < 0x10100000L

 void ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps)
 {
    if (pr != NULL)
        *pr = sig->r;
    if (ps != NULL)
        *ps = sig->s;
 }

typedef enum {big, little} endianess_t;

 static int bn2binpad(const BIGNUM *a, unsigned char *to, int tolen, endianess_t endianess)
{
    int n;
    size_t i, lasti, j, atop, mask;
    BN_ULONG l;

    /*
     * In case |a| is fixed-top, BN_num_bytes can return bogus length,
     * but it's assumed that fixed-top inputs ought to be "nominated"
     * even for padded output, so it works out...
     */
    n = BN_num_bytes(a);
    if (tolen == -1) {
        tolen = n;
    } else if (tolen < n) {     /* uncommon/unlike case */
        BIGNUM temp = *a;

        bn_correct_top(&temp);
        n = BN_num_bytes(&temp);
        if (tolen < n)
            return -1;
    }

    /* Swipe through whole available data and don't give away padded zero. */
    atop = a->dmax * BN_BYTES;
    if (atop == 0) {
        OPENSSL_cleanse(to, tolen);
        return tolen;
    }

    lasti = atop - 1;
    atop = a->top * BN_BYTES;
    if (endianess == big)
        to += tolen; /* start from the end of the buffer */
    for (i = 0, j = 0; j < (size_t)tolen; j++) {
        unsigned char val;
        l = a->d[i / BN_BYTES];
        mask = 0 - ((j - atop) >> (8 * sizeof(i) - 1));
        val = (unsigned char)(l >> (8 * (i % BN_BYTES)) & mask);
        if (endianess == big)
            *--to = val;
        else
            *to++ = val;
        i += (i - lasti) >> (8 * sizeof(i) - 1); /* stay on last limb */
    }

    return tolen;
}

int BN_bn2binpad(const BIGNUM *a, unsigned char *to, int tolen)
{
    if (tolen < 0)
        return -1;
    return bn2binpad(a, to, tolen, big);
}

#endif

/* Arguments in order :
        - curve name : The name of the curve : P-192, P-224, P-256, P-384, P-521
        - hash : The precomputed hash of the message to sign in hexadecimal form
        - d : The private key in hexadecimal form
        - k : The random value used in the signature to produce r in hexadecimal form
*/
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

    ecdsa_sign(curvename, k, d, Msg, &r, &s);

    printf("%s %s\n", r, s);

    // free
    free(r);
    free(s);
}



// Switch the internal RNG to our fake RNG
static int change_rand(void)
{
    /* save old rand method */
    if ((original_method = RAND_get_rand_method()) == NULL)
        return 0;

    fake_method = *original_method;
    /* use own random function */
    fake_method.bytes = fakeRNG;
    /* set new RAND_METHOD */
    if (RAND_set_rand_method(&fake_method) != 1)
        return 0;
    return 1;
}

// Restore the internal RNG to its original value
static int restore_rand(void)
{
    if (RAND_set_rand_method(original_method) != 1)
        return 0;
    return 1;
}

static int fakeRNG(unsigned char *buf, int num)
{
    int ret = 0;
    static int fbytes_counter = 0;
    BIGNUM *tmp = NULL;

    // In case we want to use the original RNG
    if (use_fake_rng == 0)
        return original_method->bytes(buf, num);

    // ensure that we only use this one, once
    use_fake_rng = 0;

    tmp = BN_new();
    if (tmp == NULL) {
        handleErrors("fakeRNG: tmp creation failed");
    }
    if (fbytes_counter >= 2) {
        handleErrors("fakeRNG: fbytes_counter >= 2");
    }
    if (BN_hex2bn(&tmp, (char*)RNG_state[fbytes_counter]) == 0) {
        handleErrors("fakeRNG: BN_hex2bn failed");
    }
    if (BN_num_bytes(tmp) > num) {
        handleErrors("fakeRNG: tmp > num");
    }
     /* tmp might need leading zeros so pad it out */
     if (BN_bn2binpad(tmp, buf, num) == 0) {
        handleErrors("fakeRNG: padding failed");
     }

    fbytes_counter = (fbytes_counter + 1) % 2;
    ret = 1;
    BN_free(tmp);
    return ret;
}

static void ecdsa_sign(char *curvename, unsigned char *k, unsigned char *d, unsigned char *hash,  unsigned char **r,  unsigned char **s) {

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

    // Set the fake RNG state
    RNG_state[0] = d;
    RNG_state[1] = k;

    // Create the message digest
    unsigned char *digest = htos(hash);
    unsigned int dgst_len = strlen((char*)hash)/2;

    //Create the key
    EC_KEY *key = EC_KEY_new_by_curve_name(curveid);
    if (NULL == key) handleErrors("EC creation failed");

    //Switch to fake RNG
    if (0 == change_rand()) handleErrors("RNG switch failed");

    //Generate the public key using the fake RNG
    use_fake_rng = 1;
    if (EC_KEY_generate_key(key) == 0) handleErrors("public key generation failed");
    // the generated key should the same as in the test

    //Create the signature via ECDSA_sign_setup to avoid use of ECDSA nonces
    use_fake_rng = 1;
    BIGNUM *kinv = NULL, *rp = NULL;
    if (ECDSA_sign_setup(key, NULL, &kinv, &rp) != 1) handleErrors("sign setup failed");
    ECDSA_SIG *signature = NULL;
    signature = ECDSA_do_sign_ex(digest, dgst_len, kinv, rp, key);
    if (signature == NULL) handleErrors("Signature generation failed");

    // get r and s from signature
    const BIGNUM *sig_r = NULL, *sig_s = NULL;
    ECDSA_SIG_get0(signature, &sig_r, &sig_s);
    *r = (unsigned char*)BN_bn2hex(sig_r);
    *s = (unsigned char*)BN_bn2hex(sig_s);

    restore_rand();
    free(digest);
    EC_KEY_free(key);
    ECDSA_SIG_free(signature);
    BN_clear_free(kinv);
    BN_clear_free(rp);
}