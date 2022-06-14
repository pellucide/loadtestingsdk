#include <sodium.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <string.h>
#include <stdio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include "openssl/core_names.h"
#include <openssl/pem.h>
#include <time.h>
#include <openssl/pem.h>
#include "cJSON.h"


#define RSA_KEYGEN_FAILED  -1
#define RSA_LOAD_RSA_KEY_FAILED  -3
#define RSA_ENCODE_RSA_PRIVATE_KEY_FAILED  -4
#define RSA_ENCODE_RSA_PRIVATE_KEY_FAILED_NEW_BUFFER_IO -5
#define RSA_ENCODE_RSA_PUBLIC_KEY_FAILED  -6
#define RSA_ENCODE_RSA_PUBLIC_KEY_FAILED_NEW_BUFFER_IO -7
#define RSA_DECODE_RSA_PRIVATE_KEY_FAILED  -8
#define RSA_DECODE_RSA_PRIVATE_KEY_FAILED_BIO  -9

#define MESSAGE (const unsigned char *) "test"
#define MESSAGE_LEN 4

char DATA[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890";
int  DATA_LEN = 62;
char HEXDATA[] = "ABCDEF1234567890";
int  HEXDATA_LEN = 16;
char bindBody[4096];
RSA * rsa = NULL;



int openssl_test_init() {
    /* Load the human readable error strings for libcrypto */
    ERR_load_crypto_strings();

    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();

    OpenSSL_add_all_digests();

    /* Load config file, and other important initialisation */
    //OPENSSL_config(NULL);

    /* ... Do some crypto stuff here ... */

    /* Clean up */

    /* Removes all digests and ciphers */
    EVP_cleanup();

    /* if you omit the next, a small leak may be left when you make use of the BIO (low level API) for e.g. base64 transformations */
    CRYPTO_cleanup_all_ex_data();

    /* Remove error strings */
    ERR_free_strings();

}

/*-
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Example showing how to generate an RSA key pair.
 *
 * When generating an RSA key, you must specify the number of bits in the key. A
 * reasonable value would be 4096. Avoid using values below 2048. These values
 * are reasonable as of 2022.
 */
/* A property query used for selecting algorithm implementations. */
static const char *propq = NULL;

/*
 * Generates an RSA public-private key pair and returns it.
 * The number of bits is specified by the bits argument.
 *
 * This uses the long way of generating an RSA key.
 */
static EVP_PKEY *generate_rsa_key_long(OSSL_LIB_CTX *libctx, unsigned int bits)
{
    EVP_PKEY_CTX *genctx = NULL;
    EVP_PKEY *pkey = NULL;
    unsigned int primes = 2;

    /* Create context using RSA algorithm. "RSA-PSS" could also be used here. */
    genctx = EVP_PKEY_CTX_new_from_name(libctx, "RSA", propq);
    if (genctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_name() failed\n");
        goto cleanup;
    }

    /* Initialize context for key generation purposes. */
    if (EVP_PKEY_keygen_init(genctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_keygen_init() failed\n");
        goto cleanup;
    }

    /*
     * Here we set the number of bits to use in the RSA key.
     * See comment at top of file for information on appropriate values.
     */
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(genctx, bits) <= 0) {
        fprintf(stderr, "EVP_PKEY_CTX_set_rsa_keygen_bits() failed\n");
        goto cleanup;
    }

    /*
     * It is possible to create an RSA key using more than two primes.
     * Do not do this unless you know why you need this.
     * You ordinarily do not need to specify this, as the default is two.
     *
     * Both of these parameters can also be set via EVP_PKEY_CTX_set_params, but
     * these functions provide a more concise way to do so.
     */
    if (EVP_PKEY_CTX_set_rsa_keygen_primes(genctx, primes) <= 0) {
        fprintf(stderr, "EVP_PKEY_CTX_set_rsa_keygen_primes() failed\n");
        goto cleanup;
    }

    /*
     * Generating an RSA key with a number of bits large enough to be secure for
     * modern applications can take a fairly substantial amount of time (e.g.
     * one second). If you require fast key generation, consider using an EC key
     * instead.
     *
     * If you require progress information during the key generation process,
     * you can set a progress callback using EVP_PKEY_set_cb; see the example in
     * EVP_PKEY_generate(3).
     */
    fprintf(stderr, "Generating RSA key, this may take some time...\n");
    if (EVP_PKEY_generate(genctx, &pkey) <= 0) {
        fprintf(stderr, "EVP_PKEY_generate() failed\n");
        goto cleanup;
    }

    /* pkey is now set to an object representing the generated key pair. */

cleanup:
    EVP_PKEY_CTX_free(genctx);
    return pkey;
}

/*
 * Generates an RSA public-private key pair and returns it.
 * The number of bits is specified by the bits argument.
 *
 * This uses a more concise way of generating an RSA key, which is suitable for
 * simple cases. It is used if -s is passed on the command line, otherwise the
 * long method above is used. The ability to choose between these two methods is
 * shown here only for demonstration; the results are equivalent.
 */
static EVP_PKEY *generate_rsa_key_short(OSSL_LIB_CTX *libctx, unsigned int bits)
{
    EVP_PKEY *pkey = NULL;

    //fprintf(stderr, "Generating RSA key, this may take some time...\n");
    pkey = EVP_PKEY_Q_keygen(libctx, propq, "RSA", (size_t)bits);

    if (pkey == NULL)
        fprintf(stderr, "EVP_PKEY_Q_keygen() failed\n");

    return pkey;
}

/*
 * Prints information on an EVP_PKEY object representing an RSA key pair.
 */
static int dump_key(const EVP_PKEY *pkey)
{
    int rv = 0;
    int bits = 0;
    BIGNUM *n = NULL, *e = NULL, *d = NULL, *p = NULL, *q = NULL;

    /*
     * Retrieve value of n. This value is not secret and forms part of the
     * public key.
     *
     * Calling EVP_PKEY_get_bn_param with a NULL BIGNUM pointer causes
     * a new BIGNUM to be allocated, so these must be freed subsequently.
     */
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n) == 0) {
        fprintf(stderr, "Failed to retrieve n\n");
        goto cleanup;
    }

    /*
     * Retrieve value of e. This value is not secret and forms part of the
     * public key. It is typically 65537 and need not be changed.
     */
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e) == 0) {
        fprintf(stderr, "Failed to retrieve e\n");
        goto cleanup;
    }

    /*
     * Retrieve value of d. This value is secret and forms part of the private
     * key. It must not be published.
     */
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_D, &d) == 0) {
        fprintf(stderr, "Failed to retrieve d\n");
        goto cleanup;
    }

    /*
     * Retrieve value of the first prime factor, commonly known as p. This value
     * is secret and forms part of the private key. It must not be published.
     */
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR1, &p) == 0) {
        fprintf(stderr, "Failed to retrieve p\n");
        goto cleanup;
    }

    /*
     * Retrieve value of the second prime factor, commonly known as q. This value
     * is secret and forms part of the private key. It must not be published.
     *
     * If you are creating an RSA key with more than two primes for special
     * applications, you can retrieve these primes with
     * OSSL_PKEY_PARAM_RSA_FACTOR3, etc.
     */
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR2, &q) == 0) {
        fprintf(stderr, "Failed to retrieve q\n");
        goto cleanup;
    }

    /*
     * We can also retrieve the key size in bits for informational purposes.
     */
    if (EVP_PKEY_get_int_param(pkey, OSSL_PKEY_PARAM_BITS, &bits) == 0) {
        fprintf(stderr, "Failed to retrieve bits\n");
        goto cleanup;
    }

    /* Output hexadecimal representations of the BIGNUM objects. */
    fprintf(stdout, "\nNumber of bits: %d\n\n", bits);
    fprintf(stderr, "Public values:\n");
    fprintf(stdout, "  n = 0x");
    BN_print_fp(stdout, n);
    fprintf(stdout, "\n");

    fprintf(stdout, "  e = 0x");
    BN_print_fp(stdout, e);
    fprintf(stdout, "\n\n");

    fprintf(stdout, "Private values:\n");
    fprintf(stdout, "  d = 0x");
    BN_print_fp(stdout, d);
    fprintf(stdout, "\n");

    fprintf(stdout, "  p = 0x");
    BN_print_fp(stdout, p);
    fprintf(stdout, "\n");

    fprintf(stdout, "  q = 0x");
    BN_print_fp(stdout, q);
    fprintf(stdout, "\n\n");

    /* Output a PEM encoding of the public key. */
    if (PEM_write_PUBKEY(stdout, pkey) == 0) {
        fprintf(stderr, "Failed to output PEM-encoded public key\n");
        goto cleanup;
    }

    /*
     * Output a PEM encoding of the private key. Please note that this output is
     * not encrypted. You may wish to use the arguments to specify encryption of
     * the key if you are storing it on disk. See PEM_write_PrivateKey(3).
     */
    if (PEM_write_PrivateKey(stdout, pkey, NULL, NULL, 0, NULL, NULL) == 0) {
        fprintf(stderr, "Failed to output PEM-encoded private key\n");
        goto cleanup;
    }

    rv = 1;
cleanup:
    BN_free(n); /* not secret */
    BN_free(e); /* not secret */
    BN_clear_free(d); /* secret - scrub before freeing */
    BN_clear_free(p); /* secret - scrub before freeing */
    BN_clear_free(q); /* secret - scrub before freeing */
    return rv;
}

int genRsaKeyPair1(int bits)
{
    int rv = 1;
    OSSL_LIB_CTX *libctx = NULL;
    EVP_PKEY *pkey = NULL;

    /* Generate RSA key. */
    pkey = generate_rsa_key_short(libctx, bits);

    if (pkey == NULL) {
        rv = RSA_KEYGEN_FAILED;
        goto cleanup;
    }

    /* Dump the integers comprising the key. */
    if (dump_key(pkey) == 0) {
        fprintf(stderr, "Failed to dump key\n");
        goto cleanup;
    }

    rv = 0;
cleanup:
    EVP_PKEY_free(pkey);
    OSSL_LIB_CTX_free(libctx);
    return rv;
}

int genRsaKeyPair2(int bits, EVP_PKEY *pkey){
    EVP_PKEY_CTX *ctx;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) /* Error occurred */
        return RSA_KEYGEN_FAILED;

    if (EVP_PKEY_keygen_init(ctx) <= 0) /* Error */
        return RSA_KEYGEN_FAILED;

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) /* Error */
        return RSA_KEYGEN_FAILED;

    /* Generate key */
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) /* Error */
        return RSA_KEYGEN_FAILED;
    printf("Success!");
}

int genRsaKeyPair(int bits, RSA ** pRSA, char newway){
    BIGNUM * bn = BN_new();
    int rc = BN_set_word(bn, RSA_F4);
    if (rc != 1) {
        return RSA_KEYGEN_FAILED;
    }

    if (newway) {
        RSA * rsa1 = RSA_new();
        rc = RSA_generate_key_ex(rsa1, bits, bn, NULL);
        if (rc != 1) {
            return RSA_KEYGEN_FAILED;
        }
        pRSA = &rsa1;
    } else {
        *pRSA = RSA_generate_key(bits, RSA_3, NULL, NULL);    
        if (*pRSA == NULL) /* Error */
            return RSA_KEYGEN_FAILED;
    }

    // Convert RSA to PKEY
    EVP_PKEY * pKey = EVP_PKEY_new();
    rc = EVP_PKEY_set1_RSA(pKey, *pRSA);

    return 0;
}


int encode_rsa_public_key_to_pem(RSA * rsa, char *output_pem_string, int includeheader) {
    char pem_str[1824];
    BIO *bp = BIO_new(BIO_s_mem());
    if (!bp) {
        return RSA_ENCODE_RSA_PUBLIC_KEY_FAILED_NEW_BUFFER_IO;
    }

    int rc = PEM_write_bio_RSAPublicKey(bp, rsa);

    //success is indicated by a value of 1
    if (rc != 1) {
        return RSA_ENCODE_RSA_PUBLIC_KEY_FAILED;
    }
     
    int keylen = BIO_pending(bp);
    int len;
    if (includeheader == 0) {
        /* remove the headers -----BEGIN----- and -----END----- */

        /* read the bio buffer into pem_Str */
        len = BIO_read(bp, pem_str, keylen);

        /* skip over the -----BEGIN---- */
        char * pem_str1 = strchr(pem_str, '\n');

        /* find -----END----- */
        char * nextLine = strstr(pem_str1, "-----");

        /* if found, mark it ad the end */
        if (nextLine) *nextLine = '\0';

        /* copy everything except newlines and count */
        char * out2 = output_pem_string;
        char chr;
        len = 0;
        while (chr = *pem_str1) {
            if (chr != '\n' && chr != '\r') {
                *out2 = chr;
                len++;
                out2++;
            }
            pem_str1++;
        }

        /* mark the end */
        *out2 = '\0';

        /* this following code is for copying with the newlines */
        //strcpy(output_pem_string, pem_str1);
        //len = strlen(pem_str1);
    } else {
        len = BIO_read(bp, output_pem_string, keylen);
    }

    return len;
}


int encode_rsa_private_key_to_pem(RSA * rsa, char *output_pem_string, int includeheader) {
    char pem_str[1824];
    BIO *bp = BIO_new(BIO_s_mem());
    if (!bp) {
        return RSA_ENCODE_RSA_PRIVATE_KEY_FAILED_NEW_BUFFER_IO;
    }

    int rc = PEM_write_bio_RSAPrivateKey(bp, rsa, NULL, NULL, 0, NULL, NULL);

    //success is indicated by a value of 1
    if (rc != 1) {
        return RSA_ENCODE_RSA_PRIVATE_KEY_FAILED;
    }
     
    int keylen = BIO_pending(bp);
    int len = 0;
    if (includeheader == 0) {
        /* remove the headers -----BEGIN----- and -----END----- */

        /* read the bio buffer into pem_Str */
        len = BIO_read(bp, pem_str, keylen);

        /* skip over the -----BEGIN---- */
        char * pem_str1 = strchr(pem_str, '\n');

        /* find -----END----- */
        char * nextLine = strstr(pem_str1, "-----");

        /* if found, mark it ad the end */
        if (nextLine) *nextLine = '\0';

        /* copy everything except newlines and count */
        char * out2 = output_pem_string;
        char chr;
        len = 0;
        while (chr = *pem_str1) {
            if (chr != '\n' && chr != '\r') {
                *out2 = chr;
                len++;
                out2++;
            }
            pem_str1++;
        }

        /* mark the end */
        *out2 = '\0';

        /* this following code is for copying with the newlines */
        //strcpy(output_pem_string, pem_str1);
        //len = strlen(pem_str1);
    } else {
        len = BIO_read(bp, output_pem_string, keylen);
    }

    return len;
}

int decode_rsa_private_key_from_pem(const char* private_key_pem_str, size_t len, RSA ** rsa)
{
  BIO *bp =  BIO_new_mem_buf((void*) private_key_pem_str, len);
  if (!bp) {
      return RSA_DECODE_RSA_PRIVATE_KEY_FAILED_BIO;
  }

  *rsa = PEM_read_bio_RSAPrivateKey(bp, NULL, NULL, NULL);

  if (*rsa == NULL) {
       return RSA_DECODE_RSA_PRIVATE_KEY_FAILED;
  }

  return 0;
}

int transmit_init(char *pem_str)
{
    unsigned char signed_message[crypto_sign_BYTES + MESSAGE_LEN];
    unsigned long long signed_message_len;

    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    unsigned char sk[crypto_box_SECRETKEYBYTES];

    unsigned char sig[crypto_sign_BYTES];

    int rc = sodium_init();
    if (rc < 0) {
         return -1;
    }
    rc =crypto_sign_keypair(pk, sk);
    if (rc < 0) {
         return -2;
    }

    rc = crypto_sign_detached(sig, NULL, MESSAGE, MESSAGE_LEN, sk);
    if (rc < 0) {
         return -3;
    }

    /* introduce a bug
    sig[0] = 0;

    char * jsonString = "{\"a\": 0}";
    cJSON *json = cJSON_Parse(jsonString);

    /* seed random number */
    srand(time(NULL));

    rc = crypto_sign_verify_detached(sig, MESSAGE, MESSAGE_LEN, pk);
    if (rc < 0) {
         return -4;
    }
   
    openssl_test_init();
    rc = genRsaKeyPair(1024, &rsa, 0);
    if (rc != 0) 
        return rc;

    int pem_str_len = encode_rsa_private_key_to_pem(rsa, pem_str, 1);

    RSA * rsa1 = NULL;
    rc = decode_rsa_private_key_from_pem(pem_str, pem_str_len, &rsa1);

    pem_str_len = encode_rsa_public_key_to_pem(rsa, pem_str, 1);
    return rc;
}

long getMilliSeconds() {
   time_t now = time(NULL) ;
   return now * 1000;

/*
   struct tm tm_now ;
   localtime_r(&now, &tm_now) ;
   char buff[100] ;
   strftime(buff, sizeof(buff), "%Y-%m-%d, time is %H:%M", &tm_now) ;
*/
}

long getMilliSeconds1() {
    struct tm y2k = {0};
    time_t timer = time(NULL);  /* get current time  */

    y2k.tm_hour = 0;
    y2k.tm_min = 0;
    y2k.tm_sec = 0;
    y2k.tm_year = 100;
    y2k.tm_mon = 0;
    y2k.tm_mday = 1;
    float seconds = difftime(timer,mktime(&y2k));

    return seconds*1000;
}

void getRandomString(char * str, int count) {
    int ii;
    int r = 0;
    for (ii=0; ii<count; ii++) {
        r = rand();
        str[ii] = DATA[r % DATA_LEN];
    }
    str[count-1] = '\0';
}

void getRandomHexString(char * str, int count) {
    int ii;
    int r = 0;
    for (ii=0; ii<count; ii++) {
        r = rand();
        str[ii] = HEXDATA[r % HEXDATA_LEN];
    }
    str[count-1] = '\0';
}

long getRandomLong() {
    long ll = rand();
    ll = ll << 32 + rand();
    return ll;
}

void base64_decode(char* inbuf, int inlen, char* outbuf, int outlen) {
    BIO *bio, *b64, *bio_out;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf((void*) inbuf, inlen);
    bio_out = BIO_new_mem_buf((void*) outbuf, outlen);
    BIO_push(b64, bio);
    while ((inlen = BIO_read(b64, inbuf, 512)) > 0)
        BIO_write(bio_out, inbuf, inlen);

    BIO_flush(bio_out);
    BIO_free_all(b64);
}

/* A BASE-64 ENCODER AND DECODER USING OPENSSL */
/*https://stackoverflow.com/a/16511093 */
void base64encode (const void *b64_encode_this, int encode_this_many_bytes, char *outbuf, int *outlen){
    BIO *b64_bio, *mem_bio;      //Declares two OpenSSL BIOs: a base64 filter and a memory BIO.
    BUF_MEM *mem_bio_mem_ptr;    //Pointer to a "memory BIO" structure holding our base64 data.
    b64_bio = BIO_new(BIO_f_base64());                      //Initialize our base64 filter BIO.
    mem_bio = BIO_new(BIO_s_mem());                           //Initialize our memory sink BIO.
    BIO_push(b64_bio, mem_bio);            //Link the BIOs by creating a filter-sink BIO chain.
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);  //No newlines every 64 characters or less.
    BIO_write(b64_bio, b64_encode_this, encode_this_many_bytes); //Records base64 encoded data.
    BIO_flush(b64_bio);   //Flush data.  Necessary for b64 encoding, because of pad characters.
    BIO_get_mem_ptr(mem_bio, &mem_bio_mem_ptr);  //Store address of mem_bio's memory structure.
    memcpy(outbuf, (*mem_bio_mem_ptr).data, *outlen);
    //BIO_set_close(mem_bio, BIO_NOCLOSE);   //Permit access to mem_ptr after BIOs are destroyed.
    BIO_free_all(b64_bio);  //Destroys all BIOs in chain, starting with b64 (i.e. the 1st one).
    *outlen = mem_bio_mem_ptr->length;
    //BUF_MEM_grow(mem_bio_mem_ptr, (*mem_bio_mem_ptr).length + 1);   //Makes space for end null.
    //(*mem_bio_mem_ptr).data[(*mem_bio_mem_ptr).length] = '\0';  //Adds null-terminator to tail.
    //return (*mem_bio_mem_ptr).data; //Returns base-64 encoded data. (See: "buf_mem_st" struct).
}

void base64decode (const void *b64_decode_this, int decode_this_many_bytes, char *base64_decoded, int * outlen){
    BIO *b64_bio, *mem_bio;      //Declares two OpenSSL BIOs: a base64 filter and a memory BIO.
    //char *base64_decoded = calloc( *outlen+1, sizeof(char));                       //+1 = null.
    b64_bio = BIO_new(BIO_f_base64());                      //Initialize our base64 filter BIO.
    mem_bio = BIO_new(BIO_s_mem());                         //Initialize our memory source BIO.
    BIO_write(mem_bio, b64_decode_this, decode_this_many_bytes); //Base64 data saved in source.
    BIO_push(b64_bio, mem_bio);          //Link the BIOs by creating a filter-source BIO chain.
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);          //Don't require trailing newlines.
    int decoded_byte_index = 0;   //Index where the next base64_decoded byte should be written.
    while ( 0 < BIO_read(b64_bio, base64_decoded+decoded_byte_index, 1) ){ //Read byte-by-byte.
        decoded_byte_index++; //Increment the index until read of BIO decoded data is complete.
    } //Once we're done reading decoded data, BIO_read returns -1 even though there's no error.
    *outlen = decoded_byte_index;
    BIO_free_all(b64_bio);  //Destroys all BIOs in chain, starting with b64 (i.e. the 1st one).
    return;
}


void byteArrayToHexString(unsigned char * byteArray, int inlen, char * hexString) {
    int ii=0;
    for (ii=0; ii<inlen; ii++) {
       sprintf(&hexString[ii * 2], "%02X", byteArray[ii]);
    }
    hexString[inlen*2] ='\0';
}


unsigned char signature_bytes[512];
int signWithRsa(RSA* rsa, const unsigned char* message,
              int MsgLen, unsigned char* outbuf, int* outbuflen) {

  if (rsa == NULL) {
      outbuf[0] = 'f';
      outbuf[1] = 'a';
      outbuf[2] = 'i';
      outbuf[3] = 'l';
      outbuf[4] = 0;
      return -1;
  }
  outbuf[0] = 't';
  outbuf[1] = 'e';
  outbuf[2] = 's';
  outbuf[3] = 't';
  outbuf[4] = 0;
  int ii=0;
  for(ii=0; ii<512; ii++)
     signature_bytes[ii] = 'a';

  int signatureLen;
  EVP_MD_CTX* m_RSASignCtx = EVP_MD_CTX_create();
  EVP_PKEY* priKey  = EVP_PKEY_new();
  EVP_PKEY_assign_RSA(priKey, rsa);
  if (EVP_DigestSignInit(m_RSASignCtx,NULL, EVP_sha256(), NULL,priKey)<=0) {
      return -1;
  }
  if (EVP_DigestSignUpdate(m_RSASignCtx, message, MsgLen) <= 0) {
      return -1;
  }
  if (EVP_DigestSignFinal(m_RSASignCtx, NULL, &signatureLen) <=0) {
      return -1;
  }
  if (EVP_DigestSignFinal(m_RSASignCtx, signature_bytes, &signatureLen) <= 0) {
      return -1;
  }


  outbuf[0] = signatureLen & 0xFF + '0'; 
  outbuf[1] = signatureLen>>8 & 0xFF + '0'; 
  outbuf[2] = signatureLen>>16 & 0xFF + '0'; 
  outbuf[3] = 0;
  //base64encode(signature_bytes, signatureLen, outbuf, outbuflen);
  //outbuf[*outbuflen]=0;


  //outbuf[0] = 'a';
  //outbuf[1] = 'b';
  //outbuf[2] = 'c';
  //outbuf[3] = 'd';
  //outbuf[4] = 0;
  //byteArrayToHexString(signature_bytes, signatureLen, outbuf);
  //outbuf[signatureLen*2]=0;

  EVP_MD_CTX_destroy(m_RSASignCtx);
  return 0;
}

int RSASign( RSA* rsa,
              const unsigned char* Msg,
              size_t MsgLen,
              unsigned char * outbuf,
              int * outbuflen) {
  size_t MsgLenEnc;
  unsigned char* EncMsg;
  EVP_MD_CTX* m_RSASignCtx = EVP_MD_CTX_create();
  EVP_PKEY* priKey  = EVP_PKEY_new();
  EVP_PKEY_assign_RSA(priKey, rsa);
  if (EVP_DigestSignInit(m_RSASignCtx,NULL, EVP_sha256(), NULL,priKey)<=0) {
      return -1;
  }
  if (EVP_DigestSignUpdate(m_RSASignCtx, Msg, MsgLen) <= 0) {
      return -1;
  }
  if (EVP_DigestSignFinal(m_RSASignCtx, NULL, &MsgLenEnc) <=0) {
      return -1;
  }
  EncMsg = (unsigned char*)malloc(MsgLenEnc);
  if (EVP_DigestSignFinal(m_RSASignCtx, EncMsg, &MsgLenEnc) <= 0) {
      return -1;
  }
  EVP_MD_CTX_destroy(m_RSASignCtx);
  base64encode(EncMsg, MsgLenEnc, outbuf, outbuflen);
  outbuf[*outbuflen]=0;
  return 0;
}
void Base64Encode1( const unsigned char* buffer, 
                   size_t length, 
                   char* outbuf, int *outbuflen) { 
  char* base64Text;
  BIO *bio, *b64;
  BUF_MEM *bufferPtr;
  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new(BIO_s_mem());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);  //No newlines every 64 characters or less.
  bio = BIO_push(b64, bio);
  BIO_write(bio, buffer, length);
  BIO_flush(bio);
  BIO_get_mem_ptr(bio, &bufferPtr);
  BIO_set_close(bio, BIO_NOCLOSE);
  BIO_free_all(bio);
  memcpy(outbuf, (*bufferPtr).data, (*bufferPtr).length); 
  *outbuflen =  (*bufferPtr).length; 
}

// Sign String
int RsaSign1( RSA* rsa,
              const unsigned char* buffer,
              size_t buflen,
              unsigned char * outbuf,
              int * outbuflen) {

    const int size = RSA_size(rsa);
    unsigned char sign[size];
    unsigned int outlen = 0;

    /* SHA256 digest */
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, buffer, buflen);
    SHA256_Final(hash, &sha256);

    /* Sign */
    sprintf(outbuf, "test");
    RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, sign, &outlen, rsa);
    sprintf(outbuf, "outlen=%d, size=%d",outlen, size);
    //base64encode(sign, outlen, outbuf, outbuflen);
    //outbuf[*outbuflen]=0;

    Base64Encode1(sign, outlen, outbuf, outbuflen);
}


void getSha256(char * inbuf, int inlen, char * outbuf, int *outlen){
    unsigned char md_value[EVP_MAX_MD_SIZE];
    const EVP_MD *md = EVP_get_digestbyname("sha256");
    EVP_MD_CTX * mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, inbuf, inlen);
    EVP_DigestFinal_ex(mdctx, outbuf, outlen);
    EVP_MD_CTX_destroy(mdctx);
    EVP_cleanup();
}

char pem_bytes[4096];
unsigned char signatureStr[524];
void getContentSignatureRsa(RSA *rsa, char * plaintext, int plaintextlen,
                            int scheme, char * deviceId,
                            char * contentSignature, int * contentSignatureLen) {
    char pem_str[1024];
    unsigned char sha256[SHA256_DIGEST_LENGTH];
    unsigned char sha256str[225];
    unsigned char public_key_bytes[224];
    int decoded_len;
    int sha256len;
    int signatureLen;

    //signWithRsa(rsa, plaintext, plaintextlen, signatureStr, &signatureLen);
    //RSASign(rsa, plaintext, plaintextlen, signatureStr, &signatureLen);
    RsaSign1(rsa, plaintext, plaintextlen, signatureStr, &signatureLen);
    if (scheme != 4) {
        *contentSignatureLen = sprintf("%s%s%s%s%s%d", "data:", signatureStr, ";key-id:", deviceId, ";scheme:", scheme);
    } else {
        int pem_str_len = encode_rsa_public_key_to_pem(rsa, pem_str, 0);
        base64decode(pem_str, pem_str_len, public_key_bytes, &decoded_len);
        getSha256(public_key_bytes, decoded_len, sha256,  &sha256len);
        byteArrayToHexString(sha256, sha256len, sha256str);
        *contentSignatureLen = sprintf(contentSignature, "%s%s%s%s%s%d", "data:", signatureStr, ";key-id:", sha256str, ";scheme:", scheme);
    }
}

void preProcess_local(RSA * rsa, char * path, char * body, char * clientVersion, char * deviceId,  int scheme, char* contentSignature) {
     unsigned char plaintext[5555];
     int len;
     int contentSignatureLen;
     if (scheme == 2 || scheme == 3 || scheme == 4) {
         len = sprintf(plaintext,"%s%s%s%s%s", path, "%%", clientVersion, "%%", body);
     } else {
         len = sprintf(plaintext, "%s%s", path, body);
     }
     getContentSignatureRsa(rsa, plaintext, len, scheme, deviceId, contentSignature, &contentSignatureLen);
}

void preProcess(char * path, char * body, char * clientVersion, char * deviceId, int scheme, char* contentSignature) {
    preProcess_local(rsa, path, body, clientVersion, deviceId, scheme, contentSignature);
}

int transmit_bind(char * userId, char * clientVersion, int scheme, char * appId, char *path, char * body, char * contentSignature) { 
    char pem_str[4096];
    int pem_str_len = encode_rsa_public_key_to_pem(rsa, pem_str, 0);
    long timestamp = getMilliSeconds();
    char randomHexStr[32];
    char randomHexStr1[32];
    char randomStr[15];
    char randomStr1[15];
    char randomLong[32];
    char randomLong1[32];
    char randomLong2[32];
    char schemestr[32];
    char timestampstr[32];

    sprintf(randomLong, "%d",getRandomLong());
    sprintf(randomLong1, "%d",getRandomLong());
    sprintf(randomLong2, "%d",getRandomLong());

    getRandomHexString(randomHexStr, 32);
    getRandomHexString(randomHexStr1, 15);
    getRandomString(randomStr, 8);

    sprintf(path, "%s%s", "/api/v2/auth/bind?aid=", appId);
    sprintf(schemestr, "%d", scheme);
    sprintf(timestampstr, "%d", timestamp);
    sprintf(body, "%s", pem_str);


    sprintf(body, "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
    "{ \"data\": { \"collection_result\": { \"metadata\": { \"scheme_version\": ", schemestr,
    ", \"timestamp\": ", timestampstr,
    ", \"version\": \"", clientVersion,
    "\"}, \"content\": { \"accounts\": [{ \"name\": \"", randomHexStr,
    "\",\"type\": \"", randomHexStr1,
    "\"},{\"name\": \"b8d2a60277443092b75b9a9f71bce945\",\"type\": \"3330d5072c5971394e189640a9f09b77\" }],",
    "\"capabilities\": {\"audio_acquisition_supported\": true, \"dyadic_present\": true,",
    "\"face_id_key_bio_protection_supported\": false, \"fido_client_present\": true,",
    "\"finger_print_supported\": true, \"host_provided_features\": \"19\", \"image_acquisition_supported\": true,",
    "\"persistent_keys_supported\": true }, \"collector_state\": {",
    "\"accounts\": \"active\", \"bluetooth\": \"active\", \"capabilities\": \"active\",",
    "\"contacts\": \"active\", \"devicedetails\": \"active\", \"externalsdkdetails\": \"active\",",
    "\"fidoauthenticators\": \"disabled\", \"hwauthenticators\": \"active\", \"largedata\": \"disabled\",",
    "\"localenrollments\": \"active\", \"location\": \"active\", \"owner\": \"active\",", " \"software\": \"active\"},",
    "\"contacts\": { \"contacts_count\": 765}, \"device_details\": {\"connection\": \"wifi: 10.103.82.192\",",
    "\"device_id\": \"", randomLong,
    "\", \"device_model\": \"", randomStr,
    "\", \"device_name\": \"", randomHexStr1,
    "\", \"frontal_camera\": true, \"has_hw_security\": true, \"hw_type\": \"Phone\", \"jailbroken\": false, \"known_networks\": [",
    "{\"ssid\": \"ab2e79dbba72c3866298b74f1a1c6fa6\"}, {\"secure\": true, \"ssid\": \"4eb341e247478a5a5ec2ba7d755cc614\"",
    "}],", " \"logged_users\": 0,", " \"master_key_generated\": ", randomLong1,
    ",\"os_type\": \"Android\", \"os_version\": \"8.0.0\", \"roaming\": false, \"screen_lock\": true, \"sflags\": -1,",
    "\"sim_operator\": \"310410\", \"sim_operator_name\": \"\", \"sim_serial\": \"", randomLong2,
    "\", \"subscriber_id\": \"310410035590766\", \"tampered\": true, \"tz\": \"America/New_York\", \"wifi_network\": {",
    "\"bssid\": \"d4705a482b5be4955808176e48f7371e\", \"secure\": true, \"ssid\": \"4eb341e247478a5a5ec2ba7d755cc614\"",
    "}}, \"hw_authenticators\": { \"face_id\": { \"secure\": false, \"supported\": false, \"user_registered\": false",
    "},\"fingerprint\": { \"secure\": true, \"supported\": true, \"user_registered\": true}}, \"installed_packages\": [",
    "\"20c496910ff8da1214ae52d3750684cd\", \"09e5b19fffdd4c9da52742ce536e1d8b\", \"5f5ca4b53bed9c75720d7ae1a8b949fc\",",
    "\"2ce4266d32140417eebea06fd2d5d9cd\", \"40197bd6e7b2b8d5880b666b7a024ab6\"], \"local_enrollments\": {},\"location\": {",
    "\"enabled\": true, \"h_acc\": 12.800999641418457, \"lat\": 40.3528937, \"lng\": -74.4993894},\"owner_details\": {",
    "\"possible_emails\": [ \"f91c98012706e141b2e3bcc286af5e06\"], \"possible_names\": [ \"c3fa673b98c1a9ee6ecc3e38d0381966\"]}}},",
    "\"public_key\": { \"key\": \"", pem_str,
    "\",\"type\": \"rsa\"}, \"encryption_public_key\": { \"key\": \"", pem_str,
    "\", \"type\": \"rsa\"}}, \"headers\": [{ \"type\": \"uid\",\"uid\": \"", userId, "\"}],\"push_token\": \"fakePushToken\"}");



    
    preProcess_local(rsa, path, body, clientVersion, "deviceId", scheme, contentSignature);

    cJSON *json = cJSON_Parse(body);
    if (json == NULL) {
         return -1;
    }
    int rc = cJSON_PrintPreallocated(json, body, 2999, 0);
    return rc;
}

