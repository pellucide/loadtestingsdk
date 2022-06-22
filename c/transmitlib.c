
#define OPENSSL_API_COMPAT 0x00908000L // (version 0.9.8)
#define OPENSSL_NO_DEPRECATED 1
#define _CRT_SECURE_NO_WARNINGS 1


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

_declspec(dllexport) char DATA[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890";
_declspec(dllexport) int  DATA_LEN = 62;
_declspec(dllexport) char HEXDATA[] = "ABCDEF1234567890";
_declspec(dllexport) int  HEXDATA_LEN = 16;
_declspec(dllexport) RSA* rsa = NULL;
_declspec(dllexport) EVP_PKEY* pkey = NULL;
_declspec(dllexport) unsigned char signature_bytes[512];
char pem_bytes[4096];
unsigned char signatureStr[524];
unsigned char paramsStr[7724];


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
static const char* propq = NULL;

/*
 * Generates an RSA public-private key pair and returns it.
 * The number of bits is specified by the bits argument.
 *
 * This uses the long way of generating an RSA key.
 */
static EVP_PKEY* generate_rsa_key_long(OSSL_LIB_CTX* libctx, unsigned int bits)
{
	EVP_PKEY_CTX* genctx = NULL;
	EVP_PKEY* pkey = NULL;
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
static EVP_PKEY* generate_rsa_key_short(OSSL_LIB_CTX* libctx, unsigned int bits)
{
	EVP_PKEY* pkey = NULL;

	//fprintf(stderr, "Generating RSA key, this may take some time...\n");
	pkey = EVP_PKEY_Q_keygen(libctx, propq, "RSA", (size_t)bits);

	if (pkey == NULL)
		fprintf(stderr, "EVP_PKEY_Q_keygen() failed\n");

	return pkey;
}

/*
 * Prints information on an EVP_PKEY object representing an RSA key pair.
 */
static int dump_key(const EVP_PKEY* pkey)
{
	int rv = 0;
	int bits = 0;
	BIGNUM* n = NULL, * e = NULL, * d = NULL, * p = NULL, * q = NULL;

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

int genRsaKeyPair1(int bits, EVP_PKEY** pkey)
{
	int rv = 0;
	OSSL_LIB_CTX* libctx = NULL;

	/* Generate RSA key. */
	*pkey = generate_rsa_key_short(libctx, bits);

	if (*pkey == NULL) {
		rv = RSA_KEYGEN_FAILED;
		goto cleanup;
	}

	/* Dump the integers comprising the key. */
	//if (dump_key(*pkey) == 0) {
		//fprintf(stderr, "Failed to dump key\n");
		//goto cleanup;
	//}

cleanup:
	OSSL_LIB_CTX_free(libctx);
	return rv;
}

int genRsaKeyPair2(int bits, EVP_PKEY** pkey) {
	EVP_PKEY_CTX* ctx;
	EVP_PKEY* pkey1;

	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	if (!ctx) /* Error occurred */
		return RSA_KEYGEN_FAILED;

	if (EVP_PKEY_keygen_init(ctx) <= 0) /* Error */
		return RSA_KEYGEN_FAILED;

	if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) /* Error */
		return RSA_KEYGEN_FAILED;

	/* Generate key */
	if (EVP_PKEY_keygen(ctx, &pkey1) <= 0) /* Error */
		return RSA_KEYGEN_FAILED;

	printf("Success!");
}

int genRsaKeyPair(int bits, RSA** pRSA, char newway) {
	BIGNUM* bn = BN_new();
	int rc = BN_set_word(bn, RSA_F4);
	if (rc != 1) {
		return RSA_KEYGEN_FAILED;
	}

	if (newway) {
		RSA* rsa1 = RSA_new();
		rc = RSA_generate_key_ex(rsa1, bits, bn, NULL);
		if (rc != 1) {
			return RSA_KEYGEN_FAILED;
		}
		*pRSA = rsa1;
	}
	else {
		*pRSA = RSA_generate_key(bits, RSA_3, NULL, NULL);
		if (*pRSA == NULL) /* Error */
			return RSA_KEYGEN_FAILED;
	}

	// Convert RSA to PKEY
	EVP_PKEY* pKey = EVP_PKEY_new();
	rc = EVP_PKEY_set1_RSA(pKey, *pRSA);

	return 0;
}


int encode_rsa_public_key_to_pem(EVP_PKEY* pkey, char* output_pem_string, int includeheader) {
	char pem_str[1824];
	BIO* bp = BIO_new(BIO_s_mem());
	if (!bp) {
		return RSA_ENCODE_RSA_PUBLIC_KEY_FAILED_NEW_BUFFER_IO;
	}

	int rc = PEM_write_bio_PUBKEY(bp, pkey);

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
		char* pem_str1 = strchr(pem_str, '\n');

		/* find -----END----- */
		char* nextLine = strstr(pem_str1, "-----");

		/* if found, mark it ad the end */
		if (nextLine) *nextLine = '\0';

		/* copy everything except newlines and count */
		char* out2 = output_pem_string;
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
	}
	else {
		len = BIO_read(bp, output_pem_string, keylen);
	}

	return len;
}


char** str_split(char* a_str, const char a_delim)
{
	char** result = 0;
	size_t count = 0;
	char* tmp = a_str;
	char* last_comma = 0;
	char delim[2];
	delim[0] = a_delim;
	delim[1] = 0;

	/* Count how many elements will be extracted. */
	while (*tmp)
	{
		if (a_delim == *tmp)
		{
			count++;
			last_comma = tmp;
		}
		tmp++;
	}

	/* Add space for trailing token. */
	count += last_comma < (a_str + strlen(a_str) - 1);

	/* Add space for terminating null string so caller
	   knows where the list of returned strings ends. */
	count++;

	result = malloc(sizeof(char*) * count);

	if (result)
	{
		size_t idx = 0;
		char* token = strtok(a_str, delim);

		while (token)
		{
			//ssert(idx < count);
			*(result + idx++) = strdup(token);
			token = strtok(0, delim);
		}
		//assert(idx == count - 1);
		*(result + idx) = 0;
	}

	return result;
}




int encode_rsa_public_key_to_pem_old(RSA* rsa, char* output_pem_string, int includeheader) {
	char pem_str[1824];
	BIO* bp = BIO_new(BIO_s_mem());
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
		char* pem_str1 = strchr(pem_str, '\n');

		/* find -----END----- */
		char* nextLine = strstr(pem_str1, "-----");

		/* if found, mark it ad the end */
		if (nextLine) *nextLine = '\0';

		/* copy everything except newlines and count */
		char* out2 = output_pem_string;
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
	}
	else {
		len = BIO_read(bp, output_pem_string, keylen);
	}

	return len;
}


int encode_rsa_private_key_to_pem(EVP_PKEY* pkey, char* output_pem_string, int includeheader) {
	char pem_str[1824];
	BIO* bp = BIO_new(BIO_s_mem());
	if (!bp) {
		return RSA_ENCODE_RSA_PRIVATE_KEY_FAILED_NEW_BUFFER_IO;
	}

	int rc = PEM_write_bio_PrivateKey(bp, pkey, NULL, NULL, 0, NULL, NULL);

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
		char* pem_str1 = strchr(pem_str, '\n');

		/* find -----END----- */
		char* nextLine = strstr(pem_str1, "-----");

		/* if found, mark it ad the end */
		if (nextLine) *nextLine = '\0';

		/* copy everything except newlines and count */
		char* out2 = output_pem_string;
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
	}
	else {
		len = BIO_read(bp, output_pem_string, keylen);
	}

	return len;
}


int encode_rsa_private_key_to_pem_old(RSA* rsa, char* output_pem_string, int includeheader) {
	char pem_str[1824];
	BIO* bp = BIO_new(BIO_s_mem());
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
		char* pem_str1 = strchr(pem_str, '\n');

		/* find -----END----- */
		char* nextLine = strstr(pem_str1, "-----");

		/* if found, mark it ad the end */
		if (nextLine) *nextLine = '\0';

		/* copy everything except newlines and count */
		char* out2 = output_pem_string;
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
	}
	else {
		len = BIO_read(bp, output_pem_string, keylen);
	}

	return len;
}

int decode_rsa_private_key_from_pem(const char* private_key_pem_str, size_t len, EVP_PKEY** pkey)
{
	BIO* bp = BIO_new_mem_buf((void*)private_key_pem_str, len);
	if (!bp) {
		return RSA_DECODE_RSA_PRIVATE_KEY_FAILED_BIO;
	}

	*pkey = PEM_read_bio_PrivateKey(bp, NULL, NULL, NULL);

	if (*pkey == NULL) {
		return RSA_DECODE_RSA_PRIVATE_KEY_FAILED;
	}

	return 0;
}

__declspec(dllexport) int decode_rsa_private_key_from_pem_old(const char* private_key_pem_str, size_t len, RSA** rsa)
{
	BIO* bp = BIO_new_mem_buf((void*)private_key_pem_str, len);
	if (!bp) {
		return RSA_DECODE_RSA_PRIVATE_KEY_FAILED_BIO;
	}

	*rsa = PEM_read_bio_RSAPrivateKey(bp, NULL, NULL, NULL);

	if (*rsa == NULL) {
		return RSA_DECODE_RSA_PRIVATE_KEY_FAILED;
	}

	return 0;
}

__declspec(dllexport) int transmit_init(char* pem_str_public, char* pem_str_private)
{
	/*
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

	rc = crypto_sign_verify_detached(sig, MESSAGE, MESSAGE_LEN, pk);
	if (rc < 0) {
		 return -4;
	}



	*/

	char* jsonString = "{\"a\": 0}";
	cJSON* json = cJSON_Parse(jsonString);

	/* seed random number */
	srand(time(NULL));

	openssl_test_init();

	int rc = genRsaKeyPair1(1024, &pkey);
	if (rc != 0)
		return rc;

	int pem_str_len = encode_rsa_private_key_to_pem(pkey, pem_str_private, 1);

	RSA* rsa1 = NULL;
	rc = decode_rsa_private_key_from_pem(pem_str_private, pem_str_len, &pkey);

	pem_str_len = encode_rsa_public_key_to_pem(pkey, pem_str_public, 1);
	return rc;
}


__declspec(dllexport) int transmit_init_old(char* pem_str_public, char* pem_str_private)
{
	/*
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



	rc = crypto_sign_verify_detached(sig, MESSAGE, MESSAGE_LEN, pk);
	if (rc < 0) {
		 return -4;
	}
	*/

	/* seed random number */
	srand(time(NULL));
	openssl_test_init();
	int rc = genRsaKeyPair(1024, &rsa, 1);
	if (rc != 0)
		return rc;

	int pem_str_len = encode_rsa_private_key_to_pem_old(rsa, pem_str_private, 1);

	RSA* rsa1 = NULL;
	rc = decode_rsa_private_key_from_pem_old(pem_str_private, pem_str_len, &rsa1);

	pem_str_len = encode_rsa_public_key_to_pem_old(rsa, pem_str_public, 1);
	return rc;
}

long getMilliSeconds() {
	time_t now = time(NULL);
	return now * 1000;

	/*
	   struct tm tm_now ;
	   localtime_r(&now, &tm_now) ;
	   char buff[100] ;
	   strftime(buff, sizeof(buff), "%Y-%m-%d, time is %H:%M", &tm_now) ;
	*/
}

long getMilliSeconds1() {
	struct tm y2k = { 0 };
	time_t timer = time(NULL);  /* get current time  */

	y2k.tm_hour = 0;
	y2k.tm_min = 0;
	y2k.tm_sec = 0;
	y2k.tm_year = 100;
	y2k.tm_mon = 0;
	y2k.tm_mday = 1;
	float seconds = difftime(timer, mktime(&y2k));

	return seconds * 1000;
}

void getRandomString(char* str, int count) {
	int ii;
	int r = 0;
	for (ii = 0; ii < count; ii++) {
		r = rand();
		str[ii] = DATA[r % DATA_LEN];
	}
	str[count - 1] = '\0';
}

void getRandomHexString(char* str, int count) {
	int ii;
	int r = 0;
	for (ii = 0; ii < count; ii++) {
		r = rand();
		str[ii] = HEXDATA[r % HEXDATA_LEN];
	}
	str[count - 1] = '\0';
}

long getRandomLong() {
	long ll = rand();
	ll = ll << 32 + rand();
	return ll;
}

void base64_decode(char* inbuf, int inlen, char* outbuf, int outlen) {
	BIO* bio, * b64, * bio_out;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new_mem_buf((void*)inbuf, inlen);
	bio_out = BIO_new_mem_buf((void*)outbuf, outlen);
	BIO_push(b64, bio);
	while ((inlen = BIO_read(b64, inbuf, 512)) > 0)
		BIO_write(bio_out, inbuf, inlen);

	BIO_flush(bio_out);
	BIO_free_all(b64);
}

/* A BASE-64 ENCODER AND DECODER USING OPENSSL */
/*https://stackoverflow.com/a/16511093 */
void base64encode(const void* b64_encode_this, int encode_this_many_bytes, char* outbuf, int* outlen) {
	BIO* b64_bio, * mem_bio;      //Declares two OpenSSL BIOs: a base64 filter and a memory BIO.
	BUF_MEM* mem_bio_mem_ptr;    //Pointer to a "memory BIO" structure holding our base64 data.
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

void base64decode(const void* b64_decode_this, int decode_this_many_bytes, char* base64_decoded, int* outlen) {
	BIO* b64_bio, * mem_bio;      //Declares two OpenSSL BIOs: a base64 filter and a memory BIO.
	//char *base64_decoded = calloc( *outlen+1, sizeof(char));                       //+1 = null.
	b64_bio = BIO_new(BIO_f_base64());                      //Initialize our base64 filter BIO.
	mem_bio = BIO_new(BIO_s_mem());                         //Initialize our memory source BIO.
	BIO_write(mem_bio, b64_decode_this, decode_this_many_bytes); //Base64 data saved in source.
	BIO_push(b64_bio, mem_bio);          //Link the BIOs by creating a filter-source BIO chain.
	BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);          //Don't require trailing newlines.
	int decoded_byte_index = 0;   //Index where the next base64_decoded byte should be written.
	while (0 < BIO_read(b64_bio, base64_decoded + decoded_byte_index, 1)) { //Read byte-by-byte.
		decoded_byte_index++; //Increment the index until read of BIO decoded data is complete.
	} //Once we're done reading decoded data, BIO_read returns -1 even though there's no error.
	*outlen = decoded_byte_index;
	BIO_free_all(b64_bio);  //Destroys all BIOs in chain, starting with b64 (i.e. the 1st one).
	return;
}


void byteArrayToHexString(unsigned char* byteArray, int inlen, char* hexString) {
	int ii = 0;
	for (ii = 0; ii < inlen; ii++) {
		sprintf(&hexString[ii * 2], "%02x", byteArray[ii]);
	}
	hexString[inlen * 2] = '\0';
}



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
	int ii = 0;
	for (ii = 0; ii < 512; ii++)
		signature_bytes[ii] = 'a';

	int signatureLen;
	EVP_MD_CTX* m_RSASignCtx = EVP_MD_CTX_create();
	EVP_PKEY* priKey = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(priKey, rsa);
	if (EVP_DigestSignInit(m_RSASignCtx, NULL, EVP_sha256(), NULL, priKey) <= 0) {
		return -1;
	}
	if (EVP_DigestSignUpdate(m_RSASignCtx, message, MsgLen) <= 0) {
		return -1;
	}
	if (EVP_DigestSignFinal(m_RSASignCtx, NULL, &signatureLen) <= 0) {
		return -1;
	}
	if (EVP_DigestSignFinal(m_RSASignCtx, signature_bytes, &signatureLen) <= 0) {
		return -1;
	}


	outbuf[0] = signatureLen & 0xFF + '0';
	outbuf[1] = signatureLen >> 8 & 0xFF + '0';
	outbuf[2] = signatureLen >> 16 & 0xFF + '0';
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

int RSASign(RSA* rsa,
	const unsigned char* Msg,
	size_t MsgLen,
	unsigned char* outbuf,
	int* outbuflen) {
	size_t MsgLenEnc;
	unsigned char* EncMsg;
	EVP_MD_CTX* m_RSASignCtx = EVP_MD_CTX_create();
	EVP_PKEY* priKey = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(priKey, rsa);
	if (EVP_DigestSignInit(m_RSASignCtx, NULL, EVP_sha256(), NULL, priKey) <= 0) {
		return -1;
	}
	if (EVP_DigestSignUpdate(m_RSASignCtx, Msg, MsgLen) <= 0) {
		return -1;
	}
	if (EVP_DigestSignFinal(m_RSASignCtx, NULL, &MsgLenEnc) <= 0) {
		return -1;
	}
	EncMsg = (unsigned char*)malloc(MsgLenEnc);
	if (EVP_DigestSignFinal(m_RSASignCtx, EncMsg, &MsgLenEnc) <= 0) {
		return -1;
	}
	EVP_MD_CTX_destroy(m_RSASignCtx);
	base64encode(EncMsg, MsgLenEnc, outbuf, outbuflen);
	outbuf[*outbuflen] = 0;
	return 0;
}
void Base64Encode1(const unsigned char* buffer,
	size_t length,
	char* outbuf, int* outbuflen) {
	char* base64Text;
	BIO* bio, * b64;
	BUF_MEM* bufferPtr;
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
	*outbuflen = (*bufferPtr).length;
}

void getSha256(const unsigned char* inbuf, int inlen, char* outbuf, unsigned int* outlen) {
	unsigned char md_value[EVP_MAX_MD_SIZE];
	const EVP_MD* md = EVP_get_digestbyname("sha256");
	EVP_MD_CTX* mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, inbuf, inlen);
	EVP_DigestFinal_ex(mdctx, outbuf, outlen);
	EVP_MD_CTX_destroy(mdctx);
	EVP_cleanup();
}



// Sign String
int RsaSign1(EVP_PKEY* signing_key,
	const unsigned char* buffer,
	size_t buflen,
	unsigned char* outbuf,
	int* outbuflen) {

	EVP_PKEY_CTX* ctx;
	/* md is a SHA-256 digest in this example. */
	unsigned char md[32];
	size_t mdlen = 32, siglen = 0;
	unsigned char sign[128];

	getSha256(buffer, buflen, md, &mdlen);
	if (mdlen != 32)
		return -1;

	/*
	 * NB: assumes signing_key and md are set up before the next
	 * step. signing_key must be an RSA private key and md must
	 * point to the SHA-256 digest to be signed.
	 */
	ctx = EVP_PKEY_CTX_new(signing_key, NULL /* no engine */);
	if (!ctx)
		return -1;
	if (EVP_PKEY_sign_init(ctx) <= 0)
		return -1;
	if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
		return -1;
	if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0)
		return -1;

	/* Determine buffer length */
	if (EVP_PKEY_sign(ctx, NULL, &siglen, md, mdlen) <= 0)
		return -1;



	if (EVP_PKEY_sign(ctx, sign, &siglen, md, mdlen) <= 0)
		return -1;

	/* Signature is siglen bytes written to buffer*/
	*outbuflen = siglen;

	Base64Encode1(sign, siglen, outbuf, outbuflen);
}



// Sign String
int RsaSign1_old(RSA* rsa,
	const unsigned char* buffer,
	size_t buflen,
	unsigned char* outbuf,
	int* outbuflen) {

	const int size = RSA_size(rsa);
	unsigned char sign[128];
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
	sprintf(outbuf, "outlen=%d, size=%d", outlen, size);
	//base64encode(sign, outlen, outbuf, outbuflen);
	//outbuf[*outbuflen]=0;

	Base64Encode1(sign, outlen, outbuf, outbuflen);
}


void getContentSignatureRsa(EVP_PKEY* pkey, char* plaintext, int plaintextlen,
	int scheme, char* deviceId,
	char* contentSignature, int* contentSignatureLen,
	char* debugString) {
	char pem_str[1024];
	unsigned char sha256[SHA256_DIGEST_LENGTH];
	unsigned char sha256str[225];
	unsigned char public_key_bytes[224];
	int decoded_len;
	int sha256len;
	int signatureLen;

	//signWithRsa(rsa, plaintext, plaintextlen, signatureStr, &signatureLen);
	//RSASign(rsa, plaintext, plaintextlen, signatureStr, &signatureLen);
	RsaSign1(pkey, plaintext, plaintextlen, signatureStr, &signatureLen);
	if (scheme != 4) {
		*contentSignatureLen = sprintf(contentSignature, "data:%s;key-id:%s;scheme:%d", signatureStr, deviceId, scheme);
	}
	else {
		int pem_str_len = encode_rsa_public_key_to_pem(pkey, pem_str, 0);
		base64decode(pem_str, pem_str_len, public_key_bytes, &decoded_len);
		getSha256(public_key_bytes, decoded_len, sha256, &sha256len);
		byteArrayToHexString(sha256, sha256len, sha256str);
		*contentSignatureLen = sprintf(contentSignature, "data:%s;key-id:%s;scheme:%d", signatureStr, sha256str, scheme);
		if (debugString != NULL)
			sprintf(debugString, "pem_str:%s;plaintext:%s;data:%s;key-id:%s;scheme:%d", pem_str, plaintext, signatureStr, sha256str, scheme);
	}
}


void getContentSignatureRsa_old(RSA* rsa, char* plaintext, int plaintextlen,
	int scheme, char* deviceId,
	char* contentSignature, int* contentSignatureLen,
	char* debugString) {
	char pem_str[1024];
	unsigned char sha256[SHA256_DIGEST_LENGTH];
	unsigned char sha256str[225];
	unsigned char public_key_bytes[224];
	int decoded_len;
	int sha256len;
	int signatureLen;

	//signWithRsa(rsa, plaintext, plaintextlen, signatureStr, &signatureLen);
	//RSASign(rsa, plaintext, plaintextlen, signatureStr, &signatureLen);
	RsaSign1_old(rsa, plaintext, plaintextlen, signatureStr, &signatureLen);
	if (scheme != 4) {
		*contentSignatureLen = sprintf(contentSignature, "data:%s;key-id:%s;scheme:%d", signatureStr, deviceId, scheme);
	}
	else {
		int pem_str_len = encode_rsa_public_key_to_pem_old(rsa, pem_str, 0);
		base64decode(pem_str, pem_str_len, public_key_bytes, &decoded_len);
		getSha256(public_key_bytes, decoded_len, sha256, &sha256len);
		byteArrayToHexString(sha256, sha256len, sha256str);
		*contentSignatureLen = sprintf(contentSignature, "data:%s;key-id:%s;scheme:%d", signatureStr, sha256str, scheme);
		if (debugString != NULL)
			sprintf(debugString, "pem_str:%s;plaintext:%s;data:%s;key-id:%s;scheme:%d", pem_str, plaintext, signatureStr, sha256str, scheme);
	}
}


void preProcess_local(EVP_PKEY* pkey, char* path, char* body, char* clientVersion, char* deviceId, int scheme, char* contentSignature, char* debugString) {
	unsigned char plaintext[5555];
	int len;
	int contentSignatureLen;
	if (scheme == 2 || scheme == 3 || scheme == 4) {
		len = sprintf(plaintext, "%s%s%s%s%s", path, "%%", clientVersion, "%%", body);
	}
	else {
		len = sprintf(plaintext, "%s%s", path, body);
	}
	getContentSignatureRsa(pkey, plaintext, strlen(plaintext), scheme, deviceId, contentSignature, &contentSignatureLen, debugString);
}


void preProcess_local_old(RSA* rsa, char* path, char* body, char* clientVersion, char* deviceId, int scheme, char* contentSignature, char* debugString) {
	unsigned char plaintext[5555];
	int len;
	int contentSignatureLen;
	if (scheme == 2 || scheme == 3 || scheme == 4) {
		len = sprintf(plaintext, "%s%s%s%s%s", path, "%%", clientVersion, "%%", body);
	}
	else {
		len = sprintf(plaintext, "%s%s", path, body);
	}
	getContentSignatureRsa_old(rsa, plaintext, strlen(plaintext), scheme, deviceId, contentSignature, &contentSignatureLen, debugString);
}

__declspec(dllexport) void transmit_preProcess_old(char* path, char* body, char* clientVersion, char* deviceId, int scheme, char* contentSignature, char* debugString) {
	preProcess_local_old(rsa, path, body, clientVersion, deviceId, scheme, contentSignature, debugString);
}


void transmit_preProcess(char* path, char* body, char* clientVersion, char* deviceId, int scheme, char* contentSignature, char* debugString) {
	preProcess_local(pkey, path, body, clientVersion, deviceId, scheme, contentSignature, debugString);
}

int transmit_bind_old(char* userId, char* clientVersion, int scheme, char* appId, char* params,
	char* path, char* body, char* contentSignature, char* debugString) {
	char pem_str[4096];
	int pem_str_len = encode_rsa_public_key_to_pem_old(rsa, pem_str, 0);
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

	sprintf(randomLong, "%d", getRandomLong());
	sprintf(randomLong1, "%d", getRandomLong());
	sprintf(randomLong2, "%d", getRandomLong());

	getRandomHexString(randomHexStr, 32);
	getRandomHexString(randomHexStr1, 15);
	getRandomString(randomStr, 8);

	sprintf(path, "%s%s", "/api/v2/auth/bind?aid=", appId);
	sprintf(schemestr, "%d", scheme);
	sprintf(timestampstr, "%d", timestamp);
	sprintf(body, "%s", pem_str);

	if (params != NULL) {
		sprintf(paramsStr, "\"params\":%s", params);
	}
	else {
		sprintf(paramsStr, "");
	}

	sprintf(body, "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
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
		"\", \"type\": \"rsa\"}}, \"headers\": [{ \"type\": \"uid\",\"uid\": \"", userId, "\"}],\"push_token\": \"fakePushToken\",",
		paramsStr, "}");




	preProcess_local_old(rsa, path, body, clientVersion, "deviceId", scheme, contentSignature, debugString);

	return 0;
}

int transmit_bind(char* userId, char* clientVersion, int scheme, char* appId, char* params,
	char* path, char* body, char* contentSignature, char* debugString) {
	char pem_str[4096];
	int pem_str_len = encode_rsa_public_key_to_pem(pkey, pem_str, 0);
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

	sprintf(randomLong, "%d", getRandomLong());
	sprintf(randomLong1, "%d", getRandomLong());
	sprintf(randomLong2, "%d", getRandomLong());

	getRandomHexString(randomHexStr, 32);
	getRandomHexString(randomHexStr1, 15);
	getRandomString(randomStr, 8);

	sprintf(path, "%s%s", "/api/v2/auth/bind?aid=", appId);
	sprintf(schemestr, "%d", scheme);
	sprintf(timestampstr, "%d", timestamp);
	sprintf(body, "%s", pem_str);

	if (params != NULL) {
		sprintf(paramsStr, "\"params\":%s", params);
	}
	else {
		sprintf(paramsStr, "");
	}

	sprintf(body, "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
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
		"\", \"type\": \"rsa\"}}, \"headers\": [{ \"type\": \"uid\",\"uid\": \"", userId, "\"}],\"push_token\": \"fakePushToken\",",
		paramsStr, "}");



	preProcess_local(pkey, path, body, clientVersion, "deviceId", scheme, contentSignature, debugString);

	return 0;
}

void processTransmitJsonHeaders(cJSON* headers, char* deviceId, char* sessionId) {
	cJSON* header = NULL;
	cJSON_ArrayForEach(header, headers)
	{
		char* headerType = cJSON_GetObjectItem(header, "type")->valuestring;
		if (strcmp(headerType, "device_id") == 0) {
			strcpy(deviceId, cJSON_GetObjectItem(header, "device_id")->valuestring);
		}
		if (strcmp(headerType, "session_id") == 0) {
			strcpy(sessionId, cJSON_GetObjectItem(header, "session_id")->valuestring);
		}
	}
}

int transmit_processResponse(char* response,
	char* deviceId, char* sessionId,
	char* challenge, char* assertionId) {

	cJSON* jsonObj = cJSON_Parse(response);
	if (jsonObj == NULL) {
		return -1;
	}
	//int rc = cJSON_PrintPreallocated(json, body, 2999, 0);

	int errorCode = cJSON_GetObjectItem(jsonObj, "error_code")->valueint;
	char* errorMessage = cJSON_GetObjectItem(jsonObj, "error_message")->valuestring;
	cJSON* jsonObjData = cJSON_GetObjectItem(jsonObj, "data");
	if (jsonObjData == NULL) {
		return -1;
	}

	cJSON* stateObj = cJSON_GetObjectItem(jsonObjData, "state");

	if (cJSON_IsString(stateObj) && (stateObj->valuestring != NULL)) {
		char* state = stateObj->valuestring;
		if (strcmp(state, "completed") == 0) {
			char* token = cJSON_GetObjectItem(jsonObjData, "token")->valuestring;
		}
		else {
			cJSON* challengeObj = cJSON_GetObjectItem(jsonObjData, "challenge");
			if (cJSON_IsString(challengeObj) && (challengeObj->valuestring != NULL)) {
				strcpy(challenge, challengeObj->valuestring);
			}
			cJSON* controlFlow = cJSON_GetObjectItem(jsonObjData, "control_flow");
			cJSON* controlFlow0 = cJSON_GetArrayItem(controlFlow, 0);
			cJSON* assertionIdObj = cJSON_GetObjectItem(controlFlow0, "assertion_id");
			if (cJSON_IsString(assertionIdObj) && (assertionIdObj->valuestring != NULL)) {
				strcpy(assertionId, assertionIdObj->valuestring);
			}

			cJSON* appData = cJSON_GetObjectItem(controlFlow0, "app_data");
			if (appData != NULL) {
			}
			else {
			}

			cJSON* methods = cJSON_GetObjectItem(controlFlow0, "methods");
			if (methods != NULL) {
				cJSON* method0 = cJSON_GetArrayItem(methods, 0);
				strcpy(assertionId, cJSON_GetObjectItem(method0, "assertion_id")->valuestring);
			}
			else {
			}

			cJSON* headers = cJSON_GetObjectItem(jsonObj, "headers");
			processTransmitJsonHeaders(headers, deviceId, sessionId);
		}
	}
	cJSON_Delete(jsonObj);
	return 0;
}




void transmit_processPasswordAuthentication(char* userId, char* passwordValue, char* challenge, char* assertionId, char* body) {
	sprintf(body, "%s%s%s%s%s%s%s%s%s",
		"{\"headers\":[{\"type\":\"uid\",\"uid\":\"",
		userId,
		"\"}],\"data\":{\"action\":\"authentication\",\"assert\":\"authenticate\",\"assertion_id\":\"",
		assertionId,
		"\",\"fch\":\"",
		challenge,
		"\",\"data\":{\"password\":\"",
		passwordValue,
		"\"},\"method\":\"password\"}}");
}


/* aaaack but it's fast and const should make it shared text page. */
static const unsigned char pr2six[256] =
{
	/* ASCII table */
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
	64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
	64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
};

int Base64decode_len(const char* bufcoded)
{
	int nbytesdecoded;
	register const unsigned char* bufin;
	register int nprbytes;

	bufin = (const unsigned char*)bufcoded;
	while (pr2six[*(bufin++)] <= 63);

	nprbytes = (bufin - (const unsigned char*)bufcoded) - 1;
	nbytesdecoded = ((nprbytes + 3) / 4) * 3;

	return nbytesdecoded + 1;
}

int Base64decode(char* bufplain, const char* bufcoded)
{
	int nbytesdecoded;
	register const unsigned char* bufin;
	register unsigned char* bufout;
	register int nprbytes;

	bufin = (const unsigned char*)bufcoded;
	while (pr2six[*(bufin++)] <= 63);
	nprbytes = (bufin - (const unsigned char*)bufcoded) - 1;
	nbytesdecoded = ((nprbytes + 3) / 4) * 3;

	bufout = (unsigned char*)bufplain;
	bufin = (const unsigned char*)bufcoded;

	while (nprbytes > 4) {
		*(bufout++) =
			(unsigned char)(pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
		*(bufout++) =
			(unsigned char)(pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
		*(bufout++) =
			(unsigned char)(pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
		bufin += 4;
		nprbytes -= 4;
	}

	/* Note: (nprbytes == 1) would be an error, so just ingore that case */
	if (nprbytes > 1) {
		*(bufout++) =
			(unsigned char)(pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
	}
	if (nprbytes > 2) {
		*(bufout++) =
			(unsigned char)(pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
	}
	if (nprbytes > 3) {
		*(bufout++) =
			(unsigned char)(pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
	}

	*(bufout++) = '\0';
	nbytesdecoded -= (4 - nprbytes) & 3;
	return nbytesdecoded;
}

static const char basis_64[] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int Base64encode_len(int len)
{
	return ((len + 2) / 3 * 4) + 1;
}

int Base64encode(char* encoded, const char* string, int len)
{
	int i;
	char* p;

	p = encoded;
	for (i = 0; i < len - 2; i += 3) {
		*p++ = basis_64[(string[i] >> 2) & 0x3F];
		*p++ = basis_64[((string[i] & 0x3) << 4) |
			((int)(string[i + 1] & 0xF0) >> 4)];
		*p++ = basis_64[((string[i + 1] & 0xF) << 2) |
			((int)(string[i + 2] & 0xC0) >> 6)];
		*p++ = basis_64[string[i + 2] & 0x3F];
	}
	if (i < len) {
		*p++ = basis_64[(string[i] >> 2) & 0x3F];
		if (i == (len - 1)) {
			*p++ = basis_64[((string[i] & 0x3) << 4)];
			*p++ = '=';
		}
		else {
			*p++ = basis_64[((string[i] & 0x3) << 4) |
				((int)(string[i + 1] & 0xF0) >> 4)];
			*p++ = basis_64[((string[i + 1] & 0xF) << 2)];
		}
		*p++ = '=';
	}

	*p++ = '\0';
	return p - encoded;
}


/*
{
"sub": "harrison21",
"op": "auth",
"lvl": 1,
"dsid": "179878e4-7938-4d84-aff3-623045b07c61",
"oa2_pf_access_token": "0004yPE6abTyWDFVlJwJ3DyHyNil",
"iss": "TS",
"mcg_hrt_protected_endpoints": "{'/sec/transfer/execute-transfer-v1':'tab_hrt_transfer_execute_transfer','/sec/payment/execute-payment-v1':'tab_hrt_payment_execute_payment'}",
"pid": "tab_login_journey",
"sid": "3931a96d-48b4-40aa-b851-94bb35d19ac4",
"aud": "tab_mobile_app",
"pvid": "default_version",
"exp": 1655823583,
"xsmid": "81de124d-fe61-4579-83d4-c79fec05e5ef",
"iat": 1655821783,
"jti": "2ce3a896-8d44-49cd-a5df-27f57bdf2189",
"did": "88c6a09b-2856-4c33-974c-fe233ddb1d01"
}
*/

int  transmit_processSuccessResponse(char* response, char* key, char* value, char* debugString) {
	char test_out[512];
	int  test_out_len = 512;
	char** tokens;
	cJSON* jsonObj = cJSON_Parse(response);
	if (jsonObj == NULL) {
		if (debugString != NULL)    sprintf(debugString, "failed to parse response");
		return -1;
	}

	cJSON* dataJsonObj = cJSON_GetObjectItem(jsonObj, "data");
	if (dataJsonObj == NULL) {
		if (debugString != NULL) sprintf(debugString, "data not found");
		return -3;
	}

	char* token = cJSON_GetObjectItem(dataJsonObj, "token")->valuestring;
	if (token == NULL) {
		if (debugString != NULL) sprintf(debugString, "token not found");
		return -2;
	}

	tokens = str_split(token, '.');
	if (debugString != NULL)
		sprintf(debugString, "--%s--", tokens[1]);


	Base64decode(test_out, tokens[1]);

	cJSON_Delete(jsonObj);
	if (debugString != NULL)
		sprintf(debugString, "%s", test_out);

	cJSON * jsonObj1 = cJSON_Parse(test_out);
	char * val = cJSON_GetObjectItem(jsonObj1, key)->valuestring;

	sprintf(value, "%s", val);
	
	cJSON_Delete(jsonObj1);

	if (tokens)
	{
		int i;
		for (i = 0; *(tokens + i); i++)
		{
			free(*(tokens + i));
		}
		free(tokens);
	}

	return 0;
}

