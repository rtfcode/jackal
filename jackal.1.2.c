/* jackal - certificate cloner - K Sheldrake
**
** Copyright (C) 2015  Kevin Sheldrake
** 
** This file is part of jackal.
**
** Jackal is free software; you can redistribute it and/or
** modify it under the terms of the GNU General Public License
** as published by the Free Software Foundation; either version 2
** of the License, or (at your option) any later version.
** 
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
** 
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
**
**
** jackal clones SSL certificates.  The purpose is to automate and simplify a step in the SSL MITM process.
**
** SSL/TLS connections are established on trust provided by the certificates that are exchanged.  Typically
** the server sends a certificate to the client for verification.  All certificates are signed by another
** certificate.  Self-signed certificates are signed by themselves; in all other cases, an end user cerficate
** is signed by an intermediate certificate authority, which is in-turn signed by other intermediates, the
** last of which is signed by a root certificate authority.  The root certificate authority is self-signed
** and should be available to the tool or client that wants to verify the end user certificate.
**
** To verify an end user certificate a tool or client finds the certificate that signed it, and then recursively
** verifies that.  If any of the certificates are contained in the CA store, the certificate is deemed to have
** a valid signature.  There are other checks, such as validity dates and confirmation of the end user
** certificate details to ensure the right certificate is in use.
**
** Man-in-the-middle attacks are possible if the certificate verification routines are flawed or if it is
** possible to add a fake CA to the CA store.  In order to effect such an attack, certificates that mimic
** the real certificates are required.  This tool, jackal, makes fake certificates that are identical to
** the originals except for the change of keys.
**
** Create a new CA with:
** % openssl genrsa -des3 -out ca.key 2048
** % openssl req -new -x509 -days 3650 -key ca.key -out ca.pem
**
** Check certificate with:
** % openssl x509 -in certificate.pem -noout -text
**
** Verify certificate trust with:
** % openssl verify -CAfile ca.pem -untrusted intermediatecas.pem certificate.pem
**
**
** Compile with:
** cc -o jackal jackal.c -lssl -lcrypto
**
** History:
**
** v1.0 - 8/11/2014
**
** Uplifted to v1.0 for release.
** Tidied welcome message.
** Added quote from The Day of the Jackal. :)
**
** v0.3 - 8/11/2014
**
** Now clones whole certificate chains.
**
** v0.2 - 30/10/2014
**
** Rewrite of version 1, same functionality.
**
** v0.1 - 30/10/2014
**
** Proof of concept.
** Takes one certificate and one CA and makes a new certificate with a new key that matches the original
** and is signed by the supplied CA.
**
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <openssl/engine.h>

#define HEX_PER_ROW 16
#define ALGO_LEN 64
#define OBJSTR_LEN 1024

void usage(char *msg)
{
	printf("ONLY USE FOR TESTING (don't be a muppet)\n\n");
	printf("jackal -c certificate\n");
	printf("  displays certificate details\n");
	printf("jackal -sl -c certificate(s) -o outputfilespec [-C newCAcert -K newCAkey]\n");
	printf("  signs the leaf certificate with the CA if specified or self-signs it if not\n");
	printf("jackal -sc -c certificates -o outputfilespec [-C newCAcert -K newCAkey]\n");
	printf("  signs the certificate chain with the CA if specified or self-signs the root if not\n");
	printf("jackal -sr -c certificates -o outputfilesepc -C newCAcert -K newCAkey\n");
	printf("  signs the certificate chain, replacing the current root with the specified CA\n");
	printf("\n");
	printf("outputfilespec will be appended with .pem/.key with -sl and .n.pem/.key with -sc/r\n");
	printf("\n");

	if (msg) {
		printf("%s\n", msg);
		exit(1);
	}

	exit(0);
}


void hexdump(unsigned char *data, int data_len, int indent)
{
	int i, j;

	for (i=0; i<data_len; i++) {
		if ((i % HEX_PER_ROW) == 0) {
			for (j=0; j<indent; j++) {
				printf("    ");
			}
		}
		printf("%02x", data[i]);
		if ((i % HEX_PER_ROW) == HEX_PER_ROW - 1) {
			printf("\n");
		} else {
			if (i < data_len - 1) {
				printf(":");
			}
		}

	}
	if ((data_len % HEX_PER_ROW) != 0) {
		printf("\n");
	}
}


void print_cert(X509 *cert)
{
	const unsigned char *serialnumber = NULL;
	const char *algorithm = NULL;
	const char *pubalgo = NULL;
	int seriallength = 0;
	char *issuer;
	char *subject;
	ASN1_TIME *time = NULL;
	char notBefore[ALGO_LEN];
	char notAfter[ALGO_LEN];
	EVP_PKEY *certkey = NULL;
	char *modulus = NULL;
	const unsigned char *hash = NULL;
	int hashlength = 0;
	const ASN1_BIT_STRING *signature;
	const X509_ALGOR *sig_algo;
	const BIGNUM *pkey_mod;

	if (!cert) {
		printf("print_cert invalid params\n");
		exit(1);
	}

	seriallength = ASN1_STRING_length(X509_get_serialNumber(cert));
	X509_get0_signature(&signature, &sig_algo, cert);
	hashlength = ASN1_STRING_length(signature);

	algorithm = OBJ_nid2ln(X509_get_signature_nid(cert));

	certkey = X509_get_pubkey(cert);
	pubalgo = OBJ_nid2ln(EVP_PKEY_base_id(certkey));
	RSA_get0_key(EVP_PKEY_get0_RSA(certkey), &pkey_mod, NULL, NULL);

	modulus = BN_bn2hex(pkey_mod);

	hash = ASN1_STRING_get0_data(signature);

	serialnumber = ASN1_STRING_get0_data(X509_get_serialNumber(cert));

	issuer = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
	subject = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);

	time = X509_get_notBefore(cert);
	strncpy(notBefore, (const char *)time->data, ALGO_LEN);
	notBefore[ALGO_LEN - 1] = 0x00;
	time = X509_get_notAfter(cert);
	strncpy(notAfter, (const char *)time->data, ALGO_LEN);
	notAfter[ALGO_LEN - 1] = 0x00;

	printf("Certificate:\n");
	printf("    Data:\n");
	printf("        Version: 0x%0lx\n", X509_get_version(cert));
	printf("        Serial Number:\n");
	hexdump((unsigned char *)serialnumber, seriallength, 3);
	printf("    Signature Algorithm: %s\n", algorithm);
	printf("        Issuer: %s\n", issuer);
	printf("        Validity\n");
	printf("            Not Before: %s\n", notBefore);
	printf("            Not After : %s\n", notAfter);
	printf("        Subject: %s\n", subject);
	printf("            Subject Public Key Info:\n");
	printf("                Public Key Algorithm: %s\n", pubalgo);
	printf("                    Public-Key: (%d bit)\n", EVP_PKEY_bits(certkey));
	printf("                    Modulus:%s\n", modulus);
	printf("    Signature Algorithm: %s\n", algorithm);
	hexdump((unsigned char *)hash, hashlength, 2);

}


X509 *find_issuer(X509_STORE_CTX *ctx, STACK_OF(X509) *sk, X509 *x)
{
	int i;
	X509 *issuer;
	X509_STORE_CTX_check_issued_fn check_issued;

	if ((!ctx) || (!sk) || (!x)) {
		printf("find_issuer invalid params\n");
		exit(1);
	}

	check_issued = X509_STORE_CTX_get_check_issued(ctx);

	for (i=0; i < sk_X509_num(sk); i++) {
		issuer = sk_X509_value(sk, i);
		if (check_issued(ctx, x, issuer))
			return issuer;
	}
	return NULL;
}


void get_cert_from_file(SSL_CTX **sslctx, SSL **ssl, X509 **crt, char *certfile)
{
	if ((!sslctx) || (!ssl) || (!crt) || (!certfile)) {
		printf("get_cert_from_file invalid params\n");
		exit(1);
	}

	/* open certificate file */
	*sslctx = SSL_CTX_new(TLS_server_method());
	if (!*sslctx) {
		printf("get_cert_from_file SSL_CTX_new failed\n");
		exit(1);
	}
	if (!SSL_CTX_use_certificate_chain_file(*sslctx, certfile)) {
		printf("get_cert_from_file SSL_CTX_use_chain_certificate_file failed\n");
		exit(1);
	}

	*ssl = SSL_new(*sslctx);
	if (!*ssl) {
		printf("get_cert_from_file SSL_new failed\n");
		exit(1);
	}
	*crt = SSL_get_certificate(*ssl);
	if (!*crt) {
		printf("get_cert_from_file SSL_get_certifcate failed\n");
		exit(1);
	}
}

STACK_OF(X509) *get_extra_certs(SSL_CTX *sslctx)
{
	STACK_OF(X509) *ca_stack;

	if (!sslctx) {
		printf("get_extra_certs invalid params\n");
		exit(1);
	}

    if (SSL_CTX_get_extra_chain_certs(sslctx, &ca_stack)) {
//        printf("SSL_CTX_get_extra_chain_certs_only success\n");
    } else {
        printf("SSL_CTX_get_extra_chain_certs_only failed\n");
        exit(0);
    }

	if (!ca_stack) {
		printf("Cert file contains 1 certificate\n");
	} else {
		printf("Cert file contains >1 certificates\n");
	}

	return ca_stack;
}


void get_key_from_file(SSL *cassl, char *cakeyfile)
{
	if ((!cassl) || (!cakeyfile)) {
		printf("get_key_from_file invalid params\n");
		exit(1);
	}

	printf("Loading CA key\n");

	/* read CA key file */
	if (!SSL_use_PrivateKey_file(cassl, cakeyfile, SSL_FILETYPE_PEM)) {
		printf("get_key_from_file SSL_use_PrivateKey_file failed\n");
		exit(1);
	}
}


int get_signing_algo(X509 *crt)
{
	int nid;

	if (!crt) {
		printf("get_signing_algo invalid params\n");
		exit(1);
	}

	/* get signing algorithm */
	nid = X509_get_signature_nid(crt);
	if (!nid) {
		printf("get_signing_algo OBJ_obj2nid failed\n");
		exit(1);
	}

	return nid;
}


const char *get_public_algo(X509 *crt)
{
	const char *pubalgo = OPENSSL_malloc(ALGO_LEN);
	EVP_PKEY *certkey;

	if (!crt) {
		printf("get_public_algo invalid params\n");
		exit(1);
	}

	if (!pubalgo) {
		printf("get_public_algo malloc error\n");
		exit(1);
	}

	certkey = X509_get_pubkey(crt);
	pubalgo = OBJ_nid2ln(EVP_PKEY_base_id(certkey));

	return pubalgo;
}


int get_pub_key_size(X509 *crt)
{
	EVP_PKEY *certkey;

	if (!crt) {
		printf("get_pub_key_size invalid params\n");
		exit(1);
	}

	certkey = X509_get_pubkey(crt);

	if (!certkey) {
		printf("get_pub_key_size X509_get_pubkey failed\n");
		exit(1);
	}

	return EVP_PKEY_bits(certkey);
}


EVP_PKEY *gen_new_key(int certkeysize)
{
	RSA *newrsa = NULL;
	EVP_PKEY *newkey = NULL;
	BIGNUM *e = NULL;

	if (certkeysize <= 0) {
		printf("gen_new_key invalid params\n");
		exit(1);
	}

	if (!BN_dec2bn(&e, "65537")) {
		printf("gen_new_key BN_dec2bn failed\n");
		exit(1);
	}
	newrsa = RSA_new();
	if (!newrsa) {
		printf("gen_new_key RSA_new failed\n");
		exit(1);
	}
	if (!RSA_generate_key_ex(newrsa, certkeysize, e, 0)) {
		printf("gen_new_key RSA_generate_key_ex failed\n");
		exit(1);
	}
	newkey = EVP_PKEY_new();
	if (!newkey) {
		printf("gen_new_key EVP_PKEY_new failed\n");
		exit(1);
	}

	if (!EVP_PKEY_assign_RSA(newkey, newrsa)) {
		printf("gen_new_key EVP_PKEY_assign_RSA failed\n");
		exit(1);
	}

	return newkey;
}


void assign_key_to_cert(X509 *crt, EVP_PKEY *newkey)
{
	if ((!crt) || (!newkey)) {
		printf("assign_key_to_cert invalid params\n");
		exit(1);
	}

	if (!X509_set_pubkey(crt, newkey)) {
		printf("assign_key_to_cert X509_set_pubkey failed\n");
		exit(1);
	}
}


void copy_subject_to_issuer(X509 *cacrt, X509 *crt)
{
	X509_NAME *caname;

	if ((!cacrt) || (!crt)) {
		printf("copy_subject_to_issuer invalid params\n");
		exit(1);
	}

	caname = X509_get_subject_name(cacrt);
	if (!caname) {
		printf("copy_subject_to_issuer X509_get_subject_name failed\n");
		exit(1);
	}

	printf("ca subject is '%s'\n", X509_NAME_oneline(caname, NULL, 0));

	if (!X509_set_issuer_name(crt, caname)) {
		printf("copy_subject_to_issuer X509_set_issuer_name failed\n");
		exit(1);
	}
}


int ext_exists(X509 *crt, int nid)
{
	int num_exts;
	const STACK_OF(X509_EXTENSION) *exts;
	X509_EXTENSION *ex;
	ASN1_OBJECT *obj;
	int i;

	if ((!crt) || (!nid)) {
		printf("ext_exists invalid params\n");
		exit(1);
	}

	exts = X509_get0_extensions(crt);
	if (exts) {
		num_exts = sk_X509_EXTENSION_num(exts);
	} else {
		num_exts = 0;
	}

	for (i=0; i<num_exts; i++) {

		ex = sk_X509_EXTENSION_value(exts, i);
		if (!ex) {
			printf("ext_exists sk_X509_EXTENSION_value failed\n");
			exit(1);
		}

		obj = X509_EXTENSION_get_object(ex);
		if (!obj) {
			printf("ext_exists X509_EXTENSION_get_object failed\n");
			exit(1);
		}

		if (OBJ_obj2nid(obj) == nid) {
			return 1;
		}
	}

	return 0;
}


void create_ext_ctx(X509 *cacrt, X509 *crt, X509V3_CTX *extctx)
{
	if ((!cacrt) || (!crt) || (!extctx)) {
		printf("create_ext_ctx invalid params\n");
		exit(1);
	}

	X509V3_set_ctx_nodb(extctx);

	X509V3_set_ctx(extctx, cacrt, crt, NULL, NULL, 0);
}


void delete_extension(X509 *crt, int nid)
{
	int idx;
	X509_EXTENSION *ex;

	if (!crt) {
		printf("delete_extension invalid params\n");
		exit(1);
	}

	/* delete extension */
	idx = X509_get_ext_by_NID(crt, nid, -1);
	if (idx < 0) {
		printf("delete_extension X509_get_ext_by_NID failed\n");
		exit(1);
	}
	ex = X509_get_ext(crt, idx);
	if (!ex) {
		printf("delete_extension X509_get_ext failed\n");
		exit(1);
	}
	if (!X509_delete_ext(crt, idx)) {
		printf("delete_extension X509_delete_ext failed\n");
		exit(1);
	}
	X509_EXTENSION_free(ex);
}


void add_extension_raw(X509 *crt, int nid, void *value, int critical)
{
	X509_EXTENSION *ex = NULL;

	if ((!crt) || (!value)) {
		printf("add_extension_raw invalid params\n");
		exit(1);
	}

	ex = X509V3_EXT_i2d(nid, critical, value);
	if (!ex) {
		printf("add_extension_raw X509V3_EXT_i2d failed\n");
		exit(1);
	}
	if (!X509_add_ext(crt, ex, -1)) {
		printf("add_extension_raw X509_add_ext failed\n");
		exit(1);
	}
}


void add_extension(X509 *crt, X509V3_CTX *extctx, int nid, char *value)
{
	X509_EXTENSION *newext;

	if ((!crt) || (!extctx) || (!value)) {
		printf("add_extension invalid params\n");
		exit(1);
	}

	newext = X509V3_EXT_conf_nid(NULL, extctx, nid, value);
	if (!newext) {
		printf("add_extension X509V3_EXT_conf_nid failed\n");
		exit(1);
	}
	if (!X509_add_ext(crt, newext, -1)) {
		printf("add_extension X509_add_ext failed\n");
		exit(1);
	}
	X509_EXTENSION_free(newext);
}


EVP_PKEY *get_private_key(SSL *cassl)
{
	EVP_PKEY *cacertkey;

	if (!cassl) {
		printf("get_private_key invalid params\n");
		exit(1);
	}

	cacertkey = SSL_get_privatekey(cassl);
	if (!cacertkey) {
		printf("get_private_key SSL_get_privatekey failed\n");
		exit(1);
	}

	return cacertkey;
}


void sign_cert(X509 *crt, EVP_PKEY *cacertkey, int algorithm)
{

	if ((!crt) || (!cacertkey) || (!algorithm)) {
		printf("sign_cert invalid params\n");
		exit(1);
	}

	switch(algorithm) {
		case NID_md5WithRSAEncryption:
		case NID_md5WithRSA:
			if (!X509_sign(crt, cacertkey, EVP_md5())) {
				printf("X509_sign md5 failed\n");
				exit(1);
			}
			break;
		case NID_shaWithRSAEncryption:
		case NID_sha1WithRSAEncryption:
		case NID_sha1WithRSA:
			if (!X509_sign(crt, cacertkey, EVP_sha1())) {
				printf("X509_sign sha1 failed\n");
				exit(1);
			}
			break;
		case NID_sha256WithRSAEncryption:
			if (!X509_sign(crt, cacertkey, EVP_sha256())) {
				printf("X509_sign sha256 failed\n");
				exit(1);
			}
			break;
		case NID_sha384WithRSAEncryption:
			if (!X509_sign(crt, cacertkey, EVP_sha384())) {
				printf("X509_sign sha384 failed\n");
				exit(1);
			}
			break;
		case NID_sha512WithRSAEncryption:
			if (!X509_sign(crt, cacertkey, EVP_sha512())) {
				printf("X509_sign sha512 failed\n");
				exit(1);
			}
			break;
		case NID_sha224WithRSAEncryption:
			if (!X509_sign(crt, cacertkey, EVP_sha224())) {
				printf("X509_sign sha224 failed\n");
				exit(1);
			}
			break;
		default:
			printf("Unknown signing algorithm, using SHA256\n");
			if (!X509_sign(crt, cacertkey, EVP_sha256())) {
				printf("X509_sign default failed\n");
				exit(1);
			}
	}
}


FILE *open_output_file(char *filename)
{
	FILE *fp;

	if (!filename) {
		printf("open_output_file invalid params\n");
		exit(1);
	}

	fp = fopen(filename, "w");
	if (!fp) {
		printf("open_output_file fopen failed\n");
		exit(1);
	}

	return fp;
}


void write_cert(X509 *crt, FILE *fp)
{
	if ((!crt) || (!fp)) {
		printf("write_cert invalid params\n");
		exit(1);
	}

	if (!PEM_write_X509(fp, crt)) {
		printf("write_cert PEM_write_X509 failed\n");
		exit(1);
	}
}


void write_key(EVP_PKEY *key, FILE *fp)
{
	if ((!key) || (!fp)) {
		printf("write_key invalid params\n");
		exit(1);
	}

	if (!PEM_write_PrivateKey(fp, key, NULL, NULL, 0, NULL, NULL)) {
		printf("write_key PEM_write_PrivateKey failed\n");
		exit(1);
	}
}


int isCritical(X509 *crt, int nid)
{
	X509_EXTENSION *ex = NULL;
	int idx = 0;

	if ((!crt) || (nid < 0)) {
		printf("isCritical invalid params\n");
		exit(1);
	}

	idx = X509_get_ext_by_NID(crt, nid, -1);

	if (idx < 0) {
		printf("isCritical X509_get_ext_by_NID failed\n");
		exit(1);
	}

	ex = X509_get_ext(crt, idx);

	if (!ex) {
		printf("isCritical X509_get_ext failed\n");
		exit(1);
	}

	return X509_EXTENSION_get_critical(ex);
}


/* set_CA_flags */
void set_CA_flags(X509 *crt, X509V3_CTX *extctx)
{
	long ver = 0;
	ASN1_BIT_STRING *usage;
	ASN1_BIT_STRING *newusage;
	int usage_val;
	unsigned char newusage_data[2];
	int critical = 0;

	if ((!crt) || (!extctx)) {
		printf("set_CA_flags invalid params\n");
		exit(1);
	}

	ver = X509_get_version(crt);

	switch(ver) {
		case 0: /* version 1 */
			/* nothing to do as self-signing implies CA */
			break;
		case 1: /* version 2 */
			/* nothing to do as self-signing implies CA */
			break;
		case 2: /* version 3+ */
			/* set v3 Basic Constraints: CA: True */
			if (ext_exists(crt, NID_basic_constraints)) {
				critical = isCritical(crt, NID_basic_constraints);
				delete_extension(crt, NID_basic_constraints);
			}
			if (critical) {
				add_extension(crt, extctx, NID_basic_constraints, "critical,CA:TRUE");
			} else {
				add_extension(crt, extctx, NID_basic_constraints, "CA:TRUE");
			}

			printf("basic constraints extension added as CA\n");

			/* set v3 Key Usage: Key Cert Sign */
			if (ext_exists(crt, NID_key_usage)) {
				/* examine key usage extension and update if necessary */
				usage = X509_get_ext_d2i(crt, NID_key_usage, &critical, NULL);
				if (!usage) {
					printf("set_CA_flags X509_get_ext_d2i failed\n");
					exit(1);
				}

				if (usage->length < 1) {
					printf("set_CA_flags key usage length < 1\n");
					exit(1);
				}
				usage_val = usage->data[0];
				if (usage->length > 1) {
					usage_val = usage_val | (usage->data[1] << 8);
				}

				if (!(usage_val & X509v3_KU_KEY_CERT_SIGN)) {
					/* add key cert sign flag */
					newusage = ASN1_BIT_STRING_new();
					if (!newusage) {
						printf("set_CA_flags ASN1_BIT_STRING_new failed\n");
						exit(1);
					}
					usage_val = usage_val | X509v3_KU_KEY_CERT_SIGN;
					newusage_data[0] = (unsigned char) (usage_val & 0xff);
					newusage_data[1] = (unsigned char) ((usage_val >> 8) & 0xff);
					delete_extension(crt, NID_key_usage);
					if (!ASN1_BIT_STRING_set(newusage, newusage_data, 2)) {
						printf("set_CA_flags ASN1_BIT_STRING_set failed\n");
						exit(1);
					}
					add_extension_raw(crt, NID_key_usage, newusage, critical);
				}
			} else {
				/* add a key usage extension */
				newusage = ASN1_BIT_STRING_new();
				if (!newusage) {
					printf("set_CA_flags ASN1_BIT_STRING_new failed\n");
					exit(1);
				}
				usage_val = X509v3_KU_KEY_CERT_SIGN;
				newusage_data[0] = (unsigned char) (usage_val & 0xff);
				newusage_data[1] = (unsigned char) ((usage_val >> 8) & 0xff);
				if (!ASN1_BIT_STRING_set(newusage, newusage_data, 2)) {
					printf("set_CA_flags ASN1_BIT_STRING_set failed\n");
					exit(1);
				}
				add_extension_raw(crt, NID_key_usage, newusage, critical);
			}

			break;
		default:
			printf("Invalid certificate version: %ld\n", ver);
			exit(1);
	}
}


/* clone_certificate */
EVP_PKEY *clone_certificate(X509 *crt, X509 *issuercrt, EVP_PKEY *issuercertkey, char *outputfile, int depth)
{
	char outputcert[256];
	char outputkey[256];

	EVP_PKEY *newkey = NULL;
	int certkeysize = 0;
	X509V3_CTX extctx;
	int algorithm = 0;
	int issuerversion = 0;

	FILE *pemfp;
	FILE *keyfp;

	if ((!crt) || (!outputfile) || (depth < 0)) {
		printf("clone_certificate invalid params\n");
		exit(1);
	}

	/* get issuer certificate version */
	if (issuercrt) {
		issuerversion = X509_get_version(issuercrt);
	} else {
		issuerversion = X509_get_version(crt);
	}

	printf("\n### %s ### v%ld\n", X509_NAME_oneline(X509_get_subject_name(crt), NULL, 0), X509_get_version(crt) + 1);

	/* get signing algorithm */
	algorithm = get_signing_algo(crt);

	printf("sig hash type = %d\n", algorithm);

	/* get public key size */
	certkeysize = get_pub_key_size(crt);

	printf("public key size = %d\n", certkeysize);

	/* generate new key */
	newkey = gen_new_key(certkeysize);

	/* assign key to certificate */
	assign_key_to_cert(crt, newkey);

	/* copy the subject name of the issuer to the issuer name of the cert */
	if (issuercrt) {
		copy_subject_to_issuer(issuercrt, crt);
	} else {
		copy_subject_to_issuer(crt, crt);
	}

	/* create an extension context linking the CA cert to the subject cert */
	if (issuercrt) {
		create_ext_ctx(issuercrt, crt, &extctx);
	} else {
		create_ext_ctx(crt, crt, &extctx);
	}

	/* correct the subject key identifier if it exists */
	if (ext_exists(crt, NID_subject_key_identifier)) {
		delete_extension(crt, NID_subject_key_identifier);
		add_extension(crt, &extctx, NID_subject_key_identifier, "hash");
		printf("subject key identifier changed\n");
	}

	if (issuerversion == 2) {

		/* correct the authority key identifier if it exists */
		if (ext_exists(crt, NID_authority_key_identifier)) {
			delete_extension(crt, NID_authority_key_identifier);
			add_extension(crt, &extctx, NID_authority_key_identifier, "keyid:always");
			printf("authority key identifier changed\n");
		}
	}

	/* set CA flags for self-signed certs (no issuer) and where depth > 1 (intermediate or CA) */
	if ((!issuercrt) || (depth)) {
		set_CA_flags(crt, &extctx);
	}

	/* sign the cert */
	if (issuercrt) {
		sign_cert(crt, issuercertkey, algorithm);
	} else {
		sign_cert(crt, newkey, algorithm);
	}

	/* create output file names */
	snprintf(outputcert, 256, "%s.pem", outputfile);
	snprintf(outputkey, 256, "%s.key", outputfile);

	/* open output files */
	pemfp = open_output_file(outputcert);
	keyfp = open_output_file(outputkey);

	/* write the cert */
	write_cert(crt, pemfp);

	/* write the new private key */
	write_key(newkey, keyfp);

	/* close the output files */
	fclose(pemfp);
	fclose(keyfp);

	return newkey;
}


/* clone_chain */
EVP_PKEY *clone_chain(X509 *crt, STACK_OF(X509) *ca_stack, X509 *cacrt, EVP_PKEY *cakey, char *outputfile, int depth, char command)
{
	EVP_PKEY *key = NULL;
	X509_STORE_CTX *storectx = NULL;
	X509 *issuer = NULL;

	if ((!crt) || (!ca_stack) || (!outputfile)) {
		printf("clone_chain invalid params\n");
		exit(1);
	}

	/* create context for chain */
	storectx = X509_STORE_CTX_new();
	if (!storectx) {
		printf("clone_chain X509_STORE_CTX_new failed\n");
		exit(1);
	}

	if (!X509_STORE_CTX_init(storectx, NULL, crt, ca_stack)) {
		printf("clone_chain X509_STORE_init failed\n");
		exit(1);
	}

	/* retrieve issuer key */
	issuer = find_issuer(storectx, ca_stack, crt);

	if ((issuer) && (X509_name_cmp(X509_get_subject_name(crt), X509_get_issuer_name(crt)))) {
		/* not at end of chain */

		/* clone rest of chain */
		key = clone_chain(issuer, ca_stack, cacrt, cakey, outputfile, depth + 1, command);

		/* fix up output file name */
		outputfile[strlen(outputfile) - 1] = depth + '0';

		/* sign this cert and return the key */
		if (key != cakey) {
			key = clone_certificate(crt, issuer, key, outputfile, depth);
		} else {
			key = clone_certificate(crt, cacrt, cakey, outputfile, depth);
		}

	} else {
		/* end of chain */

		/* fix up output file name */
		outputfile[strlen(outputfile) - 1] = depth + '0';

		if (command == 'c') {
			/* sign this cert and return the key */
			key = clone_certificate(crt, cacrt, cakey, outputfile, depth);
		} else if (command == 'r') {
			/* return the ca key */
			key = cakey;
		} else {
			printf("clone_chain invalid command\n");
			exit(1);
		}
	}

	return key;
}




int main(int argc, char *argv[])
{
	char c;

	char *certfile = NULL;
	char *cacertfile = NULL;
	char *cakeyfile = NULL;
	char *outputfile = NULL;
	char *outputchainfile = NULL;

	SSL_CTX *sslctx = NULL;
	SSL *ssl = NULL;
	X509 *crt = NULL;
	STACK_OF(X509) *ca_stack = NULL;
	X509 *tempcert = NULL;
	SSL_CTX *casslctx = NULL;
	SSL *cassl = NULL;
	X509 *cacrt = NULL;
	X509_STORE_CTX *storectx = NULL;
	EVP_PKEY *issuerkey = NULL;

	char command = ' ';
	int haveCA = 0;

	printf("Jackal v1.0 - Certificate Cloner - K Sheldrake\n");
	printf("----------------------------------------------\n\n");
	printf("Jackal comes with ABSOLUTELY NO WARRANTY.\n");
	printf("This is free software, and you are welcome\n");
	printf("to redistribute it under certain conditions.\n");
	printf("Jackal is provided under GPLv2.\n");
	printf("See http://www.gnu.org/licenses/gpl-2.0.html\n");
	printf("for details.\n\n");
	printf("\"Certainly, the Jackal masqueraded as an Englishman,\n");
	printf("but he also masqueraded as a Dane and as a Frenchman.\n");
	printf("So there's no way of proving his identity at all.\"\n");
	printf("                             - The Day of the Jackal\n\n\n");

	/* sort options */
	opterr = 0;

	while((c = getopt(argc, argv, "hc:C:K:o:s:")) != -1) {
		switch(c) {
			case 'h':
				usage(NULL);
				break;
			case 'c':
				if (strlen(optarg) > 0) {
					certfile = optarg;
				}
				break;
			case 'C':
				if (strlen(optarg) > 0) {
					cacertfile = optarg;
				}
				break;
			case 'K':
				if (strlen(optarg) > 0) {
					cakeyfile = optarg;
				}
				break;
			case 'o':
				if (strlen(optarg) > 0) {
					outputfile = optarg;
				}
				break;
			case 's':
				if (strlen(optarg) == 1) {
					command = *optarg;
				}
				break;
			default:
				usage("unknown option");
		}
	}

	if (!certfile) {
		usage(NULL);
	}

	haveCA = 0;
	if ((cacertfile) && (cakeyfile)) {
		haveCA = 1;
	} else if ((cacertfile) || (cakeyfile)) {
		usage("Specify either both -C and -K, or specify neither");
	}

	if ((command == ' ') && ((haveCA) || (outputfile))) {
		usage("You need to specify a command wtih -s");
	}

	if (! strchr(" lcr", command)) {
		usage("Command must be -sl, -sc, -sr or unspecified to print certificate details");
	}

	if ((strchr("lcr", command)) && (!outputfile)) {
		usage("You must specify an output file specification");
	}

	if ((command == 'r') && (!haveCA)) {
		usage("You need to specify a CA with -sr\n");
	}

	/* set up openssl */
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	SSL_library_init();

	/* open certificate file */
	get_cert_from_file(&sslctx, &ssl, &crt, certfile);

	if (haveCA) {
		/* open CA certificate file */
		get_cert_from_file(&casslctx, &cassl, &cacrt, cacertfile);

		/* read CA key file */
		get_key_from_file(cassl, cakeyfile);

		issuerkey = get_private_key(cassl);
	}

	/* get any extra certs */
	ca_stack = get_extra_certs(sslctx);

	/* if only a certificate file, display and exit */
	if (command == ' ') {
		print_cert(crt);

		if (ca_stack) {
			storectx = X509_STORE_CTX_new();
			if (!storectx) {
				printf("main X509_STORE_CTX_new failed\n");
				exit(1);
			}

			if (!X509_STORE_CTX_init(storectx, NULL, crt, ca_stack)) {
				printf("main X509_STORE_init failed\n");
				exit(1);
			}

			tempcert = crt;

			while (tempcert) {
				printf("%s\n", X509_NAME_oneline(X509_get_subject_name(tempcert), NULL, 0));
				if (!X509_name_cmp(X509_get_subject_name(tempcert), X509_get_issuer_name(tempcert))) {
					tempcert = NULL;
				} else {
					tempcert = find_issuer(storectx, ca_stack, tempcert);
				}
			}

		}

		exit(0);
	}

	switch(command) {
		case 'l':
			if (haveCA) {
				clone_certificate(crt, cacrt, issuerkey, outputfile, 0);
			} else {
				clone_certificate(crt, NULL, NULL, outputfile, 0);
			}
			break;
		case 'c':
		case 'r':
			outputchainfile = malloc(strlen(outputfile) + 3);
			if (!outputchainfile) {
				printf("main malloc error\n");
				exit(1);
			}
			sprintf(outputchainfile, "%s.1", outputfile);
			if (haveCA) {
				if (!clone_chain(crt, ca_stack, cacrt, issuerkey, outputchainfile, 0, command)) {
					printf("main clone_chain failed\n");
					exit(1);
				}
			} else {
				if (!clone_chain(crt, ca_stack, NULL, NULL, outputchainfile, 0, command)) {
					printf("main clone_chain failed\n");
					exit(1);
				}
			}
			break;

	}


	printf("\nSuccess!\n\n");

	return 0;

}


