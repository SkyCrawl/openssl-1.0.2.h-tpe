/* ssl/t1_ext.c */
/* ====================================================================
 * Copyright (c) 2014 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

/* Custom extension utility functions */

#include "ssl_locl.h"

#ifndef OPENSSL_NO_TLSEXT

#define ENQUOTE(name) #name
#define STR(str) ENQUOTE(str)
#define COMMA ,

/*
 * This much should really suffice but maybe it's safer to set double.
 */
#define TLS12_TPE_ARTIFACT_MAX_SIZE 4096

#define TLS12_TPE_INTRO STR(If you sign this message with your certificateCOMMA \
the signature will be used in the TLS protocol to authenticate you as a \
client with the service identified by the following distinguished name:)

#define TLS12_TPE_MEZZO1 STR(You should always verify the above name. If you \
haven’t made a request to the service in the last few momentsCOMMA don’t sign \
the message.)

#define TLS12_TPE_MEZZO2 STR(%sFor more securityCOMMA you should verify the \
service’s certificate’s Base16-encoded fingerprintCOMMA constructed with \
the %s cryptographic hash function. Checking the first and last three components \
should suffice:)

#define TLS12_TPE_MEZZO3 STR(AdditionallyCOMMA this message must include \
certain values that you don’t need to mind (or verify):)

#define TLS12_TPE_OUTRO STR(This is the end of the message and nothing else \
must follow.)

unsigned char* TLS12_TPE_get_signed_artifact(SSL* s, long* out_size) {
	/*
	 * Allocate the result artifact.
	 */

	long pos = 0;
	const long size = TLS12_TPE_ARTIFACT_MAX_SIZE;
	unsigned char* buff = (unsigned char*) OPENSSL_malloc(size);
	if(buff == NULL) {
		return NULL;
	}

	/*
	 * Determine the hash to use.
	 */

	const SSL_CIPHER* cipher = SSL_get_current_cipher(s);
	const long cryptoHashCode = SSL_get_hash_code_from_cipher(cipher);
	EVP_MD* cryptoHashFromCipher = SSL_get_hash_from_code(cryptoHashCode);

	unsigned char* cryptoHashName;
	switch (cryptoHashCode) {
		case SSL_MD5:
			cryptoHashName = "MD5";
			break;
		case SSL_SHA1:
			cryptoHashName = "SHA1";
			break;
		case SSL_SHA256:
			cryptoHashName = "SHA256";
			break;
		case SSL_SHA384:
			cryptoHashName = "SHA384";
			break;
		default: // SSL_GOST94, SSL_GOST89MAC and unknown macs
			// should never happen (not supported at the moment)
			goto err;
	}

	/*
	 * Construct the artifact.
	 */

	const X509* server_certificate = s->server ?
			ssl_get_server_send_pkey(s)->x509 :
			s->session->sess_cert->peer_key->x509;
	const X509_NAME* x509_name = server_certificate->cert_info->subject;
	unsigned char* x509_value = NULL;
	int ret;

	// fill intro
	if(!TLS12_TPE_append_line_to_art(buff, &pos, &size, "", TLS12_TPE_INTRO)) {
		goto err; // buffer too small or problems with encoding...
	}

	// fill the distinguished name
	if((ret = TLS12_TPE_get_utf(x509_name, NID_commonName, &x509_value))) {
		// component was found
		if (TLS12_TPE_append_line_to_art(buff, &pos, &size, "- Common Name: ", x509_value)) {
			OPENSSL_free(x509_value);
			x509_value = NULL;
		} else {
			goto err; // buffer too small or problems with encoding...
		}
	} else if(ret == -1) {
		goto err; // not enough memory...
	}

	if((ret = TLS12_TPE_get_utf(x509_name, NID_organizationName, &x509_value))) {
		// component was found
		if (TLS12_TPE_append_line_to_art(buff, &pos, &size, "- Organization: ", x509_value)) {
			OPENSSL_free(x509_value);
			x509_value = NULL;
		} else {
			goto err; // buffer too small or problems with encoding...
		}
	} else if(ret == -1) {
		goto err; // not enough memory...
	}

	if((ret = TLS12_TPE_get_utf(x509_name, NID_organizationalUnitName, &x509_value))) {
		// component was found
		if (TLS12_TPE_append_line_to_art(buff, &pos, &size, "- Organization Unit: ", x509_value)) {
			OPENSSL_free(x509_value);
			x509_value = NULL;
		} else {
			goto err; // buffer too small or problems with encoding...
		}
	} else if(ret == -1) {
		goto err; // not enough memory...
	}

	if((ret = TLS12_TPE_get_utf(x509_name, NID_localityName, &x509_value))) {
		// component was found
		if (TLS12_TPE_append_line_to_art(buff, &pos, &size, "- Locality: ", x509_value)) {
			OPENSSL_free(x509_value);
			x509_value = NULL;
		} else {
			goto err; // buffer too small or problems with encoding...
		}
	} else if(ret == -1) {
		goto err; // not enough memory...
	}

	if((ret = TLS12_TPE_get_utf(x509_name, NID_stateOrProvinceName, &x509_value))) {
		// component was found
		if (TLS12_TPE_append_line_to_art(buff, &pos, &size, "- State/Province: ", x509_value)) {
			OPENSSL_free(x509_value);
			x509_value = NULL;
		} else {
			goto err; // buffer too small or problems with encoding...
		}
	} else if(ret == -1) {
		goto err; // not enough memory...
	}

	if((ret = TLS12_TPE_get_utf(x509_name, NID_countryName, &x509_value))) {
		// component was found
		if (TLS12_TPE_append_line_to_art(buff, &pos, &size, "- Country/Region: ", x509_value)) {
			OPENSSL_free(x509_value);
			x509_value = NULL;
		} else {
			goto err; // buffer too small or problems with encoding...
		}
	} else if(ret == -1) {
		goto err; // not enough memory...
	}

	if((ret = TLS12_TPE_get_utf(x509_name, NID_Mail, &x509_value))) {
		// component was found
		if (TLS12_TPE_append_line_to_art(buff, &pos, &size, "- Email: ", x509_value)) {
			OPENSSL_free(x509_value);
			x509_value = NULL;
		} else {
			goto err; // buffer too small or problems with encoding...
		}
	} else if(ret == -1) {
		goto err; // not enough memory...
	}

	// fill intermezzo #1
	if(!TLS12_TPE_append_line_to_art(buff, &pos, &size, "", TLS12_TPE_MEZZO1)) {
		goto err; // buffer too small or problems with encoding...
	}

	// fill intermezzo #2, with hash name
	if(!TLS12_TPE_append_line_to_art_with_pattern(buff, &pos, &size, TLS12_TPE_MEZZO2, "", cryptoHashName)) {
		goto err; // buffer too small or problems with encoding...
	}

	// fill the server's certificate's encoded fingerprint
	unsigned int digest_size = EVP_MAX_MD_SIZE;
	unsigned char digest[digest_size];
	char* encoded;
	if(!EVP_Digest((void*)server_certificate->cert_info->enc.enc, server_certificate->cert_info->enc.len,
			&digest, &digest_size, cryptoHashFromCipher, NULL)) {
		goto err; // could not compute the hash for some reason...
	} else if((encoded = hex_to_string(&(digest[0]), digest_size)) == NULL) {
		goto err; // not enough memory...
	} else if(!TLS12_TPE_append_line_to_art(buff, &pos, &size, "- ", encoded)) {
		goto err; // buffer too small or problems with encoding...
	} else { // everything OK
		OPENSSL_free(encoded);
		encoded = NULL;
	}

	// fill intermezzo #3
	if(!TLS12_TPE_append_line_to_art(buff, &pos, &size, "", TLS12_TPE_MEZZO3)) {
		goto err; // buffer too small or problems with encoding...
	}

	// fill the encoded client random data
	if((encoded = hex_to_string(&(s->s3->client_random[0]), SSL3_RANDOM_SIZE)) == NULL) {
		goto err; // not enough memory...
	} else if(!TLS12_TPE_append_line_to_art(buff, &pos, &size, "- Client random data: ", encoded)) {
		goto err; // buffer too small or problems with encoding...
	} else { // everything OK
		OPENSSL_free(encoded);
		encoded = NULL;
	}

	// fill the encoded server random data
	if((encoded = hex_to_string(&(s->s3->server_random[0]), SSL3_RANDOM_SIZE)) == NULL) {
		goto err; // not enough memory...
	} else if(!TLS12_TPE_append_line_to_art(buff, &pos, &size, "- Peer random data: ", encoded)) {
		goto err; // buffer too small or problems with encoding...
	} else { // everything OK
		OPENSSL_free(encoded);
		encoded = NULL;
	}

	// fill the encoded session ID
	if((encoded = hex_to_string(&(s->session->session_id[0]), s->session->session_id_length)) == NULL) {
		goto err; // not enough memory...
	} else if(!TLS12_TPE_append_line_to_art(buff, &pos, &size, "- Session identifier: ", encoded)) {
		goto err; // buffer too small or problems with encoding...
	} else { // everything OK
		OPENSSL_free(encoded);
		encoded = NULL;
	}

	// fill the proxy's public key, hashed and encoded
	if((s->proxy_pubkey_tmp == NULL) || (s->proxy_pubkey_tmp_len <= 0)) {
		// should never happen
		goto err; // proxy's public key for the other session is required...
	}
	digest_size = EVP_MAX_MD_SIZE + 1;
	if(!EVP_Digest((void*)s->proxy_pubkey_tmp, s->proxy_pubkey_tmp_len,
			&digest, &digest_size, cryptoHashFromCipher, NULL)) {
		goto err; // could not compute the hash for some reason...
	} else if((encoded = hex_to_string(&(digest[0]), digest_size)) == NULL) {
		goto err; // not enough memory...
	} else if(!TLS12_TPE_append_line_to_art(buff, &pos, &size, "- Proxy's signed public key: ", encoded)) {
		goto err; // buffer too small or problems with encoding...
	} else { // everything OK
		OPENSSL_free(encoded);
		encoded = NULL;
	}

	// fill outro
	if(!TLS12_TPE_append_line_to_art(buff, &pos, &size, "", TLS12_TPE_OUTRO)) {
		goto err; // buffer too small or problems with encoding...
	}

	/*
	 * Handle error, cleanup & return.
	 */

	if(0) {
		err:
		OPENSSL_free(buff);
		if(x509_value != NULL) {
			OPENSSL_free(x509_value);
		}
		return NULL;
	}
	else {
		*out_size = pos;
		return buff;
	}
}

int TLS12_TPE_get_utf(X509_NAME* name, int nid, unsigned char** value) {
	int idx = X509_NAME_get_index_by_NID(name, nid, -1);
	if(idx != -1) // found
	{
		// entry should be defined
		X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, idx);
		if(entry->value->length <= 0) { // just in case check
			return 0;
		}
		unsigned char* result = (unsigned char*) OPENSSL_malloc(entry->value->length + 1);
		if(result == NULL) {
			return -1; // TODO: proper OpenSSL error handling ???
		}
		memset(result, entry->value->data, entry->value->length);
		result[entry->value->length] = '\0';
		*value = result;
		// entry->value->type; // TODO: UTF8 encoding...
		return 1;
	}
	else // not found
	{
		return 0;
	}
}

int TLS12_TPE_append_line_to_art(char* art, int* pos, const int* size, const char* prefix, const char* value) {
	return TLS12_TPE_append_line_to_art_with_pattern(art, pos, size, "%s%s\n", prefix, value);
}

int TLS12_TPE_append_line_to_art_with_pattern(char* art, int* pos, const int* size, const char* pattern, const char* prefix, const char* value) {
	int bytes_left = *size - *pos;
	int ret = snprintf(&(art[pos]), bytes_left, pattern, prefix, value);
	if((ret > 0) && (ret < bytes_left)) {
		*pos += ret;
		return 1;
	}
	else {
		return 0;
	}
}

/* Find a custom extension from the list. */
static custom_ext_method *custom_ext_find(custom_ext_methods *exts,
                                          unsigned int ext_type)
{
    size_t i;
    custom_ext_method *meth = exts->meths;
    for (i = 0; i < exts->meths_count; i++, meth++) {
        if (ext_type == meth->ext_type)
            return meth;
    }
    return NULL;
}

/*
 * Initialise custom extensions flags to indicate neither sent nor received.
 */
void custom_ext_init(custom_ext_methods *exts)
{
    size_t i;
    custom_ext_method *meth = exts->meths;
    for (i = 0; i < exts->meths_count; i++, meth++)
        meth->ext_flags = 0;
}

/* Pass received custom extension data to the application for parsing. */
int custom_ext_parse(SSL *s, int server,
                     unsigned int ext_type,
                     const unsigned char *ext_data, size_t ext_size, int *al)
{
    custom_ext_methods *exts = server ? &s->cert->srv_ext : &s->cert->cli_ext;
    custom_ext_method *meth;
    meth = custom_ext_find(exts, ext_type);
    /* If not found return success */
    if (!meth)
        return 1;
    if (!server) {
        /*
         * If it's ServerHello we can't have any extensions not sent in
         * ClientHello.
         */
        if (!(meth->ext_flags & SSL_EXT_FLAG_SENT)) {
            *al = TLS1_AD_UNSUPPORTED_EXTENSION;
            return 0;
        }
    }
    /* If already present it's a duplicate */
    if (meth->ext_flags & SSL_EXT_FLAG_RECEIVED) {
        *al = TLS1_AD_DECODE_ERROR;
        return 0;
    }
    meth->ext_flags |= SSL_EXT_FLAG_RECEIVED;
    /* If no parse function set return success */
    if (!meth->parse_cb)
        return 1;

    return meth->parse_cb(s, ext_type, ext_data, ext_size, al,
                          meth->parse_arg);
}

/*
 * Request custom extension data from the application and add to the return
 * buffer.
 */
int custom_ext_add(SSL *s, int server,
                   unsigned char **pret, unsigned char *limit, int *al)
{
    custom_ext_methods *exts = server ? &s->cert->srv_ext : &s->cert->cli_ext;
    custom_ext_method *meth;
    unsigned char *ret = *pret;
    size_t i;

    for (i = 0; i < exts->meths_count; i++) {
        const unsigned char *out = NULL;
        size_t outlen = 0;
        meth = exts->meths + i;

        if (server) {
            /*
             * For ServerHello only send extensions present in ClientHello.
             */
            if (!(meth->ext_flags & SSL_EXT_FLAG_RECEIVED))
                continue;
            /* If callback absent for server skip it */
            if (!meth->add_cb)
                continue;
        }
        if (meth->add_cb) {
            int cb_retval = 0;
            cb_retval = meth->add_cb(s, meth->ext_type,
                                     &out, &outlen, al, meth->add_arg);
            if (cb_retval < 0)
                return 0;       /* error */
            if (cb_retval == 0)
                continue;       /* skip this extension */
        }
        if (4 > limit - ret || outlen > (size_t)(limit - ret - 4))
            return 0;
        s2n(meth->ext_type, ret);
        s2n(outlen, ret);
        if (outlen) {
            memcpy(ret, out, outlen);
            ret += outlen;
        }
        /*
         * We can't send duplicates: code logic should prevent this.
         */
        OPENSSL_assert(!(meth->ext_flags & SSL_EXT_FLAG_SENT));
        /*
         * Indicate extension has been sent: this is both a sanity check to
         * ensure we don't send duplicate extensions and indicates that it is
         * not an error if the extension is present in ServerHello.
         */
        meth->ext_flags |= SSL_EXT_FLAG_SENT;
        if (meth->free_cb)
            meth->free_cb(s, meth->ext_type, out, meth->add_arg);
    }
    *pret = ret;
    return 1;
}

/* Copy table of custom extensions */
int custom_exts_copy(custom_ext_methods *dst, const custom_ext_methods *src)
{
    if (src->meths_count) {
        dst->meths =
            BUF_memdup(src->meths,
                       sizeof(custom_ext_method) * src->meths_count);
        if (dst->meths == NULL)
            return 0;
        dst->meths_count = src->meths_count;
    }
    return 1;
}

void custom_exts_free(custom_ext_methods *exts)
{
    if (exts->meths)
        OPENSSL_free(exts->meths);
}

/* Set callbacks for a custom extension. */
static int custom_ext_meth_add(custom_ext_methods *exts,
                               unsigned int ext_type,
                               custom_ext_add_cb add_cb,
                               custom_ext_free_cb free_cb,
                               void *add_arg,
                               custom_ext_parse_cb parse_cb, void *parse_arg)
{
    custom_ext_method *meth;
    /*
     * Check application error: if add_cb is not set free_cb will never be
     * called.
     */
    if (!add_cb && free_cb)
        return 0;
    /* Don't add if extension supported internally. */
    if (SSL_extension_supported(ext_type))
        return 0;
    /* Extension type must fit in 16 bits */
    if (ext_type > 0xffff)
        return 0;
    /* Search for duplicate */
    if (custom_ext_find(exts, ext_type))
        return 0;
    exts->meths = OPENSSL_realloc(exts->meths,
                                  (exts->meths_count +
                                   1) * sizeof(custom_ext_method));

    if (!exts->meths) {
        exts->meths_count = 0;
        return 0;
    }

    meth = exts->meths + exts->meths_count;
    memset(meth, 0, sizeof(custom_ext_method));
    meth->parse_cb = parse_cb;
    meth->add_cb = add_cb;
    meth->free_cb = free_cb;
    meth->ext_type = ext_type;
    meth->add_arg = add_arg;
    meth->parse_arg = parse_arg;
    exts->meths_count++;
    return 1;
}

/* Application level functions to add custom extension callbacks */
int SSL_CTX_add_client_custom_ext(SSL_CTX *ctx, unsigned int ext_type,
                                  custom_ext_add_cb add_cb,
                                  custom_ext_free_cb free_cb,
                                  void *add_arg,
                                  custom_ext_parse_cb parse_cb,
                                  void *parse_arg)
{
    return custom_ext_meth_add(&ctx->cert->cli_ext, ext_type,
                               add_cb, free_cb, add_arg, parse_cb, parse_arg);
}

int SSL_CTX_add_server_custom_ext(SSL_CTX *ctx, unsigned int ext_type,
                                  custom_ext_add_cb add_cb,
                                  custom_ext_free_cb free_cb,
                                  void *add_arg,
                                  custom_ext_parse_cb parse_cb,
                                  void *parse_arg)
{
    return custom_ext_meth_add(&ctx->cert->srv_ext, ext_type,
                               add_cb, free_cb, add_arg, parse_cb, parse_arg);
}

int SSL_extension_supported(unsigned int ext_type)
{
    switch (ext_type) {
        /* Internally supported extensions. */
    case TLSEXT_TYPE_application_layer_protocol_negotiation:
    case TLSEXT_TYPE_ec_point_formats:
    case TLSEXT_TYPE_elliptic_curves:
    case TLSEXT_TYPE_heartbeat:
    case TLSEXT_TYPE_next_proto_neg:
    case TLSEXT_TYPE_padding:
    case TLSEXT_TYPE_renegotiate:
    case TLSEXT_TYPE_server_name:
    case TLSEXT_TYPE_session_ticket:
    case TLSEXT_TYPE_signature_algorithms:
    case TLSEXT_TYPE_srp:
    case TLSEXT_TYPE_status_request:
    case TLSEXT_TYPE_use_srtp:
    case TLSEXT_TYPE_trustworthy_proxy:
# ifdef TLSEXT_TYPE_opaque_prf_input
    case TLSEXT_TYPE_opaque_prf_input:
# endif
# ifdef TLSEXT_TYPE_encrypt_then_mac
    case TLSEXT_TYPE_encrypt_then_mac:
# endif
        return 1;
    default:
        return 0;
    }
}
#endif
