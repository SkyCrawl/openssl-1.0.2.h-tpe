/* apps/s_proxy.c */
/*
 * Copyright (C) 1995-1998 Jiří Smolík (smolikj@e-trends.cz)
 * All rights reserved.
 */

/*
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */
/* ====================================================================
 * Copyright (c) 1998-2006 The OpenSSL Project.  All rights reserved.
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
/* ====================================================================
 * Copyright 2005 Nokia. All rights reserved.
 *
 * The portions of the attached software ("Contribution") is developed by
 * Nokia Corporation and is licensed pursuant to the OpenSSL open source
 * license.
 *
 * The Contribution, originally written by Mika Kousa and Pasi Eronen of
 * Nokia Corporation, consists of the "PSK" (Pre-Shared Key) ciphersuites
 * support (see RFC 4279) to OpenSSL.
 *
 * No patent licenses or other rights except those expressly stated in
 * the OpenSSL open source license shall be deemed granted or received
 * expressly, by implication, estoppel, or otherwise.
 *
 * No assurances are provided by Nokia that the Contribution does not
 * infringe the patent or other intellectual property rights of any third
 * party or that the license provides you with all the necessary rights
 * to make use of the Contribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND. IN
 * ADDITION TO THE DISCLAIMERS INCLUDED IN THE LICENSE, NOKIA
 * SPECIFICALLY DISCLAIMS ANY LIABILITY FOR CLAIMS BROUGHT BY YOU OR ANY
 * OTHER ENTITY BASED ON INFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS OR
 * OTHERWISE.
 */

/*
 * This app is a combination of 's_client' and 's_server' as proxy needs
 * to accept connections from client and forward them to the real server.
 * Needless (unsupported) stuff from both apps has been removed.
 */

// system includes
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/errno.h>

/*
 * OpenSSL 's_server' includes.
 */
#include <openssl/e_os2.h>
#include <openssl/lhash.h>

// a little 'server-client' extra...
#define USE_SOCKETS

#include "apps.h"
#include <openssl/err.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#ifndef OPENSSL_NO_DH
# include <openssl/dh.h>
#endif
#ifndef OPENSSL_NO_RSA
# include <openssl/rsa.h>
#endif

/*
 * Additional OpenSSL 's_client' includes.
 */

#include <openssl/bn.h>
#include "s_apps.h"
#include "timeouts.h"

// #include <openssl/ssl3.h>
// #include <openssl/bio.h>

/*
 * Server definitions.
 */

#undef BUFSIZZ
#undef PROG

#define SERVER_BUFSIZZ 1024*16
#define CLIENT_BUFSIZZ 1024*8
#define PROG s_proxy_main
#define PROXY_PORT 4434
#define SERVER_PORT PORT
#define SSL_HOST_NAME "localhost"
#define TEST_CERT "server.pem"

/*
 * -----------------------------------------------------------------
 * Data structures.
 * -----------------------------------------------------------------
 */

/*
 * Taken from 's_server'.
 * Structure passed to certificate status callback.
 */
typedef struct tlsextstatusctx_st {
    /* Default responder to use */
    char *host, *path, *port;
    int use_ssl;
    int timeout;
    BIO *err;
    int verbose;
} Status_cb_ctx;

/*
 * Taken from 's_server'.
 * By default, 's_server' uses an in-memory cache which caches
 * SSL_SESSION structures without any serialization. This hides
 * some bugs which only become apparent in deployed servers. By
 * implementing a basic external session cache some issues can be
 * debugged using 's_server'.
 */

typedef struct simple_ssl_session_st {
    unsigned char *id;
    unsigned int idlen;
    unsigned char *der;
    int derlen;
    struct simple_ssl_session_st *next;
} simple_ssl_session;

/*
 * -----------------------------------------------------------------
 * Global variables. A mixture of 's_client' and 's_server'.
 * -----------------------------------------------------------------
 */

static int accept_socket = -1;
static char* server_connect_host = SSL_HOST_NAME;
static short server_connect_port = SERVER_PORT;
static short proxy_host_port = PROXY_PORT;

static BIO *sp_bio_out = NULL;
static BIO *sp_bio_msg = NULL;
static BIO *sp_bio_err = NULL;

static char *sp_key_file = NULL;
static int sp_key_format = FORMAT_PEM;
static EVP_PKEY *sp_key = NULL;

static char *sp_cert_file = TEST_CERT;
static int sp_cert_format = FORMAT_PEM;
static X509 *sp_cert = NULL;

static char *sp_chain_file = NULL;
static STACK_OF(X509) *sp_chain = NULL;

static SSL* conn_prx_is_srvr = NULL;
static SSL* conn_prx_is_clnt = NULL;

static SSL_CTX *ctx_prx_is_srvr = NULL;
static SSL_CTX *ctx_prx_is_clnt = NULL;

static SSL_CONF_CTX *cctx_prx_is_srvr = NULL;
static SSL_CONF_CTX *cctx_prx_is_clnt = NULL;

static STACK_OF(OPENSSL_STRING) *ssl_args = NULL;

static int s_tlsextstatus = 0;
static int s_debug = 0;
static int s_crlf = 0;
static int sp_msg = 0;
static int sp_quiet = 0;
static int c_ign_eof = 0;
static int bufsize = SERVER_BUFSIZZ;

static Status_cb_ctx tlscstatp = { NULL, NULL, NULL, 0, -1, NULL, 0 };
static simple_ssl_session *first = NULL;

/*
 * -----------------------------------------------------------------
 * Application-level callbacks.
 * -----------------------------------------------------------------
 */

/*
 * Callback to provide status of the proxy's certificate. This should
 * be called when a client includes a certificate status request
 * extension.
 */
static int prx_cert_status_cb(SSL *s, void *arg)
{
	/*
	 * As status information is not mandatory, we can just return...
	 */
    return SSL_TLSEXT_ERR_OK;
}

/*
 * -----------------------------------------------------------------
 * Utility functions to manage sessions. Copied from 's_server'.
 * -----------------------------------------------------------------
 */

static int prx_add_session(SSL* ssl, SSL_SESSION* session)
{
    simple_ssl_session *sess;
    unsigned char *p;

    sess = OPENSSL_malloc(sizeof(simple_ssl_session));
    if (!sess) {
        BIO_printf(bio_err, "Out of memory adding session to external cache\n");
        return 0;
    }

    SSL_SESSION_get_id(session, &sess->idlen);
    sess->derlen = i2d_SSL_SESSION(session, NULL);

    sess->id = BUF_memdup(SSL_SESSION_get_id(session, NULL), sess->idlen);

    sess->der = OPENSSL_malloc(sess->derlen);
    if (!sess->id || !sess->der) {
        BIO_printf(bio_err, "Out of memory adding session to external cache\n");

        if (sess->id)
            OPENSSL_free(sess->id);
        if (sess->der)
            OPENSSL_free(sess->der);
        OPENSSL_free(sess);
        return 0;
    }
    p = sess->der;
    i2d_SSL_SESSION(session, &p);

    sess->next = first;
    first = sess;
    BIO_printf(bio_err, "New session added to external cache\n");
    return 0;
}

static SSL_SESSION* prx_get_session(SSL* ssl,
		unsigned char* id, int idlen, int* do_copy)
{
    simple_ssl_session *sess;
    *do_copy = 0;
    for (sess = first; sess; sess = sess->next) {
        if (idlen == (int)sess->idlen && !memcmp(sess->id, id, idlen)) {
            const unsigned char *p = sess->der;
            BIO_printf(bio_err, "Lookup session: cache hit\n");
            return d2i_SSL_SESSION(NULL, &p, sess->derlen);
        }
    }
    BIO_printf(bio_err, "Lookup session: cache miss\n");
    return NULL;
}

static void prx_del_session(SSL_CTX* sctx, SSL_SESSION* session)
{
    simple_ssl_session *sess, *prev = NULL;
    const unsigned char *id;
    unsigned int idlen;
    id = SSL_SESSION_get_id(session, &idlen);
    for (sess = first; sess; sess = sess->next) {
        if (idlen == sess->idlen && !memcmp(sess->id, id, idlen)) {
            if (prev)
                prev->next = sess->next;
            else
                first = sess->next;
            OPENSSL_free(sess->id);
            OPENSSL_free(sess->der);
            OPENSSL_free(sess);
            return;
        }
        prev = sess;
    }
}

static void prx_free_session_cache()
{
    simple_ssl_session *sess, *tsess;
    for (sess = first; sess;) {
        OPENSSL_free(sess->id);
        OPENSSL_free(sess->der);
        tsess = sess;
        sess = sess->next;
        OPENSSL_free(tsess);
    }
    first = NULL;
}

static void prx_init_session_cache(SSL_CTX* ctx)
{
	/*
	 * The following will tell OpenSSL to remember sessions
	 * and set session IDs. It is absolutely essential for
	 * session resumption to work.
	 */
	if (ctx == ctx_prx_is_srvr) {
		// only 'SSL_accept()' will cache sessions
		SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_NO_INTERNAL |
				SSL_SESS_CACHE_SERVER);
	} else if (ctx == ctx_prx_is_clnt) {
		// only 'SSL_connect()' will cache sessions
		SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_NO_INTERNAL |
				SSL_SESS_CACHE_CLIENT);
	}

	// additional setup
    SSL_CTX_sess_set_new_cb(ctx, prx_add_session);
    SSL_CTX_sess_set_get_cb(ctx, prx_get_session);
    SSL_CTX_sess_set_remove_cb(ctx, prx_del_session);
    SSL_CTX_sess_set_cache_size(ctx, 128);
}

/*
 * -----------------------------------------------------------------
 * Utility functions to print into console.
 * -----------------------------------------------------------------
 */

static void prx_print_usage()
{
	BIO_printf(sp_bio_err, "usage: s_proxy [args ...]\n");
	BIO_printf(sp_bio_err, "\n");
	BIO_printf(sp_bio_err, " -s_host arg   - server hostname to connect to (default is '%s')\n", SSL_HOST_NAME);
	BIO_printf(sp_bio_err, " -s_port arg   - server port to connect to (default is %d)\n", SERVER_PORT);
	BIO_printf(sp_bio_err, " -p_port arg   - proxy port to accept on (default is %d)\n", PROXY_PORT);
	BIO_printf(sp_bio_err, " -cert arg     - certificate file to use (default is %s)\n", TEST_CERT);
	BIO_printf(sp_bio_err, " -certform arg - certificate format (PEM or DER; default is PEM)\n");
	BIO_printf(sp_bio_err, " -key arg      - private key file to use, if not in certificate file\n");
	BIO_printf(sp_bio_err, "                 (default is %s)\n", TEST_CERT);
	BIO_printf(sp_bio_err, " -keyform arg  - private key format (PEM or DER; default is PEM)\n");
	BIO_printf(sp_bio_err, " -pass arg     - private key pass phrase source\n");
	BIO_printf(sp_bio_err, " -debug        - print more output\n");
	BIO_printf(sp_bio_err, " -status       - respond to certificate status requests\n");
	BIO_printf(sp_bio_err, " -msg          - show protocol messages\n");
	BIO_printf(sp_bio_err, " -state        - print the SSL states\n");
	BIO_printf(sp_bio_err, " -crlf         - convert LF from terminal into CRLF\n");
	BIO_printf(sp_bio_err, " -quiet        - silent mode (no output)\n");
}

static void prx_print_lifetime_stats(BIO *bio, SSL_CTX *ssl_ctx)
{
    BIO_printf(bio, "%4ld items in the session cache\n",
               SSL_CTX_sess_number(ssl_ctx));
    BIO_printf(bio, "%4ld client connects (SSL_connect())\n",
               SSL_CTX_sess_connect(ssl_ctx));
    BIO_printf(bio, "%4ld client renegotiates (SSL_connect())\n",
               SSL_CTX_sess_connect_renegotiate(ssl_ctx));
    BIO_printf(bio, "%4ld client connects that finished\n",
               SSL_CTX_sess_connect_good(ssl_ctx));
    BIO_printf(bio, "%4ld server accepts (SSL_accept())\n",
               SSL_CTX_sess_accept(ssl_ctx));
    BIO_printf(bio, "%4ld server renegotiates (SSL_accept())\n",
               SSL_CTX_sess_accept_renegotiate(ssl_ctx));
    BIO_printf(bio, "%4ld server accepts that finished\n",
               SSL_CTX_sess_accept_good(ssl_ctx));
    BIO_printf(bio, "%4ld session cache hits\n", SSL_CTX_sess_hits(ssl_ctx));
    BIO_printf(bio, "%4ld session cache misses\n",
               SSL_CTX_sess_misses(ssl_ctx));
    BIO_printf(bio, "%4ld session cache timeouts\n",
               SSL_CTX_sess_timeouts(ssl_ctx));
    BIO_printf(bio, "%4ld callback cache hits\n",
               SSL_CTX_sess_cb_hits(ssl_ctx));
    BIO_printf(bio, "%4ld cache full overflows (%ld allowed)\n",
               SSL_CTX_sess_cache_full(ssl_ctx),
               SSL_CTX_sess_get_cache_size(ssl_ctx));
}

/*
 * Generalization of an extraction of:
 * - 'print_stuff()' from 's_client'
 * - 'prx_print_accept_info()' from 's_server'
 */
static void prx_print_session_info(BIO *bio, SSL* s)
{
	// announce it
	if (s == conn_prx_is_srvr) {
		BIO_printf(bio, "---Client-side session:\n");
	} else {
		BIO_printf(bio, "---Server-side session:\n");
	}

	// print the main part
	BIO_printf(bio, "Session resumed: %s\n", SSL_cache_hit(s) ? "YES" : "NO");
	SSL_SESSION_print(bio, SSL_get_session(s));

	// print some more compression-related info
#ifndef OPENSSL_NO_COMP
	const COMP_METHOD *expansion = SSL_get_current_expansion(s);
	BIO_printf(bio, "Expansion: %s\n",
			expansion ? SSL_COMP_get_name(expansion) : "NONE");
#endif

	/*
	 * Print extension info.
	 */
	BIO_printf(bio, "Secure renegotiation: %s\n",
			SSL_get_secure_renegotiation_support(s) ? "YES" : "NO");

#if !defined(OPENSSL_NO_TLSEXT)
# if !defined(OPENSSL_NO_NEXTPROTONEG)
    if (next_proto.status != -1) {
        const unsigned char *proto;
        unsigned int proto_len;
        SSL_get0_next_proto_negotiated(s, &proto, &proto_len);
        BIO_printf(bio, "Next protocol: (%d) ", next_proto.status);
        BIO_write(bio, proto, proto_len);
        BIO_write(bio, "\n", 1);
    }
# endif
    {
        const unsigned char *proto;
        unsigned int proto_len;
        SSL_get0_alpn_selected(s, &proto, &proto_len);
        if (proto_len > 0) {
            BIO_printf(bio, "ALPN protocol: ");
            BIO_write(bio, proto, proto_len);
            BIO_write(bio, "\n", 1);
        } else {
            BIO_printf(bio, "No ALPN negotiated\n");
        }
    }
#endif

    // and finally
	BIO_printf(bio, "Bytes read: %ld\n", BIO_number_read(SSL_get_rbio(s)));
	BIO_printf(bio, "Bytes written: %ld\n", BIO_number_written(SSL_get_wbio(s)));
}

/*
 * A mixture of:
 * - 'print_stuff()' from 's_client'
 * - 'prx_print_accept_info()' from 's_server'
 *
 * Removed:
 * - SRTP (not compatible with TPE).
 * - Export key material (not needed).
 * - Certificates (client and server will print that).
 *
 * Only call this when communication has been successfully established.
 */
static void prx_print_connect_info(BIO *bio)
{
    /*
     * First print some information from both sessions.
     */

    prx_print_session_info(bio, conn_prx_is_srvr);
    prx_print_session_info(bio, conn_prx_is_clnt);

    /*
     * No need to print certificate info (client & server will do
     * that). Instead, print cipher lists to see the real effect
     * of our filtering.
     */

    BIO_printf(bio, "---Client's original cipher list:\n");
    tls12_print_cipher_stack(bio, SSL_get_session_ciphers(conn_prx_is_srvr));

    BIO_printf(bio, "---Proxy's filtered cipher list:\n");
    tls12_print_cipher_stack(bio, SSL_get_session_ciphers(conn_prx_is_clnt));

    /*
     * And finally, print some info about public keys of the endpoints.
     */

    BIO_printf(bio, "---\n");
    ssl_print_tmp_key(bio, conn_prx_is_clnt);
    X509 *peer = SSL_get_peer_x509(conn_prx_is_clnt);
    if (peer != NULL) {
    	// TODO: where do we actually store the peer's public key?
		EVP_PKEY *pktmp = X509_get_pubkey(peer);
		BIO_printf(bio, "Server public key is %d bit strong\n",
				EVP_PKEY_bits(pktmp));
		EVP_PKEY_free(pktmp);
	}

	/* flush, or debugging output gets mixed with http response */
	(void)BIO_flush(bio);
}

/*
 * -----------------------------------------------------------------
 * Utility functions to help setup or destroy communication.
 * -----------------------------------------------------------------
 */

static SSL_CTX* prx_init_ctx(SSL_CONF_CTX* cctx, int state)
{
	/*
	 * Basic setup.
	 */

	int server = cctx == cctx_prx_is_srvr;
	int client = cctx == cctx_prx_is_clnt;
	if (!server && !client) {
		goto err;
	}

	// determine the method to use
	const SSL_METHOD* meth = server ? TLSv1_2_server_method() :
			TLSv1_2_client_method();

	// create the new context
	SSL_CTX* ctx_new = SSL_CTX_new(meth);
	if (ctx_new == NULL) {
		ERR_print_errors(sp_bio_err);
		goto err;
	}

	/*
	 * More advanced setup.
	 */

	prx_init_session_cache(ctx_new);
	SSL_CTX_set_quiet_shutdown(ctx_new, 1);

	// something I don't really understand but it seems required...
	if (state) {
		SSL_CTX_set_info_callback(ctx_new, apps_ssl_info_callback);
	}
	if (!args_ssl_call(ctx_new, sp_bio_err, cctx_prx_is_srvr, ssl_args, server ? 0 : 1, 1)) {
		ERR_print_errors(sp_bio_err);
		goto err;
	}

	/*
	 * Finally...
	 */

	if (0) {
 err:
		if (ctx_new) {
			SSL_CTX_free(ctx_new);
		}
		return NULL;
	} else {
		return ctx_new;
	}
}

// forward declare a later function
int prx_connect();

/*
 * A function taken from 's_server'.
 */
int prx_do_accept_client_conn()
{
    /*
     * Before we accept the client connection, we need to register
     * the correct role so that further code will know what to do.
     */
	SSL_set_role(conn_prx_is_srvr, SSL_ROLE_PROXY, 1);

    // register client connection to the proxy's routines
    int i = SSL_accept(conn_prx_is_srvr);
    if (i != 2) {
    	// should never happen...
    	return -1; // calling code will handle the error
    }

    /*
     * Register server connection to the proxy's routines
     * and try to do handshake on both connections.
     */
    i = prx_connect();

    /*
	 * If connection to client has been shut down, we must NOT return a
	 * positive code because of the cycles in connection methods.
	 */
    if (i > 0 && (SSL_get_shutdown(conn_prx_is_srvr) & (SSL_RECEIVED_SHUTDOWN |
    		SSL_SENT_SHUTDOWN))) {
    	BIO_printf(sp_bio_err,
    			"Error: connection to server returned success but connection"
    			"to client has been shut down.\n");
    	return -1;
    }

    // by default, return what we received
    return i;
}

static void prx_close_accept_socket(void)
{
    BIO_printf(sp_bio_err, "shutdown accept socket\n");
    if (accept_socket >= 0) {
        SHUTDOWN2(accept_socket);
    }
}

static void prx_shutdown()
{
	// here we assume that the connections have been shut down already
	if (ctx_prx_is_srvr != NULL) {
		SSL_CTX_free(ctx_prx_is_srvr);
	}
	if (ctx_prx_is_clnt != NULL) {
		SSL_CTX_free(ctx_prx_is_clnt);
	}
	if (cctx_prx_is_srvr != NULL) {
		SSL_CONF_CTX_free(cctx_prx_is_srvr);
	}
	if (cctx_prx_is_clnt != NULL) {
		SSL_CONF_CTX_free(cctx_prx_is_clnt);
	}
	if (ssl_args) {
		sk_OPENSSL_STRING_free(ssl_args);
	}

	// free buffers
	if (sp_bio_out != NULL) {
		BIO_free(sp_bio_out);
		sp_bio_out = NULL;
	}
	if (sp_bio_msg != NULL) {
		BIO_free(sp_bio_msg);
		sp_bio_msg = NULL;
	}

	// free additional structures
	if (sp_key) {
		EVP_PKEY_free(sp_key);
	}
	if (sp_cert) {
		X509_free(sp_cert);
	}
	if (sp_chain) {
		sk_X509_pop_free(sp_chain, X509_free);
	}
}

/*
 * -----------------------------------------------------------------
 * Main methods to establish communication.
 * -----------------------------------------------------------------
 */

// first forward declare several functions
static int prx_host(char *hostname, int s, int stype, unsigned char* context);

int MAIN(int, char **);
int MAIN(int argc, char *argv[])
{
#ifdef OPENSSL_NO_TLSEXT
	BIO_printf(sp_bio_err, "Error: 's_proxy' tool works on the basis of TLS extensions but this\n");
	BIO_printf(sp_bio_err, "distribution of OpenSSL has been configured (compiled) NOT to include them.\n");
	goto end;
#endif

	// declare variables for arguments
	char *pass = NULL, *passarg = NULL;
	int state = 0;

    // begin
	apps_startup();

    // setup error buffer
    if (sp_bio_err == NULL) {
        sp_bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
    }
    if (!load_config(sp_bio_err, NULL)) {
        goto end;
    }

    // setup server configuration context
    cctx_prx_is_srvr = SSL_CONF_CTX_new();
    if (!cctx_prx_is_srvr) {
        goto end;
    }
    SSL_CONF_CTX_set_flags(cctx_prx_is_srvr, SSL_CONF_FLAG_SERVER);
    SSL_CONF_CTX_set_flags(cctx_prx_is_srvr, SSL_CONF_FLAG_CMDLINE);

    // setup client configuration context
    cctx_prx_is_clnt = SSL_CONF_CTX_new();
	if (!cctx_prx_is_clnt) {
		goto end;
	}
	SSL_CONF_CTX_set_flags(cctx_prx_is_clnt, SSL_CONF_FLAG_CLIENT);
	SSL_CONF_CTX_set_flags(cctx_prx_is_clnt, SSL_CONF_FLAG_CMDLINE);

    // disregard the command name name
    argc--;
    argv++;

    // handle input arguments
    int badarg = 0;
    int badop = 0;
    int ret = 1;
    while (argc >= 1) {
        if ((strcmp(*argv, "-p_port") == 0)) {
            if (--argc < 1)
                goto bad;
            if (!extract_port(*(++argv), &proxy_host_port))
                goto bad;
        } else if ((strcmp(*argv, "-s_host") == 0)) {
            if (--argc < 1)
                goto bad;
            server_connect_host = *(++argv);
        }  else if ((strcmp(*argv, "-s_port") == 0)) {
            if (--argc < 1)
                goto bad;
            if (!extract_port(*(++argv), &server_connect_port))
                goto bad;
        } else if (strcmp(*argv, "-cert") == 0) {
            if (--argc < 1)
                goto bad;
            sp_cert_file = *(++argv);
        } else if (strcmp(*argv, "-certform") == 0) {
            if (--argc < 1)
                goto bad;
            sp_cert_format = str2fmt(*(++argv));
        } else if (strcmp(*argv, "-key") == 0) {
            if (--argc < 1)
                goto bad;
            sp_key_file = *(++argv);
        } else if (strcmp(*argv, "-keyform") == 0) {
            if (--argc < 1)
                goto bad;
            sp_key_format = str2fmt(*(++argv));
        } else if (strcmp(*argv, "-pass") == 0) {
            if (--argc < 1)
                goto bad;
            passarg = *(++argv);
        } else if (strcmp(*argv, "-debug") == 0) {
            s_debug = 1;
        } else if (strcmp(*argv, "-status") == 0) {
            s_tlsextstatus = 1;
        } else if (strcmp(*argv, "-msg") == 0) {
            sp_msg = 1;
        } else if (strcmp(*argv, "-state") == 0) {
            state = 1;
        } else if (strcmp(*argv, "-crlf") == 0) {
            s_crlf = 1;
        } else if (strcmp(*argv, "-quiet") == 0) {
            sp_quiet = 1;
            c_ign_eof = 1;
        } else {
            BIO_printf(sp_bio_err, "unknown option %s\n", *argv);
            badop = 1;
            break;
        }
        argc--;
        argv++;
    }

    // first check & handle the result
    if (badop) {
 bad:
        prx_print_usage();
        goto end;
    } else {
    	// further initialization
    	SSL_load_error_strings();
    	OpenSSL_add_ssl_algorithms();
    }

    // setup the needed buffers to communicate with the caller
    if (sp_bio_out == NULL) {
		if (sp_quiet && !s_debug) {
			sp_bio_out = BIO_new(BIO_s_null());
			if (sp_msg && !sp_bio_msg)
				sp_bio_msg = BIO_new_fp(stdout, BIO_NOCLOSE);
		} else {
			if (sp_bio_out == NULL)
				sp_bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
		}
	}

    /*
     * Setup environment using the arguments.
     */

    // prepare private key password
    if (!app_passwd(sp_bio_err, passarg, passarg, &pass, &pass)) {
        BIO_printf(sp_bio_err, "Error getting password\n");
        goto end;
    }

    // prepare private key
    if (sp_key_file == NULL) {
        sp_key_file = sp_cert_file;
    }
    sp_key = load_key(sp_bio_err, sp_key_file, sp_key_format, 0, pass, NULL,
                         "proxy certificate private key file");
	if (!sp_key) {
		BIO_printf(sp_bio_err, "Could not load the private key...\n");
		ERR_print_errors(sp_bio_err);
		goto end;
	}

	// prepare certificate
	if (sp_cert_file == NULL) {
		BIO_printf(sp_bio_err, "You must specify a certificate file for the proxy to use\n");
		goto end;
	}
	sp_cert = load_cert(sp_bio_err, sp_cert_file, sp_cert_format,
					   NULL, NULL, "proxy certificate file");
	if (!sp_cert) {
		BIO_printf(sp_bio_err, "Could not load the proxy certificate...\n");
		ERR_print_errors(sp_bio_err);
		goto end;
	}

	// prepare certificate chain
	if (sp_chain_file) {
		sp_chain = load_certs(sp_bio_err, sp_chain_file, FORMAT_PEM,
							 NULL, NULL, "proxy certificate chain");
		if (!sp_chain) {
			goto end;
		}
	}

	/*
	 * Setup global SSL contexts. We can only do this now.
	 */

	ctx_prx_is_srvr = prx_init_ctx(cctx_prx_is_srvr, state);
	ctx_prx_is_clnt = prx_init_ctx(cctx_prx_is_clnt, state);

    // if we set the last argument to 1, proxy won't work...
    if (!set_cert_key_stuff(ctx_prx_is_srvr, sp_cert, sp_key, sp_chain, 0)) {
        goto end;
    }

    // host a blocking server
    BIO_printf(sp_bio_out, "ACCEPT\n");
    (void)BIO_flush(sp_bio_out);
    do_server(proxy_host_port, SOCK_STREAM, &accept_socket, prx_host, NULL, -1);

    // when done
    prx_print_lifetime_stats(sp_bio_out, ctx_prx_is_srvr);
    ret = 0;

end:
    if (pass) {
        OPENSSL_free(pass);
    }

    prx_shutdown();
    prx_free_session_cache();
    apps_shutdown();
    OPENSSL_EXIT(ret);
    return ret;
}

/*
 * Accepts connections from clients and does all the necessary checks.
 * Calls 'prx_connect' when a client connection is ready. If this method
 * returns a negative integer, the server is stopped.
 */
static int prx_host(char *hostname, int s, int stype, unsigned char* context)
{
    char *buf = NULL;
    fd_set readfds;
    int ret = 1, width;
    int k, i;
    unsigned long l;
    BIO *sbio;
    struct timeval timeout;
#if defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_MSDOS) || defined(OPENSSL_SYS_NETWARE) || defined(OPENSSL_SYS_BEOS_R5)
    struct timeval tv;
#else
    struct timeval *timeoutp;
#endif

    if ((buf = OPENSSL_malloc(bufsize)) == NULL) {
        BIO_printf(sp_bio_err, "out of memory\n");
        goto err;
    }

    if (conn_prx_is_srvr == NULL) {
    	// create the new connection
    	conn_prx_is_srvr = SSL_new(ctx_prx_is_srvr);

#ifndef OPENSSL_NO_TLSEXT
        if (s_tlsextstatus) {
            SSL_CTX_set_tlsext_status_cb(ctx_prx_is_srvr, prx_cert_status_cb);
            tlscstatp.err = sp_bio_err;
            SSL_CTX_set_tlsext_status_arg(ctx_prx_is_srvr, &tlscstatp);
        }
#endif
    }
    SSL_clear(conn_prx_is_srvr);

    sbio = BIO_new_socket(s, BIO_NOCLOSE);
    SSL_set_bio(conn_prx_is_srvr, sbio, sbio);
    SSL_set_accept_state(conn_prx_is_srvr);

    if (s_debug) {
        SSL_set_debug(conn_prx_is_srvr, s_debug);
        BIO_set_callback(SSL_get_rbio(conn_prx_is_srvr), bio_dump_callback);
        BIO_set_callback_arg(SSL_get_rbio(conn_prx_is_srvr), (char *)sp_bio_out);
    }

    if (sp_msg) {
#ifndef OPENSSL_NO_SSL_TRACE
        if (sp_msg == 2)
            SSL_set_msg_callback(conn_prx_is_srvr, SSL_trace);
        else
#endif
            SSL_set_msg_callback(conn_prx_is_srvr, msg_cb);
        SSL_set_msg_callback_arg(conn_prx_is_srvr, sp_bio_msg ? sp_bio_msg : sp_bio_out);
    }

    width = s + 1;
    for (;;) {
        int read_from_terminal;
        int read_from_sslcon;

        read_from_terminal = 0;
        read_from_sslcon = SSL_pending(conn_prx_is_srvr);

        if (!read_from_sslcon) {
            FD_ZERO(&readfds);
#if !defined(OPENSSL_SYS_WINDOWS) && !defined(OPENSSL_SYS_MSDOS) && !defined(OPENSSL_SYS_NETWARE) && !defined(OPENSSL_SYS_BEOS_R5)
            openssl_fdset(fileno(stdin), &readfds);
#endif
            openssl_fdset(s, &readfds);
            /*
             * Note: under VMS with SOCKETSHR the second parameter is
             * currently of type (int *) whereas under other systems it is
             * (void *) if you don't have a cast it will choke the compiler:
             * if you do have a cast then you can either go for (int *) or
             * (void *).
             */
#if defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_MSDOS) || defined(OPENSSL_SYS_NETWARE)
            /*
             * Under DOS (non-djgpp) and Windows we can't select on stdin:
             * only on sockets. As a workaround we timeout the select every
             * second and check for any keypress. In a proper Windows
             * application we wouldn't do this because it is inefficient.
             */
            tv.tv_sec = 1;
            tv.tv_usec = 0;
            i = select(width, (void *)&readfds, NULL, NULL, &tv);
            if ((i < 0) || (!i && !_kbhit()))
                continue;
            if (_kbhit())
                read_from_terminal = 1;
#elif defined(OPENSSL_SYS_BEOS_R5)
            /* Under BeOS-R5 the situation is similar to DOS */
            tv.tv_sec = 1;
            tv.tv_usec = 0;
            (void)fcntl(fileno(stdin), F_SETFL, O_NONBLOCK);
            i = select(width, (void *)&readfds, NULL, NULL, &tv);
            if ((i < 0) || (!i && read(fileno(stdin), buf, 0) < 0))
                continue;
            if (read(fileno(stdin), buf, 0) >= 0)
                read_from_terminal = 1;
            (void)fcntl(fileno(stdin), F_SETFL, 0);
#else
            timeoutp = NULL;

            i = select(width, (void *)&readfds, NULL, NULL, timeoutp);
            if (i <= 0)
                continue;

            if (FD_ISSET(fileno(stdin), &readfds))
                read_from_terminal = 1;
#endif
            if (FD_ISSET(s, &readfds))
                read_from_sslcon = 1;
        }
        if (read_from_terminal) {
            if (s_crlf) {
                int j, lf_num;

                i = raw_read_stdin(buf, bufsize / 2);
                lf_num = 0;
                /* both loops are skipped when i <= 0 */
                for (j = 0; j < i; j++)
                    if (buf[j] == '\n')
                        lf_num++;
                for (j = i - 1; j >= 0; j--) {
                    buf[j + lf_num] = buf[j];
                    if (buf[j] == '\n') {
                        lf_num--;
                        i++;
                        buf[j + lf_num] = '\r';
                    }
                }
                assert(lf_num == 0);
            } else
                i = raw_read_stdin(buf, bufsize);
            if (!sp_quiet) {
                if ((i <= 0) || (buf[0] == 'Q')) {
                    BIO_printf(sp_bio_out, "DONE\n");
                    SHUTDOWN(s);
                    prx_close_accept_socket();
                    ret = -11;
                    goto err;
                }
                if ((i <= 0) || (buf[0] == 'q')) {
                    BIO_printf(sp_bio_out, "DONE\n");
                    if (SSL_version(conn_prx_is_srvr) != DTLS1_VERSION)
                        SHUTDOWN(s);
                    /*
                     * prx_close_accept_socket(); ret= -11;
                     */
                    goto err;
                }
#ifndef OPENSSL_NO_HEARTBEATS
                if ((buf[0] == 'B') && ((buf[1] == '\n') || (buf[1] == '\r'))) {
                    BIO_printf(sp_bio_err, "HEARTBEATING\n");
                    SSL_heartbeat(conn_prx_is_srvr);
                    i = 0;
                    continue;
                }
#endif
                // TODO: proceed with proxy renegotiation...
                if ((buf[0] == 'r') && ((buf[1] == '\n') || (buf[1] == '\r'))) {
                	SSL_renegotiate(conn_prx_is_srvr);
                	i = SSL_do_handshake(conn_prx_is_srvr);
                    printf("SSL_do_handshake -> %d\n", i); // TODO: move the printing somewhere else?
                    i = 0;      /* 13; */
                    continue;
                    /*
                     * strcpy(buf,"server side RE-NEGOTIATE\n");
                     */
                }
                if ((buf[0] == 'R') && ((buf[1] == '\n') || (buf[1] == '\r'))) {
                    SSL_set_verify(conn_prx_is_srvr,
                                   SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE,
                                   NULL);
                    SSL_renegotiate(conn_prx_is_srvr);
                    i = SSL_do_handshake(conn_prx_is_srvr);
                    printf("SSL_do_handshake -> %d\n", i); // TODO: move the printing somewhere else?
                    i = 0;      /* 13; */
                    continue;
                    /*
                     * strcpy(buf,"server side RE-NEGOTIATE asking for client
                     * cert\n");
                     */
                }
                if (buf[0] == 'P') {
                    static const char *str = "Lets print some clear text\n";
                    BIO_write(SSL_get_wbio(conn_prx_is_srvr), str, strlen(str));
                }
                if (buf[0] == 'S') {
                    prx_print_lifetime_stats(sp_bio_out, SSL_get_SSL_CTX(conn_prx_is_srvr));
                }
            }
#ifdef CHARSET_EBCDIC
            ebcdic2ascii(buf, buf, i);
#endif
            l = k = 0;
            for (;;) {
                /* should do a select for the write */
#ifdef RENEG
                {
                    static count = 0;
                    if (++count == 100) {
                        count = 0;
                        SSL_renegotiate(conn_to_client);
                    }
                }
#endif

                // PROXY: this is where we call 'ssl_accept()' if we read from terminal
                k = SSL_write(conn_prx_is_srvr, &(buf[l]), (unsigned int)i);

                switch (SSL_get_error(conn_prx_is_srvr, k)) {
                case SSL_ERROR_NONE:
                    break;
                case SSL_ERROR_WANT_WRITE:
                case SSL_ERROR_WANT_READ:
                case SSL_ERROR_WANT_X509_LOOKUP:
                    BIO_printf(sp_bio_out, "Write BLOCK\n");
                    break;
                case SSL_ERROR_SYSCALL:
                case SSL_ERROR_SSL:
                    BIO_printf(sp_bio_out, "ERROR\n");
                    ERR_print_errors(sp_bio_err);
                    ret = 1;
                    goto err;
                    /* break; */
                case SSL_ERROR_ZERO_RETURN:
                    BIO_printf(sp_bio_out, "DONE\n");
                    ret = 1;
                    goto err;
                }
                if (k > 0) {
                    l += k;
                    i -= k;
                }
                if (i <= 0)
                    break;
            }
        }
        if (read_from_sslcon) {
            if (!SSL_is_init_finished(conn_prx_is_srvr)) {
            	// PROXY: this is where we call 'ssl_accept()' if we read from the connection
            	i = prx_do_accept_client_conn();
                if (i < 0) {
                    ret = 0;
                    goto err;
                } else if (i == 0) {
                    ret = 1;
                    goto err;
                }
            } else {
 again:
                i = SSL_read(conn_prx_is_srvr, (char *)buf, bufsize);
                switch (SSL_get_error(conn_prx_is_srvr, i)) {
                case SSL_ERROR_NONE:
                    raw_write_stdout(buf, (unsigned int)i);
                    if (SSL_pending(conn_prx_is_srvr))
                        goto again;
                    break;
                case SSL_ERROR_WANT_WRITE:
                case SSL_ERROR_WANT_READ:
                    BIO_printf(sp_bio_out, "Read BLOCK\n");
                    break;
                case SSL_ERROR_SYSCALL:
                case SSL_ERROR_SSL:
                    BIO_printf(sp_bio_out, "ERROR\n");
                    ERR_print_errors(sp_bio_err);
                    ret = 1;
                    goto err;
                case SSL_ERROR_ZERO_RETURN:
                    BIO_printf(sp_bio_out, "DONE\n");
                    ret = 1;
                    goto err;
                }
            }
        }
    }

 err:
    if (conn_prx_is_srvr != NULL) {
        BIO_printf(sp_bio_out, "shutting down SSL\n");
        SSL_set_shutdown(conn_prx_is_srvr, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
        SSL_free(conn_prx_is_srvr);
    }
    BIO_printf(sp_bio_out, "CONNECTION CLOSED\n");

    // clean
    if (buf != NULL) {
        OPENSSL_cleanse(buf, bufsize);
        OPENSSL_free(buf);
    }

    // proxy will continue hosting as long as non-negative codes are returned
    if (ret >= 0) {
        BIO_printf(sp_bio_out, "ACCEPT\n");
        return ret;
    } else if (BIO_sock_should_retry(ret)) {
		BIO_printf(sp_bio_out, "DELAY\n");
		return (1);
	} else {
    	// only execute this when proxy stops hosting and returns
		BIO_printf(sp_bio_err, "ERROR\n");
		ERR_print_errors(sp_bio_err);
		prx_shutdown();
		return (ret);
    }
}

/*
 * Creates a connection to the server and forwards messages between participants,
 * perhaps a bit altered.
 */
int prx_connect()
{
	// declare vars
	BIO *sbio;
    char *cbuf = NULL, *sbuf = NULL, *mbuf = NULL;
    int i, k, s, width;
    int full_log = 1;
    int crlf = 0;
    int ret = 1, in_init = 1;

    struct timeval timeout, *timeoutp;
#if defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_MSDOS) || defined(OPENSSL_SYS_NETWARE) || defined(OPENSSL_SYS_BEOS_R5)
    struct timeval tv;
# if defined(OPENSSL_SYS_BEOS_R5)
    int stdin_set = 0;
# endif
#endif

    struct sockaddr peer;
    int peerlen = sizeof(peer);
    int enable_timeouts = 0;
    long socket_mtu = 0;

    // initialize buffers
    if (((cbuf = OPENSSL_malloc(CLIENT_BUFSIZZ)) == NULL) ||
        ((sbuf = OPENSSL_malloc(CLIENT_BUFSIZZ)) == NULL) ||
        ((mbuf = OPENSSL_malloc(CLIENT_BUFSIZZ)) == NULL)) {
        BIO_printf(sp_bio_err, "out of memory\n");
        goto end;
    }

#if 0
    else
        SSL_CTX_set_cipher_list(ctx_lop, getenv("SSL_CIPHER"));
/*      SSL_set_cipher_list(con,"RC4-MD5"); */
#endif

    // create the target connection
    conn_prx_is_clnt = SSL_new(ctx_prx_is_clnt);

 re_start:

 	// initialize it
    if (init_client(&s, server_connect_host, server_connect_port, SOCK_STREAM) == 0) {
        BIO_printf(sp_bio_err, "connect:errno=%d\n", get_last_socket_error());
        SHUTDOWN(s);
        goto end;
    }
    BIO_printf(sp_bio_out, "CONNECTED(%08X)\n", s);

    // wrap the connection to a buffer
    sbio = BIO_new_socket(s, BIO_NOCLOSE);

    // further initialization
    if (s_debug) {
        SSL_set_debug(conn_prx_is_clnt, 1);
        BIO_set_callback(sbio, bio_dump_callback);
        BIO_set_callback_arg(sbio, (char *)sp_bio_out);
    }
    if (sp_msg) {
#ifndef OPENSSL_NO_SSL_TRACE
        if (sp_msg == 2)
            SSL_set_msg_callback(conn_prx_is_srvr, SSL_trace);
        else
#endif
            SSL_set_msg_callback(conn_prx_is_clnt, msg_cb);
        SSL_set_msg_callback_arg(conn_prx_is_clnt, sp_bio_msg ? sp_bio_msg : sp_bio_out);
    }
    SSL_set_bio(conn_prx_is_clnt, sbio, sbio);
    SSL_set_connect_state(conn_prx_is_clnt);

    // ok, lets connect...
    width = SSL_get_fd(conn_prx_is_clnt) + 1;

    // declare more vars
    fd_set readfds, writefds;
    int read_tty = 1;
    int write_tty = 0;
    int tty_on = 0;
    int read_ssl = 1;
    int write_ssl = 1;
    int cbuf_len, cbuf_off = 0;
    int sbuf_len, sbuf_off = 0;
    int mbuf_len = 0;
    int ssl_pending;

    /*
     * GENERAL NOTE TO THE CODE BELOW:
     * If necessary, 'SSL_write()' will negotiate a TLS/SSL session, if not
     * already explicitly performed by SSL_connect or SSL_accept. If the peer
     * requests a re-negotiation, it will be performed transparently during
     * the 'SSL_write()' operation. Behaviour of 'SSL_write()' depends on the
     * underlying BIO. For transparent negotiation to succeed, the SSL must
     * have been initialized to client or server mode. This is being done by
     * calling 'SSL_set_connect_state()' or 'SSL_set_accept_state()' before
     * the first call to an 'SSL_read()' or 'SSL_write()' function.
     */

    // do connect to the server
    for (;;) {
        FD_ZERO(&readfds);
        FD_ZERO(&writefds);

        timeoutp = NULL;

        if (SSL_in_init(conn_prx_is_clnt) && !SSL_total_renegotiations(conn_prx_is_clnt)) {
            in_init = 1;
            tty_on = 0;
        } else {
            tty_on = 1;
            if (in_init) {
                in_init = 0;

                /*
                 * Let's disable this in favor of our own printing method,
                 * called at the right time.
                prx_print_connect_info(sp_bio_out, conn_prx_is_clnt, full_log);
                if (full_log > 0) {
                    full_log--;
                }
                */
            }
        }

        ssl_pending = read_ssl && SSL_pending(conn_prx_is_clnt);

        if (!ssl_pending) {
#if !defined(OPENSSL_SYS_WINDOWS) && !defined(OPENSSL_SYS_MSDOS) && !defined(OPENSSL_SYS_NETWARE) && !defined (OPENSSL_SYS_BEOS_R5)
            if (tty_on) {
                if (read_tty) {
                    openssl_fdset(fileno(stdin), &readfds);
                }
                if (write_tty) {
                    openssl_fdset(fileno(stdout), &writefds);
                }
            }
            if (read_ssl) {
                openssl_fdset(SSL_get_fd(conn_prx_is_clnt), &readfds);
            }
            if (write_ssl) {
                openssl_fdset(SSL_get_fd(conn_prx_is_clnt), &writefds);
            }
#else
            if (!tty_on || !write_tty) {
                if (read_ssl) {
                    openssl_fdset(SSL_get_fd(conn_to_server), &readfds);
                }
                if (write_ssl) {
                    openssl_fdset(SSL_get_fd(conn_to_server), &writefds);
                }
            }
#endif
/*-         printf("mode tty(%d %d%d) ssl(%d%d)\n",
                    tty_on,read_tty,write_tty,read_ssl,write_ssl);*/

            /*
             * Note: under VMS with SOCKETSHR the second parameter is
             * currently of type (int *) whereas under other systems it is
             * (void *) if you don't have a cast it will choke the compiler:
             * if you do have a cast then you can either go for (int *) or
             * (void *).
             */
#if defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_MSDOS)
            /*
             * Under Windows/DOS we make the assumption that we can always
             * write to the tty: therefore if we need to write to the tty we
             * just fall through. Otherwise we timeout the select every
             * second and see if there are any keypresses. Note: this is a
             * hack, in a proper Windows application we wouldn't do this.
             */
            i = 0;
            if (!write_tty) {
                if (read_tty) {
                    tv.tv_sec = 1;
                    tv.tv_usec = 0;
                    i = select(width, (void *)&readfds, (void *)&writefds,
                               NULL, &tv);
# if defined(OPENSSL_SYS_WINCE) || defined(OPENSSL_SYS_MSDOS)
                    if (!i && (!_kbhit() || !read_tty))
                        continue;
# else
                    if (!i && (!((_kbhit())
                                 || (WAIT_OBJECT_0 ==
                                     WaitForSingleObject(GetStdHandle
                                                         (STD_INPUT_HANDLE),
                                                         0)))
                               || !read_tty))
                        continue;
# endif
                } else
                    i = select(width, (void *)&readfds, (void *)&writefds,
                               NULL, timeoutp);
            }
#elif defined(OPENSSL_SYS_NETWARE)
            if (!write_tty) {
                if (read_tty) {
                    tv.tv_sec = 1;
                    tv.tv_usec = 0;
                    i = select(width, (void *)&readfds, (void *)&writefds,
                               NULL, &tv);
                } else
                    i = select(width, (void *)&readfds, (void *)&writefds,
                               NULL, timeoutp);
            }
#elif defined(OPENSSL_SYS_BEOS_R5)
            /* Under BeOS-R5 the situation is similar to DOS */
            i = 0;
            stdin_set = 0;
            (void)fcntl(fileno(stdin), F_SETFL, O_NONBLOCK);
            if (!write_tty) {
                if (read_tty) {
                    tv.tv_sec = 1;
                    tv.tv_usec = 0;
                    i = select(width, (void *)&readfds, (void *)&writefds,
                               NULL, &tv);
                    if (read(fileno(stdin), sbuf, 0) >= 0)
                        stdin_set = 1;
                    if (!i && (stdin_set != 1 || !read_tty))
                        continue;
                } else
                    i = select(width, (void *)&readfds, (void *)&writefds,
                               NULL, timeoutp);
            }
            (void)fcntl(fileno(stdin), F_SETFL, 0);
#else
            i = select(width, (void *)&readfds, (void *)&writefds,
                       NULL, timeoutp);
#endif
            if (i < 0) {
                BIO_printf(sp_bio_err, "bad select %d\n",
                           get_last_socket_error());
                goto shut;
                /* goto end; */
            }
        }

        if (!ssl_pending && FD_ISSET(SSL_get_fd(conn_prx_is_clnt), &writefds)) {
        	/*
			 * Before we connect to the server, we need to register the correct
			 * role so that further code will know what to do.
			 */
			SSL_set_role(conn_prx_is_clnt, SSL_ROLE_PROXY, 1);

        	// PROXY: this is where we transitively call 'ssl_connect'...
            k = SSL_write(conn_prx_is_clnt, &(cbuf[cbuf_off]), (unsigned int)cbuf_len);
            switch (SSL_get_error(conn_prx_is_clnt, k)) {
            case SSL_ERROR_NONE:
                cbuf_off += k;
                cbuf_len -= k;
                if (k <= 0) {
                    goto end;
                }

                // always print success info before reading from terminal
                prx_print_connect_info(sp_bio_out);

                /* we have done a  write(con,NULL,0); */
                if (cbuf_len <= 0) {
                    read_tty = 1;
                    write_ssl = 0;
                } else {        /* if (cbuf_len > 0) */
                    read_tty = 0;
                    write_ssl = 1;
                }
                break;
            case SSL_ERROR_WANT_WRITE:
                BIO_printf(sp_bio_out, "write W BLOCK\n");
                write_ssl = 1;
                read_tty = 0;
                break;
            case SSL_ERROR_WANT_READ:
                BIO_printf(sp_bio_out, "write R BLOCK\n");
                write_tty = 0;
                read_ssl = 1;
                write_ssl = 0;
                break;
            case SSL_ERROR_WANT_X509_LOOKUP:
                BIO_printf(sp_bio_out, "write X BLOCK\n");
                break;
            case SSL_ERROR_ZERO_RETURN:
                if (cbuf_len != 0) {
                    BIO_printf(sp_bio_out, "shutdown\n");
                    ret = 0;
                    goto shut;
                } else {
                    read_tty = 1;
                    write_ssl = 0;
                    break;
                }

            case SSL_ERROR_SYSCALL:
                if ((k != 0) || (cbuf_len != 0)) {
                    BIO_printf(sp_bio_err, "write:errno=%d\n",
                               get_last_socket_error());
                    goto shut;
                } else {
                    read_tty = 1;
                    write_ssl = 0;
                }
                break;
            case SSL_ERROR_SSL:
                ERR_print_errors(sp_bio_err);
                goto shut;
            }
        }
#if defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_MSDOS) || defined(OPENSSL_SYS_NETWARE) || defined(OPENSSL_SYS_BEOS_R5)
        /* Assume Windows/DOS/BeOS can always write */
        else if (!ssl_pending && write_tty)
#else
        else if (!ssl_pending && FD_ISSET(fileno(stdout), &writefds))
#endif
        {
#ifdef CHARSET_EBCDIC
            ascii2ebcdic(&(sbuf[sbuf_off]), &(sbuf[sbuf_off]), sbuf_len);
#endif
            i = raw_write_stdout(&(sbuf[sbuf_off]), sbuf_len);

            if (i <= 0) {
                BIO_printf(sp_bio_out, "DONE\n");
                ret = 0;
                goto shut;
                /* goto end; */
            }

            sbuf_len -= i;;
            sbuf_off += i;
            if (sbuf_len <= 0) {
                read_ssl = 1;
                write_tty = 0;
            }
        }

        // this is where we read from the connection...
        else if (ssl_pending || FD_ISSET(SSL_get_fd(conn_prx_is_clnt), &readfds)) {
#ifdef RENEG
            {
                static int iiii;
                if (++iiii == 52) {
                    SSL_renegotiate(conn_to_server);
                    iiii = 0;
                }
            }
#endif
#if 1
            // ok, we read... but how do we advance further FFS?
            k = SSL_read(conn_prx_is_clnt, sbuf, 1024 /* CLIENT_BUFSIZZ */ );
#else
/* Demo for pending and peek :-) */
            k = SSL_read(conn_to_server, sbuf, 16);
            {
                char zbuf[10240];
                printf("read=%d pending=%d peek=%d\n", k, SSL_pending(conn_to_server),
                       SSL_peek(conn_to_server, zbuf, 10240));
            }
#endif

            switch (SSL_get_error(conn_prx_is_clnt, k)) {
            case SSL_ERROR_NONE:
                if (k <= 0)
                    goto end;
                sbuf_off = 0;
                sbuf_len = k;

                read_ssl = 0;
                write_tty = 1;
                break;
            case SSL_ERROR_WANT_WRITE:
                BIO_printf(sp_bio_out, "read W BLOCK\n");
                write_ssl = 1;
                read_tty = 0;
                break;
            case SSL_ERROR_WANT_READ:
                BIO_printf(sp_bio_out, "read R BLOCK\n");
                write_tty = 0;
                read_ssl = 1;
                if ((read_tty == 0) && (write_ssl == 0))
                    write_ssl = 1;
                break;
            case SSL_ERROR_WANT_X509_LOOKUP:
                BIO_printf(sp_bio_out, "read X BLOCK\n");
                break;
            case SSL_ERROR_SYSCALL:
                ret = get_last_socket_error();
                BIO_printf(sp_bio_err, "read:errno=%d\n", ret);
                goto shut;
            case SSL_ERROR_ZERO_RETURN:
                BIO_printf(sp_bio_out, "closed\n");
                ret = 0;
                goto shut;
            case SSL_ERROR_SSL:
                ERR_print_errors(sp_bio_err);
                goto shut;
                /* break; */
            }
        }
#if defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_MSDOS)
# if defined(OPENSSL_SYS_WINCE) || defined(OPENSSL_SYS_MSDOS)
        else if (_kbhit())
# else
        else if ((_kbhit())
                 || (WAIT_OBJECT_0 ==
                     WaitForSingleObject(GetStdHandle(STD_INPUT_HANDLE), 0)))
# endif
#elif defined (OPENSSL_SYS_NETWARE)
        else if (_kbhit())
#elif defined(OPENSSL_SYS_BEOS_R5)
        else if (stdin_set)
#else
        // reading from the terminal again...
        else if (FD_ISSET(fileno(stdin), &readfds))
#endif
        {
            if (crlf) {
                int j, lf_num;

                i = raw_read_stdin(cbuf, CLIENT_BUFSIZZ / 2);
                lf_num = 0;
                /* both loops are skipped when i <= 0 */
                for (j = 0; j < i; j++)
                    if (cbuf[j] == '\n')
                        lf_num++;
                for (j = i - 1; j >= 0; j--) {
                    cbuf[j + lf_num] = cbuf[j];
                    if (cbuf[j] == '\n') {
                        lf_num--;
                        i++;
                        cbuf[j + lf_num] = '\r';
                    }
                }
                assert(lf_num == 0);
            } else
                i = raw_read_stdin(cbuf, CLIENT_BUFSIZZ);

            if ((!c_ign_eof) && ((i <= 0) || (cbuf[0] == 'Q'))) {
                BIO_printf(sp_bio_err, "DONE\n");
                ret = 0;
                goto shut;
            }

            // TODO: proceed with proxy renegotiation...
            if ((!c_ign_eof) && (cbuf[0] == 'R')) {
                BIO_printf(sp_bio_err, "RENEGOTIATING\n");
                SSL_renegotiate(conn_prx_is_clnt);
                cbuf_len = 0;
            }
#ifndef OPENSSL_NO_HEARTBEATS
            else if ((!c_ign_eof) && (cbuf[0] == 'B')) {
                BIO_printf(sp_bio_err, "HEARTBEATING\n");
                SSL_heartbeat(conn_prx_is_clnt);
                cbuf_len = 0;
            }
#endif
            else {
                cbuf_len = i;
                cbuf_off = 0;
#ifdef CHARSET_EBCDIC
                ebcdic2ascii(cbuf, cbuf, i);
#endif
            }

            write_ssl = 1;
            read_tty = 0;
        }
    }

    ret = 0;

 shut:
 	if (in_init) {
 		prx_print_connect_info(sp_bio_out);
 	}

 end:
    if (cbuf != NULL) {
        OPENSSL_cleanse(cbuf, CLIENT_BUFSIZZ);
        OPENSSL_free(cbuf);
    }
    if (sbuf != NULL) {
        OPENSSL_cleanse(sbuf, CLIENT_BUFSIZZ);
        OPENSSL_free(sbuf);
    }
    if (mbuf != NULL) {
        OPENSSL_cleanse(mbuf, CLIENT_BUFSIZZ);
        OPENSSL_free(mbuf);
    }
    if (conn_prx_is_clnt != NULL) {
		SSL_shutdown(conn_prx_is_clnt);
		SHUTDOWN(SSL_get_fd(conn_prx_is_clnt));
		SSL_free(conn_prx_is_clnt);
	}

    apps_shutdown();
    OPENSSL_EXIT(ret);
}
