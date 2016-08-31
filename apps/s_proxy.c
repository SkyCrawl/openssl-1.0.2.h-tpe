/* apps/s_proxy.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
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

// openssl includes
#include <openssl/e_os2.h>
#include <openssl/ssl/ssl.h>
#include <openssl/ssl/ssl_locl.h>
#include <openssl/ssl/ssl3.h>
#include <openssl/ssl/dtls1.h>
#include <openssl/crypto/bio/bio.h>
#include "s_apps.h"
#include "apps.h"
#include "timeouts.h"

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

/*
 * Custom structures.
 */

// create the proxy's method flow for TLS 1.2
IMPLEMENT_tls_meth_func(
		TLS1_2_VERSION,
		TLS12_prx_method,
		tls12_prx_accept,
		tls12_prx_connect,
		tls1_get_method, // TODO:
		TLSv1_2_enc_data)

/* Structure passed to cert status callback */
typedef struct tlsextstatusctx_st {
    /* Default responder to use */
    char *host, *path, *port;
    int use_ssl;
    int timeout;
    BIO *err;
    int verbose;
} Status_cb_ctx;

/*
 * Global variables.
 */

static int accept_socket = -1;
static char* server_host = SSL_HOST_NAME;
static short server_port = SERVER_PORT;
static short proxy_port = PROXY_PORT;

static BIO *sp_bio_out = NULL;
static BIO *sp_bio_msg = NULL;
static BIO *sp_bio_err = NULL;

static SSL* conn_server = NULL;
static SSL* conn_to_client = NULL;

static char *sp_key_file = NULL;
static int sp_key_format = FORMAT_PEM;
static EVP_PKEY *sp_key = NULL;

static char *sp_cert_file = TEST_CERT;
static int sp_cert_format = FORMAT_PEM;
static X509 *sp_cert = NULL;

static char *sp_chain_file = NULL;
static STACK_OF(X509) *sp_chain = NULL;

static SSL_CTX *ctx = NULL;
static SSL_CONF_CTX *cctx_server = NULL;
static SSL_CONF_CTX *cctx_client = NULL;

static STACK_OF(OPENSSL_STRING) *ssl_args = NULL;

static int s_tlsextstatus = 0;
static int s_debug = 0;
static int sp_msg = 0;
static int sp_quiet = 0;
static int c_ign_eof = 0;
static int bufsize = SERVER_BUFSIZZ;

static Status_cb_ctx tlscstatp = { NULL, NULL, NULL, 0, -1, NULL, 0 };

/*
 * -----------------------------------------------------------------
 * Utility functions.
 * -----------------------------------------------------------------
 */

static int accept_client_connection()
{
	// declare vars
    int i;
    const char *str;
    X509 *peer;
    long verify_error;
    MS_STATIC char buf[BUFSIZ];

    // accept connection
    i = SSL_accept(conn_to_client);
#ifdef CERT_CB_TEST_RETRY
    {
        while (i <= 0 && SSL_get_error(con, i) == SSL_ERROR_WANT_X509_LOOKUP
               && SSL_state(con) == SSL3_ST_SR_CLNT_HELLO_C) {
            fprintf(stderr,
                    "LOOKUP from certificate callback during accept\n");
            i = SSL_accept(con);
        }
    }
#endif

    // check the result & verify the newly created connection
    if (i <= 0) {
        if (BIO_sock_should_retry(i)) {
            BIO_printf(sp_bio_out, "DELAY\n");
            return (1);
        }

        BIO_printf(sp_bio_err, "ERROR\n");
        verify_error = SSL_get_verify_result(conn_to_client);
        if (verify_error != X509_V_OK) {
            BIO_printf(sp_bio_err, "verify error:%s\n",
                       X509_verify_cert_error_string(verify_error));
        }
        /* Always print any error messages */
        ERR_print_errors(sp_bio_err);
        return (0);
    }

    /*
     * Print out some session information.
     */

    PEM_write_bio_SSL_SESSION(sp_bio_out, SSL_get_session(conn_to_client));
    peer = SSL_get_peer_x509(conn_to_client);
    if (peer != NULL) {
        BIO_printf(sp_bio_out, "Client certificate\n");
        PEM_write_bio_X509(sp_bio_out, peer);
        X509_NAME_oneline(X509_get_subject_name(peer), buf, sizeof buf);
        BIO_printf(sp_bio_out, "subject=%s\n", buf);
        X509_NAME_oneline(X509_get_issuer_name(peer), buf, sizeof buf);
        BIO_printf(sp_bio_out, "issuer=%s\n", buf);
        X509_free(peer);
    }
    if (SSL_get_shared_ciphers(conn_to_client, buf, sizeof buf) != NULL) {
        BIO_printf(sp_bio_out, "Shared ciphers:%s\n", buf);
    }
    str = SSL_CIPHER_get_name(SSL_get_current_cipher(conn_to_client));
    ssl_print_sigalgs(sp_bio_out, conn_to_client);
#ifndef OPENSSL_NO_EC
    ssl_print_point_formats(sp_bio_out, conn_to_client);
    ssl_print_curves(sp_bio_out, conn_to_client, 0);
#endif
    BIO_printf(sp_bio_out, "CIPHER is %s\n", (str != NULL) ? str : "(NONE)");
    if (SSL_cache_hit(conn_to_client)) {
        BIO_printf(sp_bio_out, "Reused session-id\n");
    }
    if (SSL_ctrl(conn_to_client, SSL_CTRL_GET_FLAGS, 0, NULL) &
        TLS1_FLAGS_TLS_PADDING_BUG) {
        BIO_printf(sp_bio_out, "Peer has incorrect TLSv1 block padding\n");
    }
    BIO_printf(sp_bio_out, "Secure Renegotiation IS%s supported\n",
               SSL_get_secure_renegotiation_support(conn_to_client) ? "" : " NOT");

    // and finally, return
    return (1);
}

static void close_accept_socket(void)
{
    BIO_printf(sp_bio_err, "shutdown accept socket\n");
    if (accept_socket >= 0) {
        SHUTDOWN2(accept_socket);
    }
}

static void prx_print_stats(BIO *bio, SSL_CTX *ssl_ctx)
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

static void prx_print_usage()
{
	BIO_printf(sp_bio_err, "usage: s_proxy [args ...]\n");
	BIO_printf(sp_bio_err, "\n");
	BIO_printf(sp_bio_err, " -s_host arg   - server hostname to connect to (default is '%d')\n", SSL_HOST_NAME);
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

/*
 * -----------------------------------------------------------------
 * Main.
 * -----------------------------------------------------------------
 */

int MAIN(int, char **);
int MAIN(int argc, char *argv[])
{
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
    cctx_server = SSL_CONF_CTX_new();
    if (!cctx_server) {
        goto end;
    }
    SSL_CONF_CTX_set_flags(cctx_server, SSL_CONF_FLAG_SERVER);
    SSL_CONF_CTX_set_flags(cctx_server, SSL_CONF_FLAG_CMDLINE);

    // setup client configuration context
    cctx_client = SSL_CONF_CTX_new();
	if (!cctx_client) {
		goto end;
	}
	SSL_CONF_CTX_set_flags(cctx_client, SSL_CONF_FLAG_CLIENT);
	SSL_CONF_CTX_set_flags(cctx_client, SSL_CONF_FLAG_CMDLINE);

    /*
     * Setup global SSL context. This is also where we set
     * special handling of both connections - through the
     * argument function).
     */
    ctx = SSL_CTX_new(TLS12_prx_method());
	if (ctx == NULL) {
		ERR_print_errors(sp_bio_err);
		goto end;
	}
	SSL_CTX_set_quiet_shutdown(ctx, 1);

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
            if (!extract_port(*(++argv), &proxy_port))
                goto bad;
        } else if ((strcmp(*argv, "-s_host") == 0)) {
            if (--argc < 1)
                goto bad;
            server_host = *(++argv);
        }  else if ((strcmp(*argv, "-s_port") == 0)) {
            if (--argc < 1)
                goto bad;
            if (!extract_port(*(++argv), &server_port))
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

	// something I don't really understand but it seems required...
    if (state) {
        SSL_CTX_set_info_callback(ctx, apps_ssl_info_callback);
    } else {
        SSL_CTX_sess_set_cache_size(ctx, 128);
    }
    if (!args_ssl_call(ctx, sp_bio_err, cctx_server, ssl_args, 0, 1)) {
        goto end;
    }
    if (!args_ssl_call(ctx, sp_bio_err, cctx_client, ssl_args, 0, 1)) {
		ERR_print_errors(sp_bio_err);
		goto end;
	}
    // TODO: build_chain 0 or 1? For now, 1...
    if (!set_cert_key_stuff(ctx, sp_cert, sp_key, sp_chain, 1)) {
        goto end;
    }

    // host a blocking server
    BIO_printf(sp_bio_out, "ACCEPT\n");
    (void)BIO_flush(sp_bio_out);
    do_server(proxy_port, SOCK_STREAM, &accept_socket, prx_host, NULL, -1);

    // when done
    prx_print_stats(sp_bio_out, ctx);
    ret = 0;

end:
    if (pass) {
        OPENSSL_free(pass);
    }

    prx_shutdown();
    free_sessions(); // TODO:
    apps_shutdown();
    OPENSSL_EXIT(ret);
    return ret;
}

/*
 * Accepts connections from clients and does all the necessary checks.
 * Calls 'prx_connect' when a client connection is ready.
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

    if (conn_to_client == NULL) {
    	conn_to_client = SSL_new(ctx);
#ifndef OPENSSL_NO_TLSEXT
        if (s_tlsextstatus) {
            SSL_CTX_set_tlsext_status_cb(ctx, cert_status_cb);
            tlscstatp.err = sp_bio_err;
            SSL_CTX_set_tlsext_status_arg(ctx, &tlscstatp);
        }
#endif
    }
    SSL_clear(conn_to_client);

    sbio = BIO_new_socket(s, BIO_NOCLOSE);
    SSL_set_bio(conn_to_client, sbio, sbio);
    SSL_set_accept_state(conn_to_client);

    if (s_debug) {
        SSL_set_debug(conn_to_client);
        BIO_set_callback(SSL_get_rbio(conn_to_client), bio_dump_callback);
        BIO_set_callback_arg(SSL_get_rbio(conn_to_client), (char *)sp_bio_out);
    }

    if (sp_msg) {
#ifndef OPENSSL_NO_SSL_TRACE
        if (s_msg == 2)
            SSL_set_msg_callback(conn_to_client, SSL_trace);
        else
#endif
            SSL_set_msg_callback(conn_to_client, msg_cb);
        SSL_set_msg_callback_arg(conn_to_client, sp_bio_msg ? sp_bio_msg : sp_bio_out);
    }

    width = s + 1;
    for (;;) {
        int read_from_terminal;
        int read_from_sslcon;

        read_from_terminal = 0;
        read_from_sslcon = SSL_pending(conn_to_client);

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
                    close_accept_socket();
                    ret = -11;
                    goto err;
                }
                if ((i <= 0) || (buf[0] == 'q')) {
                    BIO_printf(sp_bio_out, "DONE\n");
                    if (SSL_version(conn_to_client) != DTLS1_VERSION)
                        SHUTDOWN(s);
                    /*
                     * close_accept_socket(); ret= -11;
                     */
                    goto err;
                }
#ifndef OPENSSL_NO_HEARTBEATS
                if ((buf[0] == 'B') && ((buf[1] == '\n') || (buf[1] == '\r'))) {
                    BIO_printf(sp_bio_err, "HEARTBEATING\n");
                    SSL_heartbeat(conn_to_client);
                    i = 0;
                    continue;
                }
#endif
                // TODO: proceed with proxy renegotiation...
                if ((buf[0] == 'r') && ((buf[1] == '\n') || (buf[1] == '\r'))) {
                	SSL_renegotiate(conn_to_client);
                	i = SSL_do_handshake(conn_to_client);
                    printf("SSL_do_handshake -> %d\n", i); // TODO: move the printing somewhere else?
                    i = 0;      /* 13; */
                    continue;
                    /*
                     * strcpy(buf,"server side RE-NEGOTIATE\n");
                     */
                }
                if ((buf[0] == 'R') && ((buf[1] == '\n') || (buf[1] == '\r'))) {
                    SSL_set_verify(conn_to_client,
                                   SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE,
                                   NULL);
                    SSL_renegotiate(conn_to_client);
                    i = SSL_do_handshake(conn_to_client);
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
                    BIO_write(SSL_get_wbio(conn_to_client), str, strlen(str));
                }
                if (buf[0] == 'S') {
                    prx_print_stats(sp_bio_out, SSL_get_SSL_CTX(conn_to_client));
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
                k = SSL_write(conn_to_client, &(buf[l]), (unsigned int)i);

                switch (SSL_get_error(conn_to_client, k)) {
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
            if (!SSL_is_init_finished(conn_to_client)) {
            	// TODO: proceed with proxy setup...
            	i = accept_client_connection();

                if (i < 0) {
                    ret = 0;
                    goto err;
                } else if (i == 0) {
                    ret = 1;
                    goto err;
                }
            } else {
 again:
                i = SSL_read(conn_to_client, (char *)buf, bufsize);
                switch (SSL_get_error(conn_to_client, i)) {
                case SSL_ERROR_NONE:
                    raw_write_stdout(buf, (unsigned int)i);
                    if (SSL_pending(conn_to_client))
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
    if (conn_to_client != NULL) {
        BIO_printf(sp_bio_out, "shutting down SSL\n");
        SSL_set_shutdown(conn_to_client, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
        SSL_free(conn_to_client);
    }
    prx_shutdown(); // don't put this right after the label...
    BIO_printf(sp_bio_out, "CONNECTION CLOSED\n");
    if (buf != NULL) {
        OPENSSL_cleanse(buf, bufsize);
        OPENSSL_free(buf);
    }
    if (ret >= 0) {
        BIO_printf(sp_bio_out, "ACCEPT\n");
    }
    return (ret);
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
        SSL_CTX_set_cipher_list(ctx, getenv("SSL_CIPHER"));
/*      SSL_set_cipher_list(con,"RC4-MD5"); */
#endif

    // create the target connection
    conn_server = SSL_new(ctx);

 re_start:

 	 // initialize it
    if (init_client(&s, server_host, server_port, SOCK_STREAM) == 0) {
        BIO_printf(sp_bio_err, "connect:errno=%d\n", get_last_socket_error());
        SHUTDOWN(s);
        goto end;
    }
    BIO_printf(sp_bio_out, "CONNECTED(%08X)\n", s);

    // wrap the connection to a buffer
    sbio = BIO_new_socket(s, BIO_NOCLOSE);

    // further initialization
    if (s_debug) {
        SSL_set_debug(conn_server, 1);
        BIO_set_callback(sbio, bio_dump_callback);
        BIO_set_callback_arg(sbio, (char *)sp_bio_out);
    }
    if (sp_msg) {
#ifndef OPENSSL_NO_SSL_TRACE
        if (sp_msg == 2)
            SSL_set_msg_callback(conn_to_client, SSL_trace);
        else
#endif
            SSL_set_msg_callback(conn_server, msg_cb);
        SSL_set_msg_callback_arg(conn_server, sp_bio_msg ? sp_bio_msg : sp_bio_out);
    }
    SSL_set_bio(conn_server, sbio, sbio);

    // this is where the set the proxy's special handshake handling...
    SSL_set_connect_state(conn_server);

    // ok, lets connect...
    width = SSL_get_fd(conn_server) + 1;

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

    // do connect to the server
    for (;;) {
        FD_ZERO(&readfds);
        FD_ZERO(&writefds);

        timeoutp = NULL;

        if (SSL_in_init(conn_server) && !SSL_total_renegotiations(conn_server)) {
            in_init = 1;
            tty_on = 0;
        } else {
            tty_on = 1;
            if (in_init) {
                in_init = 0;

                print_stuff(sp_bio_out, conn_server, full_log);
                if (full_log > 0) {
                    full_log--;
                }

                if (reconnect) {
                    reconnect--;
                    BIO_printf(sp_bio_out,
                               "drop connection and then reconnect\n");
                    SSL_shutdown(conn_server);
                    SSL_set_connect_state(conn_server);
                    SHUTDOWN(SSL_get_fd(conn_server));
                    goto re_start;
                }
            }
        }

        ssl_pending = read_ssl && SSL_pending(conn_server);

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
                openssl_fdset(SSL_get_fd(conn_server), &readfds);
            }
            if (write_ssl) {
                openssl_fdset(SSL_get_fd(conn_server), &writefds);
            }
#else
            if (!tty_on || !write_tty) {
                if (read_ssl) {
                    openssl_fdset(SSL_get_fd(conn_server), &readfds);
                }
                if (write_ssl) {
                    openssl_fdset(SSL_get_fd(conn_server), &writefds);
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

        if (!ssl_pending && FD_ISSET(SSL_get_fd(conn_server), &writefds)) {
            k = SSL_write(conn_server, &(cbuf[cbuf_off]), (unsigned int)cbuf_len);
            switch (SSL_get_error(conn_server, k)) {
            case SSL_ERROR_NONE:
                cbuf_off += k;
                cbuf_len -= k;
                if (k <= 0)
                    goto end;
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
        else if (ssl_pending || FD_ISSET(SSL_get_fd(conn_server), &readfds)) {
#ifdef RENEG
            {
                static int iiii;
                if (++iiii == 52) {
                    SSL_renegotiate(conn_server);
                    iiii = 0;
                }
            }
#endif
#if 1
            // ok, we read... but how do we advance further FFS?
            k = SSL_read(conn_server, sbuf, 1024 /* CLIENT_BUFSIZZ */ );
#else
/* Demo for pending and peek :-) */
            k = SSL_read(conn_server, sbuf, 16);
            {
                char zbuf[10240];
                printf("read=%d pending=%d peek=%d\n", k, SSL_pending(conn_server),
                       SSL_peek(conn_server, zbuf, 10240));
            }
#endif

            switch (SSL_get_error(conn_server, k)) {
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
                SSL_renegotiate(conn_server);
                cbuf_len = 0;
            }
#ifndef OPENSSL_NO_HEARTBEATS
            else if ((!c_ign_eof) && (cbuf[0] == 'B')) {
                BIO_printf(sp_bio_err, "HEARTBEATING\n");
                SSL_heartbeat(conn_server);
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

    // s->handshake_func = ssl3_accept; // now, it is my accept
    // s->handshake_func = ssl3_connect; // now, it is my connect

    // s->method->... are functions from our own METHOD

    /*
    int ssl3_renegotiate(SSL *s)
	{
		if (s->handshake_func == NULL)
			return (1);

		if (s->s3->flags & SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS)
			return (0);

		s->s3->renegotiate = 1;
		return (1);
	}

	int SSL_accept(SSL *s) // VOLÁNO!
	{
		if (s->handshake_func == 0)
			SSL_set_accept_state(s);

		return (s->method->ssl_accept(s));
	}

	int SSL_connect(SSL *s) // TODO: NEVOLÁNO!
	{
		if (s->handshake_func == 0)
			SSL_set_connect_state(s);

		return (s->method->ssl_connect(s));
	}

	int SSL_do_handshake(SSL *s) // VOLÁNO!
	{
		int ret = 1;

		if (s->handshake_func == NULL) {
			SSLerr(SSL_F_SSL_DO_HANDSHAKE, SSL_R_CONNECTION_TYPE_NOT_SET);
			return (-1);
		}

		s->method->ssl_renegotiate_check(s);

		if (SSL_in_init(s) || SSL_in_before(s)) {
			ret = s->handshake_func(s);
		}
		return (ret);
	}
    */

 shut:
    if (in_init) {
        print_stuff(sp_bio_out, conn_server, full_log);
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
    if (conn_server != NULL) {
		SSL_shutdown(conn_server);
		SHUTDOWN(SSL_get_fd(conn_server));
		SSL_free(conn_server);
	}

    apps_shutdown();
    OPENSSL_EXIT(ret);
    return ret;
}

static void prx_shutdown()
{
	// here we assume that the connections have been shut down already
	if (ctx != NULL) {
		SSL_CTX_free(ctx);
	}
	if (cctx_server != NULL) {
		SSL_CONF_CTX_free(cctx_server);
	}
	if (cctx_client != NULL) {
		SSL_CONF_CTX_free(cctx_client);
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

int tls12_prx_accept(SSL* conn_client)
{
	// TODO:
	return 0;
}

int tls12_prx_connect(SSL* conn_server)
{
	// TODO:
	return 0;
}

/*
 * Certificate Status callback. This is called when a client includes a
 * certificate status request extension.
 */

static int cert_status_cb(SSL *s, void *arg)
{
	// up to each and every single one whether they want to implement this
    return 1;
}

int whatever(void)
{
	// TODO:
	// /opensslconf.h
	// #ifndef OPENSSL_NO_TS

	// https://www.openssl.org/docs/man1.0.2/ssl/SSL_CONF_CTX_set_ssl_ctx.html
	SSL_CONF_CTX_set_ssl_ctx();

	// https://www.openssl.org/docs/man1.0.2/ssl/SSL_CONF_CTX_set_ssl.html
	SSL_CONF_CTX_set_ssl();

	// must read and implement!
	// https://www.openssl.org/docs/man1.0.2/ssl/SSL_CONF_CTX_set_flags.html
	// https://www.openssl.org/docs/man1.0.2/ssl/SSL_CONF_cmd.html
	// https://www.openssl.org/docs/man1.0.2/ssl/SSL_use_PrivateKey.html

	// externalizovanej seznam extenzí a jejich dat pro ServerHello:
	// https://www.openssl.org/docs/man1.0.2/ssl/SSL_CTX_use_serverinfo.html

	/*
	 * If necessary, SSL_write() will negotiate a TLS/SSL session, if not already explicitly performed by SSL_connect or SSL_accept.
	 * If the peer requests a re-negotiation, it will be performed transparently during the SSL_write() operation. The behaviour of SSL_write() depends on the underlying BIO.
	 * For the transparent negotiation to succeed, the ssl must have been initialized to client or server mode.
	 * This is being done by calling SSL_set_connect_state or SSL_set_accept_state() before the first call to an SSL_read or SSL_write() function.
	 */

	puts("Hello World"); /* prints Hello World */
	return EXIT_SUCCESS;
}
