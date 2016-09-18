/* ssl/s3_clnt.c */
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
 * Copyright (c) 1998-2007 The OpenSSL Project.  All rights reserved.
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
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 *
 * Portions of the attached software ("Contribution") are developed by
 * SUN MICROSYSTEMS, INC., and are contributed to the OpenSSL project.
 *
 * The Contribution is licensed pursuant to the OpenSSL open source
 * license provided above.
 *
 * ECC cipher suite support in OpenSSL originally written by
 * Vipul Gupta and Sumit Gupta of Sun Microsystems Laboratories.
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

#include <stdio.h>
#include "ssl_locl.h"
#include "kssl_lcl.h"
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#ifdef OPENSSL_FIPS
# include <openssl/fips.h>
#endif
#ifndef OPENSSL_NO_DH
# include <openssl/dh.h>
#endif
#include <openssl/bn.h>
#ifndef OPENSSL_NO_ENGINE
# include <openssl/engine.h>
#endif

static int ca_dn_cmp(const X509_NAME *const *a, const X509_NAME *const *b);


#ifndef OPENSSL_NO_SSL3_METHOD
static const SSL_METHOD *ssl3_get_client_method(int ver)
{
    if (ver == SSL3_VERSION)
        return (SSLv3_client_method());
    else
        return (NULL);
}

IMPLEMENT_ssl3_meth_func(SSLv3_client_method,
                         ssl_undefined_function,
                         ssl3_connect, ssl3_get_client_method)
#endif
int ssl3_connect(SSL *s)
{
	/*
	 * First a little special handling...
	 * Sorry OpenSSL developers but this hack was the only way.
	 * Otherwise, it would really be a pain to implement the proxy.
	 */
	if(SSL_is_proxy(s)) {
		return tls12_prx_connect(s);
	}

    BUF_MEM *buf = NULL;
    unsigned long Time = (unsigned long)time(NULL);
    void (*cb) (const SSL *ssl, int type, int val) = NULL;
    int ret = -1;
    int new_state, state, skip = 0;

    RAND_add(&Time, sizeof(Time), 0);
    ERR_clear_error();
    clear_sys_error();

    if (s->info_callback != NULL)
        cb = s->info_callback;
    else if (s->ctx->info_callback != NULL)
        cb = s->ctx->info_callback;

    s->in_handshake++;
    if (!SSL_in_init(s) || SSL_in_before(s))
        SSL_clear(s);

#ifndef OPENSSL_NO_HEARTBEATS
    /*
     * If we're awaiting a HeartbeatResponse, pretend we already got and
     * don't await it anymore, because Heartbeats don't make sense during
     * handshakes anyway.
     */
    if (s->tlsext_hb_pending) {
        s->tlsext_hb_pending = 0;
        s->tlsext_hb_seq++;
    }
#endif

    // declare the number of received messages of specific type
    int received_cert_msgs = 0;

    // declare the peer certificate
    SESS_CERT* sc;

    for (;;) {
        state = s->state;

        switch (s->state) {
        case SSL_ST_RENEGOTIATE:
            s->renegotiate = 1;
            s->state = SSL_ST_CONNECT;
            s->ctx->stats.sess_connect_renegotiate++;
            /* break // notice the silent state transition into a regular handshake */
        case SSL_ST_BEFORE:
        case SSL_ST_CONNECT:
        case SSL_ST_BEFORE | SSL_ST_CONNECT:
        case SSL_ST_OK | SSL_ST_CONNECT:

			SSL_set_role(s, SSL_ROLE_CLIENT, 0); // don't force because of proxy...
            if (cb != NULL)
                cb(s, SSL_CB_HANDSHAKE_START, 1);

            if ((s->version & 0xff00) != 0x0300) {
                SSLerr(SSL_F_SSL3_CONNECT, ERR_R_INTERNAL_ERROR);
                s->state = SSL_ST_ERR;
                ret = -1;
                goto end;
            }

            /* s->version=SSL3_VERSION; */
            s->type = SSL_ST_CONNECT;

            if (s->init_buf == NULL) {
                if ((buf = BUF_MEM_new()) == NULL) {
                    ret = -1;
                    s->state = SSL_ST_ERR;
                    goto end;
                }
                if (!BUF_MEM_grow(buf, SSL3_RT_MAX_PLAIN_LENGTH)) {
                    ret = -1;
                    s->state = SSL_ST_ERR;
                    goto end;
                }
                s->init_buf = buf;
                buf = NULL;
            }

            if (!ssl3_setup_buffers(s)) {
                ret = -1;
                goto end;
            }

            /* setup buffing BIO */
            if (!ssl_init_wbio_buffer(s, 0)) {
                ret = -1;
                s->state = SSL_ST_ERR;
                goto end;
            }

            /* don't push the buffering BIO quite yet */

            ssl3_init_finished_mac(s);

            // this method handles handshake as seen from the client
            s->state = SSL3_ST_CW_CLNT_HELLO_A;
            s->ctx->stats.sess_connect++;
            s->init_num = 0;
            s->s3->flags &= ~SSL3_FLAGS_CCS_OK;
            /*
             * Should have been reset by ssl3_get_finished, too.
             */
            s->s3->change_cipher_spec = 0;
            break;

        case SSL3_ST_CW_CLNT_HELLO_A:
        case SSL3_ST_CW_CLNT_HELLO_B:

            s->shutdown = 0;
            ret = ssl3_send_client_hello(s);
            if (ret <= 0)
                goto end;

            // this method handles handshake as seen from the client
            s->state = SSL3_ST_CR_SRVR_HELLO_A;
            s->init_num = 0;

            /* turn on buffering for the next lot of output */
            if (s->bbio != s->wbio)
                s->wbio = BIO_push(s->bbio, s->wbio);

            break;

        case SSL3_ST_CR_SRVR_HELLO_A:
        case SSL3_ST_CR_SRVR_HELLO_B:
            ret = ssl3_get_server_hello(s);
            if (ret <= 0)
                goto end;

            if (s->hit) {
            	// we're reusing a previous session => abbreviated handshake
                s->state = SSL3_ST_CR_FINISHED_A;
#ifndef OPENSSL_NO_TLSEXT
                if (s->tlsext_ticket_expected) {
                    /* receive renewed session ticket */
                    s->state = SSL3_ST_CR_SESSION_TICKET_A;
                }
#endif
            } else {
            	// we're creating a new session => full handshake
                s->state = SSL3_ST_CR_CERT_A;
            }
            s->init_num = 0;
            break;
        case SSL3_ST_CR_CERT_A:
        case SSL3_ST_CR_CERT_B:
#ifndef OPENSSL_NO_TLSEXT
            /* Noop (ret = 0) for everything but EAP-FAST. */
            ret = ssl3_check_finished(s);
            if (ret < 0)
                goto end;
            if (ret == 1) {
                s->hit = 1;
                s->state = SSL3_ST_CR_FINISHED_A;
                s->init_num = 0;
                break;
            }
#endif
            /* Check if it is anon DH/ECDH, SRP auth or PSK */
            if (!
                (s->s3->tmp.
                 new_cipher->algorithm_auth & (SSL_aNULL | SSL_aSRP))
                    && !(s->s3->tmp.new_cipher->algorithm_mkey & SSL_kPSK)) {
                ret = ssl3_get_certificate(s, received_cert_msgs);
                if (ret <= 0)
                    goto end;
                else
                	received_cert_msgs++;
#ifndef OPENSSL_NO_TLSEXT
                if (s->tlsext_status_expected)
                    s->state = SSL3_ST_CR_CERT_STATUS_A;
                else if(!s->session->is_inspected)
                    s->state = SSL3_ST_CR_KEY_EXCH_A;
                else {
                	/*
                	 * Otherwise 1 more cert message is required and state
                	 * persists.
                	 */
                }
            } else {
                skip = 1;
                s->state = SSL3_ST_CR_KEY_EXCH_A;
            }
#else
            } else
                skip = 1;

            s->state = SSL3_ST_CR_KEY_EXCH_A;
#endif
            s->init_num = 0;
            break;

        case SSL3_ST_CR_KEY_EXCH_A:
        case SSL3_ST_CR_KEY_EXCH_B:
        	sc = SSL_get_peer_cert(s);
        	ret = ssl3_get_key_exchange(s, &sc);
			if (ret <= 0)
				goto end;
			s->state = SSL3_ST_CR_CERT_REQ_A;
			s->init_num = 0;

			/*
			 * at this point we check that we have the required stuff from
			 * the server
			 */
			if (!ssl3_check_cert_and_algorithm(s, sc)) {
				ret = -1;
				s->state = SSL_ST_ERR;
				goto end;
			}
        	break;

        case SSL3_ST_CR_CERT_REQ_A:
        case SSL3_ST_CR_CERT_REQ_B:
        	// receive the message
        	ret = ssl3_get_certificate_request(s);
			if (ret <= 0)
				goto end;
			s->state = SSL3_ST_CR_SRVR_DONE_A;
			s->init_num = 0;
        	break;

        case SSL3_ST_CR_SRVR_DONE_A:
        case SSL3_ST_CR_SRVR_DONE_B:
            ret = ssl3_get_server_done(s);
            if (ret <= 0)
                goto end;
#ifndef OPENSSL_NO_SRP
            if (s->s3->tmp.new_cipher->algorithm_mkey & SSL_kSRP) {
                if ((ret = SRP_Calc_A_param(s)) <= 0) {
                    SSLerr(SSL_F_SSL3_CONNECT, SSL_R_SRP_A_CALC);
                    ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
                    s->state = SSL_ST_ERR;
                    goto end;
                }
            }
#endif
            if (s->s3->tmp.cert_req)
                s->state = SSL3_ST_CW_CERT_A;
            else
                s->state = SSL3_ST_CW_KEY_EXCH_A;
            s->init_num = 0;
            break;

        case SSL3_ST_CW_CERT_A:
        case SSL3_ST_CW_CERT_B:
        case SSL3_ST_CW_CERT_C:
        case SSL3_ST_CW_CERT_D:
            ret = ssl3_send_client_certificate(s);
            if (ret <= 0)
                goto end;
            s->state = SSL3_ST_CW_KEY_EXCH_A;
            s->init_num = 0;
            break;

        case SSL3_ST_CW_KEY_EXCH_A:
        case SSL3_ST_CW_KEY_EXCH_B:
        	// certificate must be identical to the one used in SSL3_ST_CR_KEY_EXCH_A
        	ret = ssl3_send_client_key_exchange(s, SSL_get_peer_cert(s));
            if (ret <= 0)
                goto end;
            /*
             * EAY EAY EAY need to check for DH fix cert sent back
             */
            /*
             * For TLS, cert_req is set to 2, so a cert chain of nothing is
             * sent, but no verify packet is sent
             */
            /*
             * XXX: For now, we do not support client authentication in ECDH
             * cipher suites with ECDH (rather than ECDSA) certificates. We
             * need to skip the certificate verify message when client's
             * ECDH public key is sent inside the client certificate.
             */
            if (s->s3->tmp.cert_req == 1) {
                s->state = SSL3_ST_CW_CERT_VRFY_A;
            } else {
                s->state = SSL3_ST_CW_CHANGE_A;
            }
            if (s->s3->flags & TLS1_FLAGS_SKIP_CERT_VERIFY) {
                s->state = SSL3_ST_CW_CHANGE_A;
            }

            s->init_num = 0;
            break;

        case SSL3_ST_CW_CERT_VRFY_A:
        case SSL3_ST_CW_CERT_VRFY_B:
        	ret = ssl3_send_client_verify(s);
            if (ret <= 0)
                goto end;
            s->state = SSL3_ST_CW_CHANGE_A;
            s->init_num = 0;
            break;

        case SSL3_ST_CW_CHANGE_A:
        case SSL3_ST_CW_CHANGE_B:
            ret = ssl3_send_change_cipher_spec(s,
                                               SSL3_ST_CW_CHANGE_A,
                                               SSL3_ST_CW_CHANGE_B);
            if (ret <= 0)
                goto end;

#if defined(OPENSSL_NO_TLSEXT) || defined(OPENSSL_NO_NEXTPROTONEG)
            s->state = SSL3_ST_CW_FINISHED_A;
#else
            if (s->s3->next_proto_neg_seen)
                s->state = SSL3_ST_CW_NEXT_PROTO_A;
            else
                s->state = SSL3_ST_CW_FINISHED_A;
#endif
            s->init_num = 0;

            s->session->cipher = s->s3->tmp.new_cipher;
#ifdef OPENSSL_NO_COMP
            s->session->compress_meth = 0;
#else
            if (s->s3->tmp.new_compression == NULL)
                s->session->compress_meth = 0;
            else
                s->session->compress_meth = s->s3->tmp.new_compression->id;
#endif
            if (!s->method->ssl3_enc->setup_key_block(s)) {
                ret = -1;
                s->state = SSL_ST_ERR;
                goto end;
            }

            if (!s->method->ssl3_enc->change_cipher_state(s,
                                                          SSL3_CHANGE_CIPHER_CLIENT_WRITE))
            {
                ret = -1;
                s->state = SSL_ST_ERR;
                goto end;
            }

            break;

#if !defined(OPENSSL_NO_TLSEXT) && !defined(OPENSSL_NO_NEXTPROTONEG)
        case SSL3_ST_CW_NEXT_PROTO_A:
        case SSL3_ST_CW_NEXT_PROTO_B:
            ret = ssl3_send_next_proto(s);
            if (ret <= 0)
                goto end;
            s->state = SSL3_ST_CW_FINISHED_A;
            break;
#endif

        case SSL3_ST_CW_FINISHED_A:
        case SSL3_ST_CW_FINISHED_B:
            ret = ssl3_send_finished(s,
                                     SSL3_ST_CW_FINISHED_A,
                                     SSL3_ST_CW_FINISHED_B,
                                     s->method->
                                     ssl3_enc->client_finished_label,
                                     s->method->
                                     ssl3_enc->client_finished_label_len);
            if (ret <= 0)
                goto end;
            s->state = SSL3_ST_CW_FLUSH;

            /* clear flags */
            s->s3->flags &= ~SSL3_FLAGS_POP_BUFFER;
            if (s->hit) {
                s->s3->tmp.next_state = SSL_ST_OK;
                if (s->s3->flags & SSL3_FLAGS_DELAY_CLIENT_FINISHED) {
                    s->state = SSL_ST_OK;
                    s->s3->flags |= SSL3_FLAGS_POP_BUFFER;
                    s->s3->delay_buf_pop_ret = 0;
                }
            } else {
#ifndef OPENSSL_NO_TLSEXT
                /*
                 * Allow NewSessionTicket if ticket expected
                 */
                if (s->tlsext_ticket_expected)
                    s->s3->tmp.next_state = SSL3_ST_CR_SESSION_TICKET_A;
                else
#endif

                    s->s3->tmp.next_state = SSL3_ST_CR_FINISHED_A;
            }
            s->init_num = 0;
            break;

#ifndef OPENSSL_NO_TLSEXT
        case SSL3_ST_CR_SESSION_TICKET_A:
        case SSL3_ST_CR_SESSION_TICKET_B:
            ret = ssl3_get_new_session_ticket(s);
            if (ret <= 0)
                goto end;
            s->state = SSL3_ST_CR_FINISHED_A;
            s->init_num = 0;
            break;

        case SSL3_ST_CR_CERT_STATUS_A:
        case SSL3_ST_CR_CERT_STATUS_B:
            ret = ssl3_get_cert_status(s, received_cert_msgs);
            if (ret <= 0)
                goto end;

            // change state
            if(s->session->is_inspected && (received_cert_msgs == 1)) {
            	// 1 more cert message is required
            	s->state = SSL3_ST_CR_CERT_A;
            }
            else {
            	s->state = SSL3_ST_CR_KEY_EXCH_A;
            }
            s->init_num = 0;
            break;
#endif

        case SSL3_ST_CR_FINISHED_A:
        case SSL3_ST_CR_FINISHED_B:
            if (!s->s3->change_cipher_spec)
                s->s3->flags |= SSL3_FLAGS_CCS_OK;
            ret = ssl3_get_finished(s, SSL3_ST_CR_FINISHED_A,
                                    SSL3_ST_CR_FINISHED_B);
            if (ret <= 0)
                goto end;

            if (s->hit)
                s->state = SSL3_ST_CW_CHANGE_A;
            else
                s->state = SSL_ST_OK;
            s->init_num = 0;
            break;

        case SSL3_ST_CW_FLUSH:
            s->rwstate = SSL_WRITING;
            if (BIO_flush(s->wbio) <= 0) {
                ret = -1;
                goto end;
            }
            s->rwstate = SSL_NOTHING;
            s->state = s->s3->tmp.next_state;
            break;

        case SSL_ST_OK:
            /* clean a few things up */
            ssl3_cleanup_key_block(s);

            if (s->init_buf != NULL) {
                BUF_MEM_free(s->init_buf);
                s->init_buf = NULL;
            }

            /*
             * If we are not 'joining' the last two packets, remove the
             * buffering now
             */
            if (!(s->s3->flags & SSL3_FLAGS_POP_BUFFER))
                ssl_free_wbio_buffer(s);
            /* else do it later in ssl3_write */

            s->init_num = 0;
            s->renegotiate = 0;
            s->new_session = 0;

            ssl_update_cache(s, SSL_SESS_CACHE_CLIENT);
            if (s->hit)
                s->ctx->stats.sess_hit++;

            ret = 1;
            /* s->server=0; */
            s->handshake_func = ssl3_connect;
            s->ctx->stats.sess_connect_good++;

            if (cb != NULL)
                cb(s, SSL_CB_HANDSHAKE_DONE, 1);

            goto end;
            /* break; */

        case SSL_ST_ERR:
        default:
            SSLerr(SSL_F_SSL3_CONNECT, SSL_R_UNKNOWN_STATE);
            ret = -1;
            goto end;
            /* break; */
        }

        /* did we do anything */
        if (!s->s3->tmp.reuse_message && !skip) {
            if (s->debug) {
                if ((ret = BIO_flush(s->wbio)) <= 0)
                    goto end;
            }

            if ((cb != NULL) && (s->state != state)) {
                new_state = s->state;
                s->state = state;
                cb(s, SSL_CB_CONNECT_LOOP, 1);
                s->state = new_state;
            }
        }
        skip = 0;
    }

 end:
    s->in_handshake--;
    if (buf != NULL)
        BUF_MEM_free(buf);
    if (cb != NULL)
        cb(s, SSL_CB_CONNECT_EXIT, ret);
    return (ret);
}

int ssl3_send_client_hello(SSL *s)
{
    unsigned char *buf;
    unsigned char *p, *d;
    int i;
    unsigned long l;
    int al = 0;
#ifndef OPENSSL_NO_COMP
    int j;
    SSL_COMP *comp;
#endif

    buf = (unsigned char *)s->init_buf->data;
    if (s->state == SSL3_ST_CW_CLNT_HELLO_A) {
        SSL_SESSION *sess = s->session;
        if ((sess == NULL) || (sess->ssl_version != s->version) ||
#ifdef OPENSSL_NO_TLSEXT
            !sess->session_id_length ||
#else
            /*
             * In the case of EAP-FAST, we can have a pre-shared
             * "ticket" without a session ID.
             */
            (!sess->session_id_length && !sess->tlsext_tick) ||
#endif
            (sess->not_resumable)) {
            if (!ssl_get_new_session(s, 0))
                goto err;
        }
        if (s->method->version == DTLS_ANY_VERSION) {
            /* Determine which DTLS version to use */
            int options = s->options;
            /* If DTLS 1.2 disabled correct the version number */
            if (options & SSL_OP_NO_DTLSv1_2) {
                if (tls1_suiteb(s)) {
                    SSLerr(SSL_F_SSL3_CLIENT_HELLO,
                           SSL_R_ONLY_DTLS_1_2_ALLOWED_IN_SUITEB_MODE);
                    goto err;
                }
                /*
                 * Disabling all versions is silly: return an error.
                 */
                if (options & SSL_OP_NO_DTLSv1) {
                    SSLerr(SSL_F_SSL3_CLIENT_HELLO, SSL_R_WRONG_SSL_VERSION);
                    goto err;
                }
                /*
                 * Update method so we don't use any DTLS 1.2 features.
                 */
                s->method = DTLSv1_client_method();
                s->version = DTLS1_VERSION;
            } else {
                /*
                 * We only support one version: update method
                 */
                if (options & SSL_OP_NO_DTLSv1)
                    s->method = DTLSv1_2_client_method();
                s->version = DTLS1_2_VERSION;
            }
            s->client_version = s->version;
        }
        /* else use the pre-loaded session */

        p = s->s3->client_random;

        /*
         * for DTLS if client_random is initialized, reuse it, we are
         * required to use same upon reply to HelloVerify
         */
        if (SSL_IS_DTLS(s)) {
            size_t idx;
            i = 1;
            for (idx = 0; idx < sizeof(s->s3->client_random); idx++) {
                if (p[idx]) {
                    i = 0;
                    break;
                }
            }
        } else
            i = 1;

        // generate client random bytes
        if (SSL_is_client(s) && i && ssl_fill_hello_random(s, 0, p,
        		sizeof(s->s3->client_random)) <= 0) {
            goto err;
        }

        /* Do the message type and length last */
        d = p = ssl_handshake_start(s);

        /*-
         * version indicates the negotiated version: for example from
         * an SSLv2/v3 compatible client hello). The client_version
         * field is the maximum version we permit and it is also
         * used in RSA encrypted premaster secrets. Some servers can
         * choke if we initially report a higher version then
         * renegotiate to a lower one in the premaster secret. This
         * didn't happen with TLS 1.0 as most servers supported it
         * but it can with TLS 1.1 or later if the server only supports
         * 1.0.
         *
         * Possible scenario with previous logic:
         *      1. Client hello indicates TLS 1.2
         *      2. Server hello says TLS 1.0
         *      3. RSA encrypted premaster secret uses 1.2.
         *      4. Handshake proceeds using TLS 1.0.
         *      5. Server sends hello request to renegotiate.
         *      6. Client hello indicates TLS v1.0 as we now
         *         know that is maximum server supports.
         *      7. Server chokes on RSA encrypted premaster secret
         *         containing version 1.0.
         *
         * For interoperability it should be OK to always use the
         * maximum version we support in client hello and then rely
         * on the checking of version to ensure the servers isn't
         * being inconsistent: for example initially negotiating with
         * TLS 1.0 and renegotiating with TLS 1.2. We do this by using
         * client_version in client hello and not resetting it to
         * the negotiated version.
         */
#if 0
        *(p++) = s->version >> 8;
        *(p++) = s->version & 0xff;
        s->client_version = s->version;
#else
        *(p++) = s->client_version >> 8;
        *(p++) = s->client_version & 0xff;
#endif

        /* Random stuff */
        memcpy(p, s->s3->client_random, SSL3_RANDOM_SIZE);
        p += SSL3_RANDOM_SIZE;

        /* Session ID */
        if (s->new_session) {
            i = 0;
        } else {
            i = s->session->session_id_length;
        }

        *(p++) = i;
        if (i != 0) {
            if (i > (int)sizeof(s->session->session_id)) {
                SSLerr(SSL_F_SSL3_CLIENT_HELLO, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            memcpy(p, s->session->session_id, i);
            p += i;
        }

        /* cookie stuff for DTLS */
        if (SSL_IS_DTLS(s)) {
            if (s->d1->cookie_len > sizeof(s->d1->cookie)) {
                SSLerr(SSL_F_SSL3_CLIENT_HELLO, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            *(p++) = s->d1->cookie_len;
            memcpy(p, s->d1->cookie, s->d1->cookie_len);
            p += s->d1->cookie_len;
        }

        /* Ciphers supported - don't free this stack! */
        STACK_OF(SSL_CIPHER)* cipher_stack = SSL_get_ciphers(s);
        if (SSL_is_proxy(s)) {
        	if (s->hit) {
        		// restore the saved stack
        		cipher_stack = s->session->ciphers;
        	} else {
        		/*
        		 * Determine the client's supported & allowed crypto hash functions.
        		 */

				int sha1 = 0;
				int sha256 = 0;
				int sha384 = 0;
				SSL_get_hash_codes(s->session->ciphers, &sha1, &sha256, &sha384);

				// we don't need the client's cipher list anymore
				sk_SSL_CIPHER_free(s->session->ciphers);
				s->session->ciphers = NULL;

				/*
				 * Determine the proxy's cipher list.
				 */

				// for client authentication to work, we need to evict DH or ECDH ahead of time
				SSL_filter_DH_and_ECDH_kxchng(cipher_stack);

				// then, we have to adjust our cipher list according to the client
				// Note: this method also filters any cipher with a non-<SHA1,SHA384> crypto hash
				SSL_filter_by_hash_codes(cipher_stack, sha1, sha256, sha384);

				// and finally, save the list so we can use it when resuming session
				s->session->ciphers = cipher_stack;
        	}
        }

        // write the list & check result
        i = ssl_cipher_list_to_bytes(s, cipher_stack, &(p[2]), 0);
        if (i == 0) {
            SSLerr(SSL_F_SSL3_CLIENT_HELLO, SSL_R_NO_CIPHERS_AVAILABLE);
            goto err;
        }
#ifdef OPENSSL_MAX_TLS1_2_CIPHER_LENGTH
        /*
         * Some servers hang if client hello > 256 bytes as hack workaround
         * chop number of supported ciphers to keep it well below this if we
         * use TLS v1.2
         */
        if (TLS1_get_version(s) >= TLS1_2_VERSION
            && i > OPENSSL_MAX_TLS1_2_CIPHER_LENGTH)
            i = OPENSSL_MAX_TLS1_2_CIPHER_LENGTH & ~1;
#endif
        s2n(i, p);
        p += i;

        /* COMPRESSION */
#ifdef OPENSSL_NO_COMP
        *(p++) = 1;
#else

        if ((s->options & SSL_OP_NO_COMPRESSION)
            || !s->ctx->comp_methods)
            j = 0;
        else
            j = sk_SSL_COMP_num(s->ctx->comp_methods);
        *(p++) = 1 + j;
        for (i = 0; i < j; i++) {
            comp = sk_SSL_COMP_value(s->ctx->comp_methods, i);
            *(p++) = comp->id;
        }
#endif
        *(p++) = 0;             /* Add the NULL method */

#ifndef OPENSSL_NO_TLSEXT
        /* TLS extensions */
        if (SSL_is_client(s) && (ssl_prepare_clienthello_tlsext(s) <= 0)) {
            SSLerr(SSL_F_SSL3_CLIENT_HELLO, SSL_R_CLIENTHELLO_TLSEXT);
            goto err;
        }
        if ((p =
             ssl_add_clienthello_tlsext(s, p, buf + SSL3_RT_MAX_PLAIN_LENGTH,
                                        &al)) == NULL) {
            ssl3_send_alert(s, SSL3_AL_FATAL, al);
            SSLerr(SSL_F_SSL3_CLIENT_HELLO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
#endif

        l = p - d;
        ssl_set_handshake_header(s, SSL3_MT_CLIENT_HELLO, l);
        s->state = SSL3_ST_CW_CLNT_HELLO_B;
    }

    /* SSL3_ST_CW_CLNT_HELLO_B */
    return ssl_do_write(s);
 err:
    s->state = SSL_ST_ERR;
    return (-1);
}

int ssl3_get_server_hello(SSL *s)
{
    STACK_OF(SSL_CIPHER) *sk;
    const SSL_CIPHER *c;
    CERT *ct = s->cert;
    unsigned char *p, *d;
    int i, al = SSL_AD_INTERNAL_ERROR, ok;
    unsigned int j;
    long n;
#ifndef OPENSSL_NO_COMP
    SSL_COMP *comp;
#endif
    /*
     * Hello verify request and/or server hello version may not match so set
     * first packet if we're negotiating version.
     */
    if (SSL_IS_DTLS(s))
        s->first_packet = 1;

    n = s->method->ssl_get_message(s,
                                   SSL3_ST_CR_SRVR_HELLO_A,
                                   SSL3_ST_CR_SRVR_HELLO_B, -1, 20000, &ok);

    // basic checks
    if (!ok) {
        return ((int)n);
    }
    if (s->s3->tmp.message_type != SSL3_MT_SERVER_HELLO) {
        al = SSL_AD_UNEXPECTED_MESSAGE;
        SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, SSL_R_BAD_MESSAGE_TYPE);
        goto f_err;
    } else {
    	d = p = (unsigned char *)s->init_msg;
    }

    // if proxy, queue the message
    if (SSL_is_proxy(s)) {
    	/*
		 * Ignore the function result and always process Hello messages
		 * until the next callback, where the decision about forwarding
		 * will take place.
		 */
    	tls12_prx_msg_rcvd_early_cb(s, p, n, s->s3->tmp.message_type);
	}

	if (SSL_IS_DTLS(s)) {
		s->first_packet = 0;
		if (s->s3->tmp.message_type == DTLS1_MT_HELLO_VERIFY_REQUEST) {
			if (s->d1->send_cookie == 0) {
				s->s3->tmp.reuse_message = 1;
				return 1;
			} else {            /* already sent a cookie */

				al = SSL_AD_UNEXPECTED_MESSAGE;
				SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, SSL_R_BAD_MESSAGE_TYPE);
				goto f_err;
			}
		}
	}

    if (s->method->version == DTLS_ANY_VERSION) {
        /* Work out correct protocol version to use */
        int hversion = (p[0] << 8) | p[1];
        int options = s->options;
        if (hversion == DTLS1_2_VERSION && !(options & SSL_OP_NO_DTLSv1_2))
            s->method = DTLSv1_2_client_method();
        else if (tls1_suiteb(s)) {
            SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,
                   SSL_R_ONLY_DTLS_1_2_ALLOWED_IN_SUITEB_MODE);
            s->version = hversion;
            al = SSL_AD_PROTOCOL_VERSION;
            goto f_err;
        } else if (hversion == DTLS1_VERSION && !(options & SSL_OP_NO_DTLSv1))
            s->method = DTLSv1_client_method();
        else {
            SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, SSL_R_WRONG_SSL_VERSION);
            s->version = hversion;
            al = SSL_AD_PROTOCOL_VERSION;
            goto f_err;
        }
        s->session->ssl_version = s->version = s->method->version;
    }

    if ((p[0] != (s->version >> 8)) || (p[1] != (s->version & 0xff))) {
        SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, SSL_R_WRONG_SSL_VERSION);
        s->version = (s->version & 0xff00) | p[1];
        al = SSL_AD_PROTOCOL_VERSION;
        goto f_err;
    }
    p += 2;

    /* load the server hello data */
    /* load the server random */
    memcpy(s->s3->server_random, p, SSL3_RANDOM_SIZE);
    p += SSL3_RANDOM_SIZE;

    /* get & check the session-id */
    j = *(p++);
    if ((j > sizeof s->session->session_id) || (j > SSL3_SESSION_ID_SIZE)) {
		al = SSL_AD_ILLEGAL_PARAMETER;
		SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, SSL_R_SSL3_SESSION_ID_TOO_LONG);
		goto f_err;
	}

#ifndef OPENSSL_NO_TLSEXT
    /*
     * Check if we can resume the session based on external pre-shared secret.
     * EAP-FAST (RFC 4851) supports two types of session resumption.
     * Resumption based on server-side state works with session IDs.
     * Resumption based on pre-shared Protected Access Credentials (PACs)
     * works by overriding the SessionTicket extension at the application
     * layer, and does not send a session ID. (We do not know whether EAP-FAST
     * servers would honour the session ID.) Therefore, the session ID alone
     * is not a reliable indicator of session resumption, so we first check if
     * we can resume, and later peek at the next handshake message to see if the
     * server wants to resume.
     */
    s->hit = 0;
    if (s->version >= TLS1_VERSION && s->tls_session_secret_cb &&
        s->session->tlsext_tick) {
        SSL_CIPHER *pref_cipher = NULL;
        s->session->master_key_length = sizeof(s->session->master_key);
        if (s->tls_session_secret_cb(s, s->session->master_key,
                                     &s->session->master_key_length,
                                     NULL, &pref_cipher,
                                     s->tls_session_secret_cb_arg)) {
            s->session->cipher = pref_cipher ?
                pref_cipher : ssl_get_cipher_by_char(s, p + j);
        } else {
            SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, ERR_R_INTERNAL_ERROR);
            al = SSL_AD_INTERNAL_ERROR;
            goto f_err;
        }
    }
#endif                          /* OPENSSL_NO_TLSEXT */

    if (j != 0 && j == s->session->session_id_length
        && memcmp(p, s->session->session_id, j) == 0) {
        if (s->sid_ctx_length != s->session->sid_ctx_length
            || memcmp(s->session->sid_ctx, s->sid_ctx, s->sid_ctx_length)) {
            /* actually a client application bug */
            al = SSL_AD_ILLEGAL_PARAMETER;
            SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,
                   SSL_R_ATTEMPT_TO_REUSE_SESSION_IN_DIFFERENT_CONTEXT);
            goto f_err;
        }
        s->hit = 1;
    } else {
        /*
         * If we were trying for session-id reuse but the server
         * didn't echo the ID, make a new SSL_SESSION.
         * In the case of EAP-FAST and PAC, we do not send a session ID,
         * so the PAC-based session secret is always preserved. It'll be
         * overwritten if the server refuses resumption.
         */
        if (s->session->session_id_length > 0) {
            if (!ssl_get_new_session(s, 0)) {
                goto f_err;
            }
        }
        s->session->session_id_length = j;
        memcpy(s->session->session_id, p, j); /* j could be 0 */
    }

    p += j;
    c = ssl_get_cipher_by_char(s, p);
    if (c == NULL) {
        /* unknown cipher */
        al = SSL_AD_ILLEGAL_PARAMETER;
        SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, SSL_R_UNKNOWN_CIPHER_RETURNED);
        goto f_err;
    }

    /* Set version disabled mask now we know version */
    if (!SSL_USE_TLS1_2_CIPHERS(s)) {
        ct->mask_ssl = SSL_TLSV1_2;
    } else {
        ct->mask_ssl = 0;
    }

    /*
     * If it is a disabled cipher we didn't send it in client hello, so
     * return an error.
     */
    if (c->algorithm_ssl & ct->mask_ssl ||
        c->algorithm_mkey & ct->mask_k || c->algorithm_auth & ct->mask_a) {
        al = SSL_AD_ILLEGAL_PARAMETER;
        SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, SSL_R_WRONG_CIPHER_RETURNED);
        goto f_err;
    }
    p += ssl_put_cipher_by_char(s, NULL, NULL);

    sk = ssl_get_ciphers_by_id(s);
    i = sk_SSL_CIPHER_find(sk, c);
    if (i < 0) {
        /* we did not say we would use this cipher */
        al = SSL_AD_ILLEGAL_PARAMETER;
        SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, SSL_R_WRONG_CIPHER_RETURNED);
        goto f_err;
    }

    /*
     * Depending on the session caching (internal/external), the cipher
     * and/or cipher_id values may not be set. Make sure that cipher_id is
     * set and use it for comparison.
     */
    if (s->session->cipher) {
        s->session->cipher_id = s->session->cipher->id;
    }
    if (s->hit && (s->session->cipher_id != c->id)) {
/* Workaround is now obsolete */
#if 0
        if (!(s->options & SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG))
#endif
        {
            al = SSL_AD_ILLEGAL_PARAMETER;
            SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,
                   SSL_R_OLD_SESSION_CIPHER_NOT_RETURNED);
            goto f_err;
        }
    }
    s->s3->tmp.new_cipher = c;

    /*
     * Don't digest cached records if no sigalgs: we may need them for client
     * authentication.
     */
    if (!SSL_USE_SIGALGS(s) && !ssl3_digest_cached_records(s)) {
        goto f_err;
    }

    /* lets get the compression algorithm */
    /* COMPRESSION */
#ifdef OPENSSL_NO_COMP
    if (*(p++) != 0) {
        al = SSL_AD_ILLEGAL_PARAMETER;
        SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,
               SSL_R_UNSUPPORTED_COMPRESSION_ALGORITHM);
        goto f_err;
    }
    /*
     * If compression is disabled we'd better not try to resume a session
     * using compression.
     */
    if (s->session->compress_meth != 0) {
        SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, SSL_R_INCONSISTENT_COMPRESSION);
        goto f_err;
    }
#else
    j = *(p++);
    if (s->hit && j != s->session->compress_meth) {
        al = SSL_AD_ILLEGAL_PARAMETER;
        SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,
               SSL_R_OLD_SESSION_COMPRESSION_ALGORITHM_NOT_RETURNED);
        goto f_err;
    }
    if (j == 0) {
        comp = NULL;
    } else if (s->options & SSL_OP_NO_COMPRESSION) {
        al = SSL_AD_ILLEGAL_PARAMETER;
        SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, SSL_R_COMPRESSION_DISABLED);
        goto f_err;
    } else {
        comp = ssl3_comp_find(s->ctx->comp_methods, j);
    }
    if ((j != 0) && (comp == NULL)) {
        al = SSL_AD_ILLEGAL_PARAMETER;
        SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,
               SSL_R_UNSUPPORTED_COMPRESSION_ALGORITHM);
        goto f_err;
    } else {
        s->s3->tmp.new_compression = comp;
    }
#endif

#ifndef OPENSSL_NO_TLSEXT
    /* TLS extensions */
    if (!ssl_parse_serverhello_tlsext(s, &p, d, n)) {
        SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, SSL_R_PARSE_TLSEXT);
        goto err;
    }
#endif

    if (p != (d + n)) {
        /* wrong packet length */
        al = SSL_AD_DECODE_ERROR;
        SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, SSL_R_BAD_PACKET_LENGTH);
        goto f_err;
    }

    // a proxy "extension" of this method
	if (SSL_is_proxy(s) && !tls12_prx_srvr_hll_rcvd_cb(s)) {
		goto f_err;
	}

 done:
    return (1);
 f_err:
    ssl3_send_alert(s, SSL3_AL_FATAL, al);
 err:
    s->state = SSL_ST_ERR;
    return (-1);
}

int ssl3_get_certificate(SSL *s, int received_cert_msgs)
{
    int al, i, ok, ret = -1;
    unsigned long n, nc, llen, l;
    X509 *x = NULL;
    const unsigned char *q, *p;
    unsigned char *d;
    STACK_OF(X509) *sk = NULL;
    SESS_CERT *sc;
    EVP_PKEY *pkey = NULL;
    int need_cert = 1;          /* VRS: 0=> will allow null cert if auth ==
                                 * KRB5 */

    /*
     * Receive the chain.
     */

    n = s->method->ssl_get_message(s,
                                   SSL3_ST_CR_CERT_A,
                                   SSL3_ST_CR_CERT_B,
                                   -1, s->max_cert_list, &ok);

    // basic checks
    if (!ok) {
        return ((int)n);
    }

    if ((s->s3->tmp.message_type == SSL3_MT_SERVER_KEY_EXCHANGE) ||
        ((s->s3->tmp.new_cipher->algorithm_auth & SSL_aKRB5) &&
         (s->s3->tmp.message_type == SSL3_MT_SERVER_DONE))) {
        s->s3->tmp.reuse_message = 1;
        return (1);
    } else if (s->s3->tmp.message_type != SSL3_MT_CERTIFICATE) {
        al = SSL_AD_UNEXPECTED_MESSAGE;
        SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE, SSL_R_BAD_MESSAGE_TYPE);
        goto f_err;
    } else {
    	p = d = (unsigned char *)s->init_msg;
    }

    // if proxy, queue the message
	if (SSL_is_proxy(s) && (tls12_prx_msg_rcvd_early_cb(s, p, n,
			s->s3->tmp.message_type) == 2)) {
		goto done;
	}

    if ((sk = sk_X509_new_null()) == NULL) {
        SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    n2l3(p, llen);
    if (llen + 3 != n) {
        al = SSL_AD_DECODE_ERROR;
        SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE, SSL_R_LENGTH_MISMATCH);
        goto f_err;
    }
    for (nc = 0; nc < llen;) {
        n2l3(p, l);
        if ((l + nc + 3) > llen) {
            al = SSL_AD_DECODE_ERROR;
            SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,
                   SSL_R_CERT_LENGTH_MISMATCH);
            goto f_err;
        }

        q = p;
        x = d2i_X509(NULL, &q, l);
        if (x == NULL) {
            al = SSL_AD_BAD_CERTIFICATE;
            SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE, ERR_R_ASN1_LIB);
            goto f_err;
        }
        if (q != (p + l)) {
            al = SSL_AD_DECODE_ERROR;
            SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,
                   SSL_R_CERT_LENGTH_MISMATCH);
            goto f_err;
        }
        if (!sk_X509_push(sk, x)) {
            SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        x = NULL;
        nc += l + 3;
        p = q;
    }

    /*
	 * Verify the received chain.
	 */
    int server_cert = received_cert_msgs == 0;

    // only if we're not a proxy though
    if (!SSL_is_proxy(s)) {
    	// verify
    	i = ssl_verify_cert_chain(s, sk, server_cert);

    	// check result
    	long verify_result = server_cert ? s->verify_result : s->proxy_verify_result;
		if ((s->verify_mode != SSL_VERIFY_NONE) && (i <= 0)
#ifndef OPENSSL_NO_KRB5
			&& !((s->s3->tmp.new_cipher->algorithm_mkey & SSL_kKRB5) &&
				 (s->s3->tmp.new_cipher->algorithm_auth & SSL_aKRB5))
#endif                          /* OPENSSL_NO_KRB5 */
			) {
			al = ssl_verify_alarm_type(verify_result, server_cert);
			SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,
				   SSL_R_CERTIFICATE_VERIFY_FAILED);
			goto f_err;
		}
		ERR_clear_error(); /* but we keep the original verification result */
    }

    /*
	 * Save the received chain.
	 */

    sc = ssl_sess_cert_new();
    if (sc == NULL)
        goto err;
    sc->cert_chain = sk;

    /*
     * Inconsistency alert: cert_chain includes the end-entity certificate,
     * which we don't include in s3_srvr.c
     */
    x = sk_X509_value(sk, 0);
    sk = NULL; // from now on, we only handle 'x'

    /*
     * VRS 19990621: possible memory leak; sk=null ==> !sk_pop_free() @end
     */
    pkey = X509_get_pubkey(x);

    /*
	 * Some special behaviour for Kerberos.
	 * VRS: allow null cert if auth == KRB5
	 */
    need_cert = ((s->s3->tmp.new_cipher->algorithm_mkey & SSL_kKRB5) &&
                 (s->s3->tmp.new_cipher->algorithm_auth & SSL_aKRB5))
        ? 0 : 1;
#ifdef KSSL_DEBUG
    fprintf(stderr, "pkey,x = %p, %p\n", pkey, x);
    fprintf(stderr, "ssl_cert_type(x,pkey) = %d\n", ssl_cert_type(x, pkey));
    fprintf(stderr, "cipher, alg, nc = %s, %lx, %lx, %d\n",
            s->s3->tmp.new_cipher->name,
            s->s3->tmp.new_cipher->algorithm_mkey,
            s->s3->tmp.new_cipher->algorithm_auth, need_cert);
#endif                          /* KSSL_DEBUG */

    /*
	 * This is not exclusive to Kerberos anymore.
	 */
    if (need_cert && ((pkey == NULL) || EVP_PKEY_missing_parameters(pkey))) {
        x = NULL;
        al = SSL3_AL_FATAL;
        SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,
               SSL_R_UNABLE_TO_FIND_PUBLIC_KEY_PARAMETERS);
        goto f_err;
    }
    i = ssl_cert_type(x, pkey);
    if (need_cert && i < 0) {
        x = NULL;
        al = SSL3_AL_FATAL;
        SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,
               SSL_R_UNKNOWN_CERTIFICATE_TYPE);
        goto f_err;
    }
    if (need_cert) {
        int exp_idx = ssl_cipher_get_cert_index(s->s3->tmp.new_cipher);
        if (exp_idx >= 0 && i != exp_idx) {
            x = NULL;
            al = SSL_AD_ILLEGAL_PARAMETER;
            SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,
                   SSL_R_WRONG_CERTIFICATE_TYPE);
            goto f_err;
        }
        sc->peer_cert_type = i;
        CRYPTO_add(&x->references, 1, CRYPTO_LOCK_X509);

        /*
         * Why would the following ever happen? We just created sc a couple
         * of lines ago.
         */
        if (sc->peer_pkeys[i].x509 != NULL)
            X509_free(sc->peer_pkeys[i].x509);
        sc->peer_pkeys[i].x509 = x;
        sc->peer_key = &(sc->peer_pkeys[i]);

        // register the public key
        X509** pubkey_ptr = server_cert ? &(s->session->server_key) : &(s->session->peer_key);
        if (*pubkey_ptr != NULL)
        	X509_free(*pubkey_ptr);
        CRYPTO_add(&x->references, 1, CRYPTO_LOCK_X509);
        *pubkey_ptr = x;
    } else {

    	/*
    	 * Kerberos again... really?
    	 */
        sc->peer_cert_type = i;
        sc->peer_key = NULL;
		if (s->session->server_key != NULL)
			X509_free(s->session->server_key);
		s->session->server_key = NULL;
    }

    /*
	 * Finish handling the new received certificate.
	 */

    if(server_cert) {
    	s->session->verify_result = s->verify_result;
    	if (s->session->end_cert)
    		ssl_sess_cert_free(s->session->end_cert);
    	s->session->end_cert = sc;
    }
    else {
    	s->session->proxy_verify_result = s->proxy_verify_result;
    	if (s->session->peer_cert)
    		ssl_sess_cert_free(s->session->peer_cert);
    	s->session->peer_cert = sc;
    }

    // a proxy "extension" of this method
	if (SSL_is_proxy(s) && !tls12_prx_srvr_crt_rcvd_cb(s)) {
		goto f_err;
	}

 done:
    x = NULL;
    ret = 1;
    if (0) {
 f_err:
        ssl3_send_alert(s, SSL3_AL_FATAL, al);
 err:
        s->state = SSL_ST_ERR;
    }

    EVP_PKEY_free(pkey);
    X509_free(x);
    sk_X509_pop_free(sk, X509_free);
    return (ret);
}

int ssl3_get_key_exchange(SSL* s, SESS_CERT** sc)
{
#ifndef OPENSSL_NO_RSA
    unsigned char *q, md_buf[EVP_MAX_MD_SIZE * 2];
#endif
    EVP_MD_CTX md_ctx;
    unsigned char *d, *p;
    int al, j, ok;
    long i, param_len, n, alg_k, alg_a;
    EVP_PKEY *pkey = NULL;
    const EVP_MD *md = NULL;
#ifndef OPENSSL_NO_DH
    DH *dh = NULL;
#endif
#ifndef OPENSSL_NO_ECDH
    EC_KEY *ecdh = NULL;
    BN_CTX *bn_ctx = NULL;
    EC_POINT *srvr_ecpoint = NULL;
    int curve_nid = 0;
    int encoded_pt_len = 0;
#endif

    EVP_MD_CTX_init(&md_ctx);

    /*
     * use same message size as in ssl3_get_certificate_request() as
     * ServerKeyExchange message may be skipped
     */
    n = s->method->ssl_get_message(s,
                                   SSL3_ST_CR_KEY_EXCH_A,
                                   SSL3_ST_CR_KEY_EXCH_B,
                                   -1, s->max_cert_list, &ok);
    if (!ok) {
        return ((int)n);
    }

    alg_k = s->s3->tmp.new_cipher->algorithm_mkey;

    // logically handle incoming message
    if (s->s3->tmp.message_type != SSL3_MT_SERVER_KEY_EXCHANGE) {
    	// must be one of:
    	if((s->s3->tmp.message_type != SSL3_MT_CERTIFICATE_REQUEST) &&
				(s->s3->tmp.message_type != SSL3_MT_SERVER_DONE)) {
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_UNEXPECTED_MESSAGE);
			al = SSL_AD_UNEXPECTED_MESSAGE;
			goto f_err;
		}
    	// verify the current state
		if(alg_k & (SSL_kDHE | SSL_kECDHE)) {
			// the peer's public key is required, if ephemeral
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_UNEXPECTED_MESSAGE);
			al = SSL_AD_UNEXPECTED_MESSAGE;
			goto f_err;
		}
#ifndef OPENSSL_NO_PSK
		/*
		 * In plain PSK ciphersuite, ServerKeyExchange can be omitted if no
		 * identity hint is sent. Set session->end_cert anyway to avoid
		 * problems later.
		 */
		if (alg_k & SSL_kPSK) {
			*sc = ssl_sess_cert_new();
			if (s->ctx->psk_identity_hint)
				OPENSSL_free(s->ctx->psk_identity_hint);
			s->ctx->psk_identity_hint = NULL;
		}
#endif
        // if we don't end up with an error, reuse the message
        s->s3->tmp.reuse_message = 1;
        return (2); // a special indicator, distinct from 1 (success)
    } else {
    	d = p = (unsigned char *)s->init_msg;
    }

    // if proxy, queue the message
	if (SSL_is_proxy(s) && (tls12_prx_msg_rcvd_early_cb(s, p, n,
			s->s3->tmp.message_type) == 2)) {
		goto done;
	}

    if (*sc == NULL) {
    	*sc = ssl_sess_cert_new();
    } else {
    	// reset all public keys for sharing the premaster secret
    	SSL_set_peer_RSA_tmp_pubkey(s, NULL);
    	SSL_set_peer_DHE_tmp_pubkey(s, NULL);
    	SSL_set_peer_ECDHE_tmp_pubkey(s, NULL);
    }

    // setup some common variables
    param_len = 0; // total length of the parameters including the length prefix
    alg_a = s->s3->tmp.new_cipher->algorithm_auth;
    al = SSL_AD_DECODE_ERROR;

#ifndef OPENSSL_NO_PSK
    if (alg_k & SSL_kPSK) {
        param_len = 2;
        if (param_len > n) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_LENGTH_TOO_SHORT);
            goto f_err;
        }
        n2s(p, i);

        /*
         * Store PSK identity hint for later use, hint is used in
         * ssl3_send_client_key_exchange.  Assume that the maximum length of
         * a PSK identity hint can be as long as the maximum length of a PSK
         * identity.
         */
        if (i > PSK_MAX_IDENTITY_LEN) {
            al = SSL_AD_HANDSHAKE_FAILURE;
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_DATA_LENGTH_TOO_LONG);
            goto f_err;
        }
        if (i > n - param_len) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
                   SSL_R_BAD_PSK_IDENTITY_HINT_LENGTH);
            goto f_err;
        }
        param_len += i;

        s->session->psk_identity_hint = BUF_strndup((char *)p, i);
        if (s->session->psk_identity_hint == NULL) {
            al = SSL_AD_HANDSHAKE_FAILURE;
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_MALLOC_FAILURE);
            goto f_err;
        }

        p += i;
        n -= param_len;
    } else
#endif                          /* !OPENSSL_NO_PSK */
#ifndef OPENSSL_NO_SRP
    if (alg_k & SSL_kSRP) {
        param_len = 2;
        if (param_len > n) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_LENGTH_TOO_SHORT);
            goto f_err;
        }
        n2s(p, i);

        if (i > n - param_len) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_BAD_SRP_N_LENGTH);
            goto f_err;
        }
        param_len += i;

        if (!(s->srp_ctx.N = BN_bin2bn(p, i, NULL))) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_BN_LIB);
            goto err;
        }
        p += i;

        if (2 > n - param_len) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_LENGTH_TOO_SHORT);
            goto f_err;
        }
        param_len += 2;

        n2s(p, i);

        if (i > n - param_len) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_BAD_SRP_G_LENGTH);
            goto f_err;
        }
        param_len += i;

        if (!(s->srp_ctx.g = BN_bin2bn(p, i, NULL))) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_BN_LIB);
            goto err;
        }
        p += i;

        if (1 > n - param_len) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_LENGTH_TOO_SHORT);
            goto f_err;
        }
        param_len += 1;

        i = (unsigned int)(p[0]);
        p++;

        if (i > n - param_len) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_BAD_SRP_S_LENGTH);
            goto f_err;
        }
        param_len += i;

        if (!(s->srp_ctx.s = BN_bin2bn(p, i, NULL))) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_BN_LIB);
            goto err;
        }
        p += i;

        if (2 > n - param_len) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_LENGTH_TOO_SHORT);
            goto f_err;
        }
        param_len += 2;

        n2s(p, i);

        if (i > n - param_len) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_BAD_SRP_B_LENGTH);
            goto f_err;
        }
        param_len += i;

        if (!(s->srp_ctx.B = BN_bin2bn(p, i, NULL))) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_BN_LIB);
            goto err;
        }
        p += i;
        n -= param_len;

        if (!srp_verify_server_param(s, &al)) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_BAD_SRP_PARAMETERS);
            goto f_err;
        }

        // handle authentication
# ifndef OPENSSL_NO_RSA // NOTE: still inside SRP
        if (alg_a & SSL_aRSA)
        	pkey = X509_get_pubkey(
        			*sc->peer_pkeys[SSL_PKEY_RSA_ENC].x509);
# else
        if (0) ;
# endif
# ifndef OPENSSL_NO_DSA // NOTE: still inside SRP
        else if (alg_a & SSL_aDSS)
        	pkey = X509_get_pubkey(
        			*sc->peer_pkeys[SSL_PKEY_DSA_SIGN].x509);
# endif
    } else
#endif                          /* !OPENSSL_NO_SRP */

#ifndef OPENSSL_NO_RSA
    if (alg_k & SSL_kRSA) {
        /*
         * Temporary RSA keys are only allowed in export ciphersuites but a proxy's
         * RSA public key in the proxy-server session is required by the TPE extension
         * if the server requests the client to authenticate. The
         * 'ssl3_send_client_key_exchange' function indicates that these two cases
    	 * are mutually exclusive.
    	 */

    	if (s->session->is_inspected) {
    		// this is client-specific
    		if (SSL_is_proxy(s)) {
    			al = SSL_AD_INTERNAL_ERROR;
    			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_TLSV1_ALERT_INTERNAL_ERROR);
    			goto f_err;
    		}

    		// determine public key for authentication
			if (alg_a & SSL_aRSA) {
				pkey = X509_get_pubkey(
						(*sc)->peer_pkeys[SSL_PKEY_RSA_ENC].x509);
			} else if (alg_a & (SSL_aDSS | SSL_aECDSA)) {
				// there is no RSA_DSA or RSA_ECDSA ciphersuite in the registry
				al = SSL_AD_INTERNAL_ERROR;
				SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_INTERNAL_ERROR);
				goto f_err;
			} else {
				// anonymous ciphersuites are not compatible with inspection
				al = SSL_AD_HANDSHAKE_FAILURE;
				SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
						SSL_R_TLS_TPE_ANON_CIPHERSUITES_NOT_SUPPORTED);
				goto f_err;
			}

			/*
			 * Deserialize the length of RSA ciphertext ('EncryptedPremasterSecret')
			 * into 'i'.
			 */
			n2s(p, i);
			n -= 2; // two bytes were taken
			param_len = 2 + i; // backup length of the signed content

			// check we have enough data in the input buffer
			if (n < i) {
				SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_LENGTH_TOO_SHORT);
				goto f_err;
			}

			/*
			 * There is no need to check the length of RSA ciphertext as it should
			 * be equal to the size of the modulus (see 'pkey'). The signature
			 * verification algorithm should complain if it receives an unexpected
			 * number of input bytes.
			 * Potentially, the lack of check may allow DoS attacks. However, there's
			 * very little risk of such attacks against clients and this is definitely
			 * not the only spot to secure in OpenSSL.
			 */

			// save the received encrypted premaster secret
			s->proxy_pubkey_tmp = BUF_memdup(p, i);
			s->proxy_pubkey_tmp_len = i;

			// finalize
			p += i;
			n -= i;

		} else if (SSL_C_IS_EXPORT(s->s3->tmp.new_cipher)) {
			// prepare
			RSA* rsa = NULL;
			if ((rsa = RSA_new()) == NULL) {
				SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_MALLOC_FAILURE);
				goto err;
			}

			// check input
			param_len = 2;
			if (param_len > n) {
				SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_LENGTH_TOO_SHORT);
				goto f_err;
			}
			n2s(p, i);
			if (i > n - param_len) {
				SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_BAD_RSA_MODULUS_LENGTH);
				goto f_err;
			}
			param_len += i;
			if (!(rsa->n = BN_bin2bn(p, i, rsa->n))) {
				SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_BN_LIB);
				goto err;
			}
			p += i;
			if (2 > n - param_len) {
				SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_LENGTH_TOO_SHORT);
				goto f_err;
			}
			param_len += 2;
			n2s(p, i);
			if (i > n - param_len) {
				SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_BAD_RSA_E_LENGTH);
				goto f_err;
			}
			param_len += i;

			// deserialize
			if (!(rsa->e = BN_bin2bn(p, i, rsa->e))) {
				SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_BN_LIB);
				goto err;
			}
			p += i;
			n -= param_len;

			// register the correct public key
			if (alg_a & SSL_aRSA) {
				pkey = X509_get_pubkey(
						(*sc)->peer_pkeys[SSL_PKEY_RSA_ENC].x509);
			}
			else {
				// there is no RSA_DSA or RSA_ECDSA ciphersuite in the registry
				SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_INTERNAL_ERROR);
				goto err;
			}

			// check that the public key's strength is truly export-grade
			if (EVP_PKEY_bits(pkey) <= SSL_C_EXPORT_PKEYLENGTH(s->s3->tmp.new_cipher)) {
				al = SSL_AD_UNEXPECTED_MESSAGE;
				SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_UNEXPECTED_MESSAGE);
				goto f_err;
			}

			// save the received public key
			SSL_set_peer_RSA_tmp_pubkey(s, rsa);

        } else {
        	/*
        	 * Non-empty ServerKeyExchange for non-export cipher suite
        	 * with RSA key exchange and without inspection...
        	 */
			al = SSL_AD_UNEXPECTED_MESSAGE;
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_UNEXPECTED_MESSAGE);
			goto f_err;
		}
    }
#else                           /* OPENSSL_NO_RSA */
    if (0) ;
#endif
#ifndef OPENSSL_NO_DH
    else if (alg_k & SSL_kDHE) {
    	// prepare
    	if ((dh = DH_new()) == NULL) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_DH_LIB);
            goto err;
        }

    	// parse
        param_len = 2;
        if (param_len > n) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_LENGTH_TOO_SHORT);
            goto f_err;
        }
        n2s(p, i);
        if (i > n - param_len) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_BAD_DH_P_LENGTH);
            goto f_err;
        }
        param_len += i;

        // deserialize & check prime
        if (!(dh->p = BN_bin2bn(p, i, NULL))) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_BN_LIB);
            goto err;
        }
        p += i;
        if (BN_is_zero(dh->p)) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_BAD_DH_P_VALUE);
            goto f_err;
        }

        // parse
        if (2 > n - param_len) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_LENGTH_TOO_SHORT);
            goto f_err;
        }
        param_len += 2;
        n2s(p, i);
        if (i > n - param_len) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_BAD_DH_G_LENGTH);
            goto f_err;
        }
        param_len += i;

        // deserialize & check the base number
        if (!(dh->g = BN_bin2bn(p, i, NULL))) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_BN_LIB);
            goto err;
        }
        p += i;
        if (BN_is_zero(dh->g)) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_BAD_DH_G_VALUE);
            goto f_err;
        }

        // parse
        if (2 > n - param_len) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_LENGTH_TOO_SHORT);
            goto f_err;
        }
        param_len += 2;
        n2s(p, i);
        if (i > n - param_len) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_BAD_DH_PUB_KEY_LENGTH);
            goto f_err;
        }
        param_len += i;

        // deserialize & check the public key
        if (!(dh->pub_key = BN_bin2bn(p, i, NULL))) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_BN_LIB);
            goto err;
        }

        // save the received raw public key if the session is inspected
        if (s->session->is_inspected) {
        	s->proxy_pubkey_tmp = BUF_memdup(p, i);
        	s->proxy_pubkey_tmp_len = i;
        }

        // continue
        p += i;
        n -= param_len;
        if (BN_is_zero(dh->pub_key)) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_BAD_DH_PUB_KEY_VALUE);
            goto f_err;
        }

        // determine public key for authentication
# ifndef OPENSSL_NO_RSA
        if (alg_a & SSL_aRSA)
        	pkey = X509_get_pubkey(
					(*sc)->peer_pkeys[SSL_PKEY_RSA_ENC].x509);
# else
        if (0) ;
# endif
# ifndef OPENSSL_NO_DSA
        else if (alg_a & SSL_aDSS)
        	pkey = X509_get_pubkey(
					(*sc)->peer_pkeys[SSL_PKEY_DSA_SIGN].x509);
# endif
        /* else anonymous DH, so no certificate or pkey. */

        // save the deserialized public key
        SSL_set_peer_DHE_tmp_pubkey(s, dh);
        dh = NULL;
    } else if ((alg_k & SSL_kDHr) || (alg_k & SSL_kDHd)) {
        al = SSL_AD_ILLEGAL_PARAMETER;
        SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
               SSL_R_TRIED_TO_USE_UNSUPPORTED_CIPHER);
        goto f_err;
    }
#endif                          /* !OPENSSL_NO_DH */

#ifndef OPENSSL_NO_ECDH
    else if (alg_k & SSL_kECDHE) {
        //prepare
        if ((ecdh = EC_KEY_new()) == NULL) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        /*
         * Extract elliptic curve parameters and the server's ephemeral ECDH
         * public key. Keep accumulating lengths of various components in
         * param_len and make sure it never exceeds n.
         */

        /*
         * XXX: For now we only support named (not generic) curves and the
         * ECParameters in this case is just three bytes. We also need one
         * byte for the length of the encoded point.
         */
        // parse
        param_len = 4;
        if (param_len > n) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_LENGTH_TOO_SHORT);
            goto f_err;
        }

        /*
         * Check curve is one of our preferences, if not server has sent an
         * invalid curve. ECParameters is 3 bytes.
         */
        if (!tls1_check_curve(s, p, 3)) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_WRONG_CURVE);
            goto f_err;
        }
        if ((curve_nid = tls1_ec_curve_id2nid(*(p + 2))) == 0) {
            al = SSL_AD_INTERNAL_ERROR;
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
                   SSL_R_UNABLE_TO_FIND_ECDH_PARAMETERS);
            goto f_err;
        }

        EC_GROUP *ngroup = EC_GROUP_new_by_curve_name(curve_nid);
        if (ngroup == NULL) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_EC_LIB);
            goto err;
        }
        if (EC_KEY_set_group(ecdh, ngroup) == 0) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_EC_LIB);
            goto err;
        }
        EC_GROUP_free(ngroup);
        const EC_GROUP *group = EC_KEY_get0_group(ecdh);

        // additional check
        if (SSL_C_IS_EXPORT(s->s3->tmp.new_cipher) &&
            (EC_GROUP_get_degree(group) > 163)) {
            al = SSL_AD_EXPORT_RESTRICTION;
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
                   SSL_R_ECGROUP_TOO_LARGE_FOR_CIPHER);
            goto f_err;
        }

        // get the encoded ECPoint
        p += 3;
        if (((srvr_ecpoint = EC_POINT_new(group)) == NULL) ||
            ((bn_ctx = BN_CTX_new()) == NULL)) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        encoded_pt_len = *p;    // length of encoded point
        p += 1;

        // check i
        if ((encoded_pt_len > n - param_len) ||
            (EC_POINT_oct2point(group, srvr_ecpoint,
                                p, encoded_pt_len, bn_ctx) == 0)) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_BAD_ECPOINT);
            goto f_err;
        }

        // save the proxy's raw public key if the session is inspected
		if (SSL_is_client(s) && s->session->is_inspected) {
			s->proxy_pubkey_tmp = BUF_memdup(p, encoded_pt_len);
			s->proxy_pubkey_tmp_len = encoded_pt_len;
		}

		// continue
        param_len += encoded_pt_len;
        n -= param_len;
        p += encoded_pt_len;

        /*
         * The ECC/TLS specification does not mention the use of DSA to sign
         * ECParameters in the server key exchange message. We do support RSA
         * and ECDSA.
         */
        if (0) ;
# ifndef OPENSSL_NO_RSA
        else if (alg_a & SSL_aRSA)
        	pkey = X509_get_pubkey(
					(*sc)->peer_pkeys[SSL_PKEY_RSA_ENC].x509);
# endif
# ifndef OPENSSL_NO_ECDSA
        else if (alg_a & SSL_aECDSA)
        	pkey = X509_get_pubkey(
					(*sc)->peer_pkeys[SSL_PKEY_ECC].x509);
# endif
        /* else anonymous ECDH, so no certificate or pkey. */

        // save the deserialized public key
        EC_KEY_set_public_key(ecdh, srvr_ecpoint);
        SSL_set_peer_ECDHE_tmp_pubkey(s, ecdh);
        ecdh = NULL;

        // cleanup
        BN_CTX_free(bn_ctx);
        bn_ctx = NULL;
        EC_POINT_free(srvr_ecpoint);
        srvr_ecpoint = NULL;
    } else if (alg_k) {
        al = SSL_AD_UNEXPECTED_MESSAGE;
        SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_UNEXPECTED_MESSAGE);
        goto f_err;
    }
#endif                          /* !OPENSSL_NO_ECDH */

    // if the received key was signed, prepare to verify the signature
    if (pkey != NULL) {
        // determine the digest and algorithm to verify the signature with
    	if (SSL_USE_SIGALGS(s)) {
            int rv;
            if (2 > n) {
                SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_LENGTH_TOO_SHORT);
                goto f_err;
            }
            rv = tls12_check_peer_sigalg(&md, s, *sc, p, pkey);
            if (rv == -1) {
                goto err;
            }
            else if (rv == 0) {
                goto f_err;
            }
#ifdef SSL_DEBUG
            fprintf(stderr, "USING TLSv1.2 HASH %s\n", EVP_MD_name(md));
#endif
            p += 2;
            n -= 2;
        } else {
            md = EVP_sha1();
        }

    	// parse signature length
        if (2 > n) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_LENGTH_TOO_SHORT);
            goto f_err;
        }
        n2s(p, i);
        n -= 2; // that's it
        j = EVP_PKEY_size(pkey);

        /*
         * At this moment, p points to the signature and it should be 'n' bytes long.
         */

        // check signature length (if n is 0 then signature is empty)
        if ((i != n) || (n > j) || (n <= 0)) {
            /* wrong packet length */
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_WRONG_SIGNATURE_LENGTH);
            goto f_err;
        }
#ifndef OPENSSL_NO_RSA

        // verify the signature
        if ((pkey->type == EVP_PKEY_RSA) && !SSL_USE_SIGALGS(s)) {
            int num;
            unsigned int size;

            j = 0;
            q = md_buf;
            for (num = 2; num > 0; num--) {
                EVP_MD_CTX_set_flags(&md_ctx, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
                if (EVP_DigestInit_ex(&md_ctx,
                                      (num == 2) ? s->ctx->md5 : s->ctx->sha1,
                                      NULL) <= 0
                        || EVP_DigestUpdate(&md_ctx, &(s->s3->client_random[0]),
                                            SSL3_RANDOM_SIZE) <= 0
                        || EVP_DigestUpdate(&md_ctx, &(s->s3->server_random[0]),
                                            SSL3_RANDOM_SIZE) <= 0
						// append the whole message to the hashed content
                        || EVP_DigestUpdate(&md_ctx, d, param_len) <= 0
						// output hash into 'q'
                        || EVP_DigestFinal_ex(&md_ctx, q, &size) <= 0) {
                    SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
                           ERR_R_INTERNAL_ERROR);
                    al = SSL_AD_INTERNAL_ERROR;
                    goto f_err;
                }
                q += size;
                j += size;
            }
            // 'p' points to the signature
            // 'md_buf' points to the start of the hash
            // compare/verify them:
            i = RSA_verify(NID_md5_sha1, md_buf, j, p, n, pkey->pkey.rsa);
            if (i < 0) {
                al = SSL_AD_DECRYPT_ERROR;
                SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_BAD_RSA_DECRYPT);
                goto f_err;
            }
            if (i == 0) {
                /* bad signature */
                al = SSL_AD_DECRYPT_ERROR;
                SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_BAD_SIGNATURE);
                goto f_err;
            }
        } else
#endif
// BUG: missing #ifndef OPENSSL_NO_DSA or OPENSSL_NO_ECDSA? How come? :)

        // inspection doesn't change anything about this
        {
            if (EVP_VerifyInit_ex(&md_ctx, md, NULL) <= 0
                    || EVP_VerifyUpdate(&md_ctx, &(s->s3->client_random[0]),
                                        SSL3_RANDOM_SIZE) <= 0
                    || EVP_VerifyUpdate(&md_ctx, &(s->s3->server_random[0]),
                                        SSL3_RANDOM_SIZE) <= 0
					// append the whole message to the hashed content
                    || EVP_VerifyUpdate(&md_ctx, d, param_len) <= 0) {
                al = SSL_AD_INTERNAL_ERROR;
                SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_EVP_LIB);
                goto f_err;
            }
            // hash is included inside
            // 'p' points to the signature
            // compare/verify them:
            if (EVP_VerifyFinal(&md_ctx, p, (int)n, pkey) <= 0) {
                /* bad signature */
                al = SSL_AD_DECRYPT_ERROR;
                SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_BAD_SIGNATURE);
                goto f_err;
            }
        }
    } else {
        /* aNULL, aSRP or kPSK do not need public keys */
        if (!(alg_a & (SSL_aNULL | SSL_aSRP)) && !(alg_k & SSL_kPSK)) {
            /* Might be wrong key type, check it */
        	if (ssl3_check_cert_and_algorithm(s, *sc))
                /* Otherwise this shouldn't happen */
                SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        /* still data left over */
        if (n != 0) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_EXTRA_DATA_IN_MESSAGE);
            goto f_err;
        }
    }

 done:
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_cleanup(&md_ctx);
    return (1);
 f_err:
    ssl3_send_alert(s, SSL3_AL_FATAL, al);
 err:
    EVP_PKEY_free(pkey);
#ifndef OPENSSL_NO_DH
    if (dh != NULL)
        DH_free(dh);
#endif
#ifndef OPENSSL_NO_ECDH
    BN_CTX_free(bn_ctx);
    EC_POINT_free(srvr_ecpoint);
    if (ecdh != NULL)
        EC_KEY_free(ecdh);
#endif
    EVP_MD_CTX_cleanup(&md_ctx);
    s->state = SSL_ST_ERR;
    return (-1);
}

int ssl3_get_certificate_request(SSL *s)
{
    int ok, ret = 0;
    unsigned long n, nc, l;
    unsigned int llen, ctype_num, i;
    X509_NAME *xn = NULL;
    const unsigned char *p, *q;
    unsigned char *d;
    STACK_OF(X509_NAME) *ca_sk = NULL;

    n = s->method->ssl_get_message(s,
                                   SSL3_ST_CR_CERT_REQ_A,
                                   SSL3_ST_CR_CERT_REQ_B,
                                   -1, s->max_cert_list, &ok);

    // basic checks
    if (!ok) {
        return ((int)n);
    } else {
    	s->s3->tmp.cert_req = 0;
    }

    if (s->s3->tmp.message_type == SSL3_MT_SERVER_DONE) {
        s->s3->tmp.reuse_message = 1;
        /*
         * If we get here we don't need any cached handshake records as we
         * wont be doing client auth.
         */
        if (s->s3->handshake_buffer) {
            if (!ssl3_digest_cached_records(s))
                goto err;
        }
        return (2);
    } else if (s->s3->tmp.message_type != SSL3_MT_CERTIFICATE_REQUEST) {
        ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_UNEXPECTED_MESSAGE);
        SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST, SSL_R_WRONG_MESSAGE_TYPE);
        goto err;
    } else {
    	p = d = (unsigned char *)s->init_msg;
    }

    // if proxy, queue the message
    if (SSL_is_proxy(s) && (tls12_prx_msg_rcvd_early_cb(s, p, n,
			s->s3->tmp.message_type) == 2)) {
		goto done;
	}

    /* TLS does not like anon-DH with client cert */
    if (s->version > SSL3_VERSION) {
        if (s->s3->tmp.new_cipher->algorithm_auth & SSL_aNULL) {
            ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_UNEXPECTED_MESSAGE);
            SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST,
                   SSL_R_TLS_CLIENT_CERT_REQ_WITH_ANON_CIPHER);
            goto err;
        }
    }

    if ((ca_sk = sk_X509_NAME_new(ca_dn_cmp)) == NULL) {
        SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /* get the certificate types */
    ctype_num = *(p++);
    if (s->cert->ctypes) {
        OPENSSL_free(s->cert->ctypes);
        s->cert->ctypes = NULL;
    }
    if (ctype_num > SSL3_CT_NUMBER) {
        /* If we exceed static buffer copy all to cert structure */
        s->cert->ctypes = OPENSSL_malloc(ctype_num);
        memcpy(s->cert->ctypes, p, ctype_num);
        s->cert->ctype_num = (size_t)ctype_num;
        ctype_num = SSL3_CT_NUMBER;
    }
    for (i = 0; i < ctype_num; i++)
        s->s3->tmp.ctype[i] = p[i];
    p += p[-1];
    if (SSL_USE_SIGALGS(s)) {
        n2s(p, llen);
        /*
         * Check we have enough room for signature algorithms and following
         * length value.
         */
        if ((unsigned long)(p - d + llen + 2) > n) {
            ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
            SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST,
                   SSL_R_DATA_LENGTH_TOO_LONG);
            goto err;
        }
        /* Clear certificate digests and validity flags */
        for (i = 0; i < SSL_PKEY_NUM; i++) {
            s->cert->pkeys[i].digest = NULL;
            s->cert->pkeys[i].valid_flags = 0;
        }
        if ((llen & 1) || !tls1_save_sigalgs(s, p, llen)) {
            ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
            SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST,
                   SSL_R_SIGNATURE_ALGORITHMS_ERROR);
            goto err;
        }
        if (!tls1_process_sigalgs(s)) {
            ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
            SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        p += llen;
    }

    /* get the CA RDNs */
    n2s(p, llen);
#if 0
    {
        FILE *out;
        out = fopen("/tmp/vsign.der", "w");
        fwrite(p, 1, llen, out);
        fclose(out);
    }
#endif

    if ((unsigned long)(p - d + llen) != n) {
        ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
        SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST, SSL_R_LENGTH_MISMATCH);
        goto err;
    }

    for (nc = 0; nc < llen;) {
        n2s(p, l);
        if ((l + nc + 2) > llen) {
            if ((s->options & SSL_OP_NETSCAPE_CA_DN_BUG))
                goto cont;      /* netscape bugs */
            ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
            SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST, SSL_R_CA_DN_TOO_LONG);
            goto err;
        }

        q = p;

        if ((xn = d2i_X509_NAME(NULL, &q, l)) == NULL) {
            /* If netscape tolerance is on, ignore errors */
            if (s->options & SSL_OP_NETSCAPE_CA_DN_BUG)
                goto cont;
            else {
                ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
                SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST, ERR_R_ASN1_LIB);
                goto err;
            }
        }

        if (q != (p + l)) {
            ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
            SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST,
                   SSL_R_CA_DN_LENGTH_MISMATCH);
            goto err;
        }
        if (!sk_X509_NAME_push(ca_sk, xn)) {
            SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        xn = NULL;

        p += l;
        nc += l + 2;
    }

    // register that we received a client authentication requirement
    s->s3->tmp.cert_req = 1;

    // a proxy "extension" of this method
	if (SSL_is_proxy(s) && !tls12_prx_crt_rqst_rcvd_cb(s)) {
		goto err;
	}

    if (0) {
 cont:
        ERR_clear_error();
    }

    /* we should setup a certificate to return.... */
    s->s3->tmp.ctype_num = ctype_num;
    if (s->s3->tmp.ca_names != NULL)
        sk_X509_NAME_pop_free(s->s3->tmp.ca_names, X509_NAME_free);
    s->s3->tmp.ca_names = ca_sk;
    ca_sk = NULL;

 done:
    ret = 1;
    goto end;
 err:
    ret = -1;
 	s->state = SSL_ST_ERR;
 end:
    X509_NAME_free(xn);
    if (ca_sk != NULL)
        sk_X509_NAME_pop_free(ca_sk, X509_NAME_free);
    return (ret);
}

static int ca_dn_cmp(const X509_NAME *const *a, const X509_NAME *const *b)
{
    return (X509_NAME_cmp(*a, *b));
}

#ifndef OPENSSL_NO_TLSEXT
int ssl3_get_new_session_ticket(SSL *s)
{
    int ok, al, ret = 0, ticklen;
    long n;
    const unsigned char *p;
    unsigned char *d;
    unsigned long ticket_lifetime_hint;

    n = s->method->ssl_get_message(s,
                                   SSL3_ST_CR_SESSION_TICKET_A,
                                   SSL3_ST_CR_SESSION_TICKET_B,
                                   SSL3_MT_NEWSESSION_TICKET, 16384, &ok);

    // basic checks
    if (!ok) {
        return ((int)n);
    } else if (n < 6) {
        /* need at least ticket_lifetime_hint + ticket length */
        al = SSL_AD_DECODE_ERROR;
        SSLerr(SSL_F_SSL3_GET_NEW_SESSION_TICKET, SSL_R_LENGTH_MISMATCH);
        goto f_err;
    } else {
    	p = d = (unsigned char *)s->init_msg;
    }

    // if proxy, queue the message
    if (SSL_is_proxy(s) && (tls12_prx_msg_rcvd_early_cb(s, p, n,
			s->s3->tmp.message_type) == 2)) {
		goto done;
	}

    n2l(p, ticket_lifetime_hint);
    n2s(p, ticklen);
    /* ticket_lifetime_hint + ticket_length + ticket */
    if (ticklen + 6 != n) {
        al = SSL_AD_DECODE_ERROR;
        SSLerr(SSL_F_SSL3_GET_NEW_SESSION_TICKET, SSL_R_LENGTH_MISMATCH);
        goto f_err;
    }

    /* Server is allowed to change its mind and send an empty ticket. */
    if (ticklen == 0)
        return 1;

    if (s->session->session_id_length > 0) {
        int i = s->session_ctx->session_cache_mode;
        SSL_SESSION *new_sess;
        /*
         * We reused an existing session, so we need to replace it with a new
         * one
         */
        if (i & SSL_SESS_CACHE_CLIENT) {
            /*
             * Remove the old session from the cache
             */
            if (i & SSL_SESS_CACHE_NO_INTERNAL_STORE) {
                if (s->session_ctx->remove_session_cb != NULL)
                    s->session_ctx->remove_session_cb(s->session_ctx,
                                                      s->session);
            } else {
                /* We carry on if this fails */
                SSL_CTX_remove_session(s->session_ctx, s->session, 1);
            }
        }

        if ((new_sess = ssl_session_dup(s->session, 0)) == 0) {
            al = SSL_AD_INTERNAL_ERROR;
            SSLerr(SSL_F_SSL3_GET_NEW_SESSION_TICKET, ERR_R_MALLOC_FAILURE);
            goto f_err;
        }

        SSL_SESSION_free(s->session);
        s->session = new_sess;
    }

    if (s->session->tlsext_tick) {
        OPENSSL_free(s->session->tlsext_tick);
        s->session->tlsext_ticklen = 0;
    }
    s->session->tlsext_tick = OPENSSL_malloc(ticklen);
    if (!s->session->tlsext_tick) {
        SSLerr(SSL_F_SSL3_GET_NEW_SESSION_TICKET, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    memcpy(s->session->tlsext_tick, p, ticklen);
    s->session->tlsext_tick_lifetime_hint = ticket_lifetime_hint;
    s->session->tlsext_ticklen = ticklen;
    /*
     * There are two ways to detect a resumed ticket session. One is to set
     * an appropriate session ID and then the server must return a match in
     * ServerHello. This allows the normal client session ID matching to work
     * and we know much earlier that the ticket has been accepted. The
     * other way is to set zero length session ID when the ticket is
     * presented and rely on the handshake to determine session resumption.
     * We choose the former approach because this fits in with assumptions
     * elsewhere in OpenSSL. The session ID is set to the SHA256 (or SHA1 if
     * SHA256 is disabled) hash of the ticket.
     */
    EVP_Digest(p, ticklen,
               s->session->session_id, &s->session->session_id_length,
# ifndef OPENSSL_NO_SHA256
               EVP_sha256(), NULL);
# else
               EVP_sha1(), NULL);
# endif

 done:
    ret = 1;
    return (ret);
 f_err:
    ssl3_send_alert(s, SSL3_AL_FATAL, al);
 err:
    s->state = SSL_ST_ERR;
    return (-1);
}

int ssl3_get_cert_status(SSL *s, int received_cert_msgs)
{
    int ok, al;
    unsigned long resplen, n;
    unsigned char *p, *d;
    int server_status = received_cert_msgs == 1;

    n = s->method->ssl_get_message(s,
                                   SSL3_ST_CR_CERT_STATUS_A,
                                   SSL3_ST_CR_CERT_STATUS_B,
                                   -1, 16384, &ok);

    // basic checks
    if (!ok) {
        return ((int)n);
    }

    if (s->s3->tmp.message_type != SSL3_MT_CERTIFICATE_STATUS) {
        /*
         * The CertificateStatus message is optional even if
         * tlsext_status_expected is set
         */
        s->s3->tmp.reuse_message = 1;
    } else if (n < 4) {
            /* need at least status type + length */
            al = SSL_AD_DECODE_ERROR;
            SSLerr(SSL_F_SSL3_GET_CERT_STATUS, SSL_R_LENGTH_MISMATCH);
            goto f_err;
    } else if (*p++ != TLSEXT_STATUSTYPE_ocsp) {
        al = SSL_AD_DECODE_ERROR;
        SSLerr(SSL_F_SSL3_GET_CERT_STATUS, SSL_R_UNSUPPORTED_STATUS_TYPE);
        goto f_err;
    } else {
    	d = p = (unsigned char *)s->init_msg;
    }

    // if proxy, queue the message
    if (SSL_is_proxy(s) && (tls12_prx_msg_rcvd_early_cb(s, p, n,
			s->s3->tmp.message_type) == 2)) {
		goto done;
	}

	n2l3(p, resplen);
	if (resplen + 4 != n) {
		al = SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_SSL3_GET_CERT_STATUS, SSL_R_LENGTH_MISMATCH);
		goto f_err;
	}
	unsigned char* ocsp_resp = BUF_memdup(p, resplen);
	if (ocsp_resp == NULL) {
		al = SSL_AD_INTERNAL_ERROR;
		SSLerr(SSL_F_SSL3_GET_CERT_STATUS, ERR_R_MALLOC_FAILURE);
		goto f_err;
	}

	// save the response
	if(server_status) {
		s->tlsext_ocsp_resp = ocsp_resp;
		s->tlsext_ocsp_resplen = resplen;
	}
	else {
		s->proxy_ocsp_resp = ocsp_resp;
		s->proxy_ocsp_resplen = resplen;
	}

    if (s->ctx->tlsext_status_cb) {
        int ret;
        ret = s->ctx->tlsext_status_cb(s, server_status, s->ctx->tlsext_status_arg);
        if (ret == 0) {
            al = SSL_AD_BAD_CERTIFICATE_STATUS_RESPONSE;
            SSLerr(SSL_F_SSL3_GET_CERT_STATUS, SSL_R_INVALID_STATUS_RESPONSE);
            goto f_err;
        }
        if (ret < 0) {
            al = SSL_AD_INTERNAL_ERROR;
            SSLerr(SSL_F_SSL3_GET_CERT_STATUS, ERR_R_MALLOC_FAILURE);
            goto f_err;
        }
    }

 done:
    return 1;
 f_err:
    ssl3_send_alert(s, SSL3_AL_FATAL, al);
    s->state = SSL_ST_ERR;
    return (-1);
}
#endif

int ssl3_get_server_done(SSL *s)
{
    int ok, ret = 0;
    long n;

    /* Second to last param should be very small, like 0 :-) */
    n = s->method->ssl_get_message(s,
                                   SSL3_ST_CR_SRVR_DONE_A,
                                   SSL3_ST_CR_SRVR_DONE_B,
                                   SSL3_MT_SERVER_DONE, 30, &ok);

    if (!ok) {
        return ((int)n);
    }

    if (n > 0) {
        /* should contain no data */
        ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
        SSLerr(SSL_F_SSL3_GET_SERVER_DONE, SSL_R_LENGTH_MISMATCH);
        s->state = SSL_ST_ERR;
        return -1;
    }

	ret = 1;
    return (ret);
}

#ifndef OPENSSL_NO_DH
static DH *get_server_static_dh_key(SESS_CERT *scert)
{
    DH *dh_srvr = NULL;
    EVP_PKEY *spkey = NULL;
    int idx = scert->peer_cert_type;

    if (idx >= 0)
        spkey = X509_get_pubkey(scert->peer_pkeys[idx].x509);
    if (spkey) {
        dh_srvr = EVP_PKEY_get1_DH(spkey);
        EVP_PKEY_free(spkey);
    }
    if (dh_srvr == NULL)
        SSLerr(SSL_F_GET_SERVER_STATIC_DH_KEY, ERR_R_INTERNAL_ERROR);
    return dh_srvr;
}
#endif

int ssl3_send_client_key_exchange(SSL *s, SESS_CERT* sc)
{
    unsigned char *p;
    int n;
    unsigned long alg_k;
#ifndef OPENSSL_NO_RSA
    unsigned char *q;
    EVP_PKEY *pkey = NULL;
#endif
#ifndef OPENSSL_NO_KRB5
    KSSL_ERR kssl_err;
#endif                          /* OPENSSL_NO_KRB5 */
#ifndef OPENSSL_NO_ECDH
    EC_KEY *clnt_ecdh = NULL;
    const EC_POINT *srvr_ecpoint = NULL;
    EVP_PKEY *srvr_pub_pkey = NULL;
    unsigned char *encodedPoint = NULL;
    int encoded_pt_len = 0;
    BN_CTX *bn_ctx = NULL;
#endif

    if (s->state == SSL3_ST_CW_KEY_EXCH_A) {
        p = ssl_handshake_start(s);

        alg_k = s->s3->tmp.new_cipher->algorithm_mkey;

        /* Fool emacs indentation */
        if (0) {
        }
#ifndef OPENSSL_NO_RSA
        else if (alg_k & SSL_kRSA) {
        	// prepare the message and random bytes
        	unsigned char tmp_buf[SSL_MAX_MASTER_KEY_LENGTH];
        	if (SSL_is_proxy(s) && s->s3->tmp.cert_req) {
        		// simply re-send the prepared key...
        		memcpy(p, s->proxy_pubkey_tmp, s->proxy_pubkey_tmp_len);
        		n = s->proxy_pubkey_tmp_len;
        		s->proxy_pubkey_tmp_len = 0;
        		s->proxy_pubkey_tmp = NULL; // freed in the other connection

        		// copy the hidden random bytes and cleanse source immediately
        		memcpy(&(tmp_buf[0]), &(s->session->master_key[0]), sizeof(tmp_buf));
        		OPENSSL_cleanse(s->session->master_key, sizeof(tmp_buf));
        	} else {
				// basic check
				if (sc == NULL) {
					/*
					 * RSA requiresWe should always have a peer certificate with SSL_kRSA.
					 */
					SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
						   ERR_R_INTERNAL_ERROR);
					goto err;
				}

				// basic setup & more checks
				RSA *rsa;
				if ((rsa = SSL_get_peer_RSA_tmp_pubkey(s)) == NULL) {
					pkey = X509_get_pubkey(sc->peer_pkeys[SSL_PKEY_RSA_ENC].x509);
					if ((pkey == NULL) || (pkey->type != EVP_PKEY_RSA)
						|| (pkey->pkey.rsa == NULL)) {
						SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
							   ERR_R_INTERNAL_ERROR);
						EVP_PKEY_free(pkey);
						goto err;
					}
					rsa = pkey->pkey.rsa;
					EVP_PKEY_free(pkey);
				}

				// begin write
				tmp_buf[0] = s->client_version >> 8;
				tmp_buf[1] = s->client_version & 0xff;
				if (RAND_bytes(&(tmp_buf[2]), sizeof tmp_buf - 2) <= 0) {
					goto err;
				}

				q = p;
				/* Fix buf for TLS and beyond */
				if (s->version > SSL3_VERSION)
					p += 2;
				n = RSA_public_encrypt(sizeof tmp_buf,
									   tmp_buf, p, rsa, RSA_PKCS1_PADDING);
# ifdef PKCS1_CHECK
				if (s->options & SSL_OP_PKCS1_CHECK_1)
					p[1]++;
				if (s->options & SSL_OP_PKCS1_CHECK_2)
					tmp_buf[0] = 0x70;
# endif
				if (n <= 0) {
					SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
						   SSL_R_BAD_RSA_ENCRYPT);
					goto err;
				}

				/* Fix buf for TLS and beyond */
				if (s->version > SSL3_VERSION) {
					s2n(n, q);
					n += 2;
				}
        	}

        	// generate master secret and cleanse
        	s->session->master_key_length = sizeof(tmp_buf);
        	s->session->master_key_length =
        			s->method->ssl3_enc->generate_master_secret(s,
        					s->session->master_key,
							tmp_buf,
							sizeof tmp_buf);
        	OPENSSL_cleanse(tmp_buf, sizeof tmp_buf);
        }
#endif
#ifndef OPENSSL_NO_KRB5
        else if (alg_k & SSL_kKRB5) {
            krb5_error_code krb5rc;
            KSSL_CTX *kssl_ctx = s->kssl_ctx;
            /*  krb5_data   krb5_ap_req;  */
            krb5_data *enc_ticket;
            krb5_data authenticator, *authp = NULL;
            EVP_CIPHER_CTX ciph_ctx;
            const EVP_CIPHER *enc = NULL;
            unsigned char iv[EVP_MAX_IV_LENGTH];
            unsigned char tmp_buf[SSL_MAX_MASTER_KEY_LENGTH];
            unsigned char epms[SSL_MAX_MASTER_KEY_LENGTH + EVP_MAX_IV_LENGTH];
            int padl, outl = sizeof(epms);

            EVP_CIPHER_CTX_init(&ciph_ctx);

# ifdef KSSL_DEBUG
            fprintf(stderr, "ssl3_send_client_key_exchange(%lx & %lx)\n",
                    alg_k, SSL_kKRB5);
# endif                         /* KSSL_DEBUG */

            authp = NULL;
# ifdef KRB5SENDAUTH
            if (KRB5SENDAUTH)
                authp = &authenticator;
# endif                         /* KRB5SENDAUTH */

            krb5rc = kssl_cget_tkt(kssl_ctx, &enc_ticket, authp, &kssl_err);
            enc = kssl_map_enc(kssl_ctx->enctype);
            if (enc == NULL)
                goto err;
# ifdef KSSL_DEBUG
            {
                fprintf(stderr, "kssl_cget_tkt rtn %d\n", krb5rc);
                if (krb5rc && kssl_err.text)
                    fprintf(stderr, "kssl_cget_tkt kssl_err=%s\n",
                            kssl_err.text);
            }
# endif                         /* KSSL_DEBUG */

            if (krb5rc) {
                ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_HANDSHAKE_FAILURE);
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, kssl_err.reason);
                goto err;
            }

            /*-
             * 20010406 VRS - Earlier versions used KRB5 AP_REQ
             * in place of RFC 2712 KerberosWrapper, as in:
             *
             * Send ticket (copy to *p, set n = length)
             * n = krb5_ap_req.length;
             * memcpy(p, krb5_ap_req.data, krb5_ap_req.length);
             * if (krb5_ap_req.data)
             *   kssl_krb5_free_data_contents(NULL,&krb5_ap_req);
             *
             * Now using real RFC 2712 KerberosWrapper
             * (Thanks to Simon Wilkinson <sxw@sxw.org.uk>)
             * Note: 2712 "opaque" types are here replaced
             * with a 2-byte length followed by the value.
             * Example:
             * KerberosWrapper= xx xx asn1ticket 0 0 xx xx encpms
             * Where "xx xx" = length bytes.  Shown here with
             * optional authenticator omitted.
             */

            /*  KerberosWrapper.Ticket              */
            s2n(enc_ticket->length, p);
            memcpy(p, enc_ticket->data, enc_ticket->length);
            p += enc_ticket->length;
            n = enc_ticket->length + 2;

            /*  KerberosWrapper.Authenticator       */
            if (authp && authp->length) {
                s2n(authp->length, p);
                memcpy(p, authp->data, authp->length);
                p += authp->length;
                n += authp->length + 2;

                free(authp->data);
                authp->data = NULL;
                authp->length = 0;
            } else {
                s2n(0, p);      /* null authenticator length */
                n += 2;
            }

            tmp_buf[0] = s->client_version >> 8;
            tmp_buf[1] = s->client_version & 0xff;
            if (RAND_bytes(&(tmp_buf[2]), sizeof tmp_buf - 2) <= 0)
                goto err;

            /*-
             * 20010420 VRS.  Tried it this way; failed.
             *      EVP_EncryptInit_ex(&ciph_ctx,enc, NULL,NULL);
             *      EVP_CIPHER_CTX_set_key_length(&ciph_ctx,
             *                              kssl_ctx->length);
             *      EVP_EncryptInit_ex(&ciph_ctx,NULL, key,iv);
             */

            memset(iv, 0, sizeof iv); /* per RFC 1510 */
            EVP_EncryptInit_ex(&ciph_ctx, enc, NULL, kssl_ctx->key, iv);
            EVP_EncryptUpdate(&ciph_ctx, epms, &outl, tmp_buf,
                              sizeof tmp_buf);
            EVP_EncryptFinal_ex(&ciph_ctx, &(epms[outl]), &padl);
            outl += padl;
            if (outl > (int)sizeof epms) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       ERR_R_INTERNAL_ERROR);
                goto err;
            }
            EVP_CIPHER_CTX_cleanup(&ciph_ctx);

            /*  KerberosWrapper.EncryptedPreMasterSecret    */
            s2n(outl, p);
            memcpy(p, epms, outl);
            p += outl;
            n += outl + 2;

            s->session->master_key_length =
                s->method->ssl3_enc->generate_master_secret(s,
                                                            s->
                                                            session->master_key,
                                                            tmp_buf,
                                                            sizeof tmp_buf);

            OPENSSL_cleanse(tmp_buf, sizeof tmp_buf);
            OPENSSL_cleanse(epms, outl);
        }
#endif
#ifndef OPENSSL_NO_DH
        else if (alg_k & (SSL_kEDH | SSL_kDHr | SSL_kDHd)) {
            // determine server key
        	DH *dh_srvr;
            if (sc == NULL) {
                ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_UNEXPECTED_MESSAGE);
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       SSL_R_UNEXPECTED_MESSAGE);
                goto err;
            } else if (sc->peer_dh_tmp != NULL) {
                dh_srvr = sc->peer_dh_tmp;
            } else {
                dh_srvr = get_server_static_dh_key(sc);
                if (dh_srvr == NULL) {
                    goto err;
                }
            }

            // determine client key
            DH *dh_clnt;
            if (SSL_is_proxy(s) && s->s3->tmp.cert_req) {
            	// actually freed elsewhere
            	// note: we assume that proxy has mirrored params among sessions
            	dh_clnt = s->s3->tmp.dh;
            	s->s3->tmp.dh = NULL;
            } else if (s->s3->flags & TLS1_FLAGS_SKIP_CERT_VERIFY) {
                EVP_PKEY *clkey = s->cert->key->privatekey;
                dh_clnt = NULL;
                if (clkey)
                    dh_clnt = EVP_PKEY_get1_DH(clkey);
                if (dh_clnt == NULL) {
                    SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                           ERR_R_INTERNAL_ERROR);
                    goto err;
                }
            } else {
            	// copy parameters
                if ((dh_clnt = DHparams_dup(dh_srvr)) == NULL) {
                    SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, ERR_R_DH_LIB);
                    goto err;
                }

                // generate a new key with the given parameters
                if (!DH_generate_key(dh_clnt)) {
                    SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, ERR_R_DH_LIB);
                    DH_free(dh_clnt);
                    goto err;
                }
            }

            /*
             * Generate master secret. Use the 'p' output buffer for the shared
             * secret but make sure to clear it out afterwards.
             */

            // compute the shared secret
            n = DH_compute_key(p, dh_srvr->pub_key, dh_clnt);
            if (n <= 0) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, ERR_R_DH_LIB);
                DH_free(dh_clnt);
                goto err;
            }

            // do generate master secret
            s->session->master_key_length =
                s->method->ssl3_enc->generate_master_secret(s,
                		s->session->master_key, p, n);

            // immediately erase the shared secret from memory & clean
            memset(p, 0, n);
            if (sc->peer_dh_tmp == NULL) {
            	DH_free(dh_srvr);
            }

            /*
             * Finally, send own public key.
             */

            if (s->s3->flags & TLS1_FLAGS_SKIP_CERT_VERIFY) {
                n = 0;
            } else {
                n = BN_num_bytes(dh_clnt->pub_key);
                s2n(n, p);
                BN_bn2bin(dh_clnt->pub_key, p);
                n += 2;
            }

            // if the condition is not met, we'll do this elsewhere
            if (!(SSL_is_proxy(s) && s->s3->tmp.cert_req)) {
            	DH_free(dh_clnt);
            }
        }
#endif

#ifndef OPENSSL_NO_ECDH
        else if (alg_k & (SSL_kEECDH | SSL_kECDHr | SSL_kECDHe)) {

            // determine server key
            EC_KEY *tkey;
            if (sc == NULL) {
                ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_UNEXPECTED_MESSAGE);
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       SSL_R_UNEXPECTED_MESSAGE);
                goto err;
            } else if (sc->peer_ecdh_tmp != NULL) {
                tkey = sc->peer_ecdh_tmp;
            } else {
                srvr_pub_pkey =
                    X509_get_pubkey(sc->peer_pkeys[SSL_PKEY_ECC].x509);
                if ((srvr_pub_pkey == NULL)
                    || (srvr_pub_pkey->type != EVP_PKEY_EC)
                    || (srvr_pub_pkey->pkey.ec == NULL)) {
                    SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                           ERR_R_INTERNAL_ERROR);
                    goto err;
                }
                tkey = srvr_pub_pkey->pkey.ec;
            }

            // determine and check parameters
            const EC_GROUP *srvr_group = EC_KEY_get0_group(tkey);
			srvr_ecpoint = EC_KEY_get0_public_key(tkey);
			if ((srvr_group == NULL) || (srvr_ecpoint == NULL)) {
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
					   ERR_R_INTERNAL_ERROR);
				goto err;
			}
			const int field_size = EC_GROUP_get_degree(srvr_group);
			if (field_size <= 0) {
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, ERR_R_ECDH_LIB);
				goto err;
			}

            // determine or generate client key
			if (SSL_is_proxy(s) && s->s3->tmp.cert_req) {
				// actually freed elsewhere
				// note: we assume that proxy has mirrored params among sessions
				clnt_ecdh = s->s3->tmp.ecdh;
				s->s3->tmp.ecdh = NULL;
			} else if ((clnt_ecdh = EC_KEY_new()) == NULL) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       ERR_R_MALLOC_FAILURE);
                goto err;
            } else if (!EC_KEY_set_group(clnt_ecdh, srvr_group)) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, ERR_R_EC_LIB);
                goto err;
            } else if (!(EC_KEY_generate_key(clnt_ecdh))) {
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
					   ERR_R_ECDH_LIB);
				goto err;
			}

			/*
			 * Generate master secret. Use the 'p' output buffer for the shared
			 * secret but make sure to clear it out afterwards.
			 */

			// compute the shared secret
            n = ECDH_compute_key(p, (field_size + 7) / 8, srvr_ecpoint,
                                 clnt_ecdh, NULL);
            if (n <= 0) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, ERR_R_ECDH_LIB);
                goto err;
            }

            // do generate master secret
            s->session->master_key_length =
                s->method->ssl3_enc->generate_master_secret(s,
                		s->session->master_key, p, n);

            // immediately erase the shared secret from memory & clean
            memset(p, 0, n);

            /*
			 * Finally, send own public key.
			 */

            // check encoding size and allocate accordingly
			encoded_pt_len =
				EC_POINT_point2oct(srvr_group,
								   EC_KEY_get0_public_key(clnt_ecdh),
								   POINT_CONVERSION_UNCOMPRESSED,
								   NULL, 0, NULL);
			encodedPoint = (unsigned char *)
				OPENSSL_malloc(encoded_pt_len * sizeof(unsigned char));
			bn_ctx = BN_CTX_new();
			if ((encodedPoint == NULL) || (bn_ctx == NULL)) {
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
					   ERR_R_MALLOC_FAILURE);
				goto err;
			}

			// encode the public key
			n = EC_POINT_point2oct(srvr_group,
								   EC_KEY_get0_public_key(clnt_ecdh),
								   POINT_CONVERSION_UNCOMPRESSED,
								   encodedPoint, encoded_pt_len, bn_ctx);

			// serialize its length
			*p = n;

			// serialize the key
			p += 1;
			n += 1;
			memcpy((unsigned char *)p, encodedPoint, n);

            // cleanup
            BN_CTX_free(bn_ctx);
            if (encodedPoint != NULL) {
                OPENSSL_free(encodedPoint);
            }
            EVP_PKEY_free(srvr_pub_pkey);

            // if the condition is not met, we'll do this elsewhere
            if (!(SSL_is_proxy(s) && s->s3->tmp.cert_req)) {
            	EC_KEY_free(clnt_ecdh);
            }
        }
#endif                          /* !OPENSSL_NO_ECDH */
        else if (alg_k & SSL_kGOST) {
            /* GOST key exchange message creation */
            EVP_PKEY_CTX *pkey_ctx;
            size_t msglen;
            unsigned int md_len;
            int keytype;
            unsigned char premaster_secret[32], shared_ukm[32], tmp[256];
            EVP_MD_CTX *ukm_hash;
            EVP_PKEY *pub_key;

            /*
             * Get server sertificate PKEY and create ctx from it
             */
            X509 *peer_cert = s->session->end_cert->
            		peer_pkeys[(keytype = SSL_PKEY_GOST01)].x509;
            if (!peer_cert)
                peer_cert =
                    s->session->
                    end_cert->peer_pkeys[(keytype = SSL_PKEY_GOST94)].x509;
            if (!peer_cert) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       SSL_R_NO_GOST_CERTIFICATE_SENT_BY_PEER);
                goto err;
            }

            pkey_ctx = EVP_PKEY_CTX_new(pub_key =
                                        X509_get_pubkey(peer_cert), NULL);
            if (pkey_ctx == NULL) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       ERR_R_MALLOC_FAILURE);
                goto err;
            }
            /*
             * If we have send a certificate, and certificate key
             *
             * * parameters match those of server certificate, use
             * certificate key for key exchange
             */

            /* Otherwise, generate ephemeral key pair */

            if (pkey_ctx == NULL
                    || EVP_PKEY_encrypt_init(pkey_ctx) <= 0
                    /* Generate session key */
                    || RAND_bytes(premaster_secret, 32) <= 0) {
                EVP_PKEY_CTX_free(pkey_ctx);
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       ERR_R_INTERNAL_ERROR);
                goto err;
            }
            /*
             * If we have client certificate, use its secret as peer key
             */
            if (s->s3->tmp.cert_req && s->cert->key->privatekey) {
                if (EVP_PKEY_derive_set_peer
                    (pkey_ctx, s->cert->key->privatekey) <= 0) {
                    /*
                     * If there was an error - just ignore it. Ephemeral key
                     * * would be used
                     */
                    ERR_clear_error();
                }
            }
            /*
             * Compute shared IV and store it in algorithm-specific context
             * data
             */
            ukm_hash = EVP_MD_CTX_create();
            if (EVP_DigestInit(ukm_hash,
                               EVP_get_digestbynid(NID_id_GostR3411_94)) <= 0
                    || EVP_DigestUpdate(ukm_hash, s->s3->client_random,
                                        SSL3_RANDOM_SIZE) <= 0
                    || EVP_DigestUpdate(ukm_hash, s->s3->server_random,
                                        SSL3_RANDOM_SIZE) <= 0
                    || EVP_DigestFinal_ex(ukm_hash, shared_ukm, &md_len) <= 0) {
                EVP_MD_CTX_destroy(ukm_hash);
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       ERR_R_INTERNAL_ERROR);
                goto err;
            }
            EVP_MD_CTX_destroy(ukm_hash);
            if (EVP_PKEY_CTX_ctrl
                (pkey_ctx, -1, EVP_PKEY_OP_ENCRYPT, EVP_PKEY_CTRL_SET_IV, 8,
                 shared_ukm) < 0) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       SSL_R_LIBRARY_BUG);
                goto err;
            }
            /* Make GOST keytransport blob message */
            /*
             * Encapsulate it into sequence
             */
            *(p++) = V_ASN1_SEQUENCE | V_ASN1_CONSTRUCTED;
            msglen = 255;
            if (EVP_PKEY_encrypt(pkey_ctx, tmp, &msglen, premaster_secret, 32)
                <= 0) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       SSL_R_LIBRARY_BUG);
                goto err;
            }
            if (msglen >= 0x80) {
                *(p++) = 0x81;
                *(p++) = msglen & 0xff;
                n = msglen + 3;
            } else {
                *(p++) = msglen & 0xff;
                n = msglen + 2;
            }
            memcpy(p, tmp, msglen);
            /* Check if pubkey from client certificate was used */
            if (EVP_PKEY_CTX_ctrl
                (pkey_ctx, -1, -1, EVP_PKEY_CTRL_PEER_KEY, 2, NULL) > 0) {
                /* Set flag "skip certificate verify" */
                s->s3->flags |= TLS1_FLAGS_SKIP_CERT_VERIFY;
            }
            EVP_PKEY_CTX_free(pkey_ctx);
            s->session->master_key_length =
                s->method->ssl3_enc->generate_master_secret(s,
                                                            s->
                                                            session->master_key,
                                                            premaster_secret,
                                                            32);
            EVP_PKEY_free(pub_key);

        }
#ifndef OPENSSL_NO_SRP
        else if (alg_k & SSL_kSRP) {
            if (s->srp_ctx.A != NULL) {
                /* send off the data */
                n = BN_num_bytes(s->srp_ctx.A);
                s2n(n, p);
                BN_bn2bin(s->srp_ctx.A, p);
                n += 2;
            } else {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       ERR_R_INTERNAL_ERROR);
                goto err;
            }
            if (s->session->srp_username != NULL)
                OPENSSL_free(s->session->srp_username);
            s->session->srp_username = BUF_strdup(s->srp_ctx.login);
            if (s->session->srp_username == NULL) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       ERR_R_MALLOC_FAILURE);
                goto err;
            }

            if ((s->session->master_key_length =
                 SRP_generate_client_master_secret(s,
                                                   s->session->master_key)) <
                0) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       ERR_R_INTERNAL_ERROR);
                goto err;
            }
        }
#endif
#ifndef OPENSSL_NO_PSK
        else if (alg_k & SSL_kPSK) {
            /*
             * The callback needs PSK_MAX_IDENTITY_LEN + 1 bytes to return a
             * \0-terminated identity. The last byte is for us for simulating
             * strnlen.
             */
            char identity[PSK_MAX_IDENTITY_LEN + 2];
            size_t identity_len;
            unsigned char *t = NULL;
            unsigned char psk_or_pre_ms[PSK_MAX_PSK_LEN * 2 + 4];
            unsigned int pre_ms_len = 0, psk_len = 0;
            int psk_err = 1;

            n = 0;
            if (s->psk_client_callback == NULL) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       SSL_R_PSK_NO_CLIENT_CB);
                goto err;
            }

            memset(identity, 0, sizeof(identity));
            psk_len = s->psk_client_callback(s, s->session->psk_identity_hint,
                                             identity, sizeof(identity) - 1,
                                             psk_or_pre_ms,
                                             sizeof(psk_or_pre_ms));
            if (psk_len > PSK_MAX_PSK_LEN) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       ERR_R_INTERNAL_ERROR);
                goto psk_err;
            } else if (psk_len == 0) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       SSL_R_PSK_IDENTITY_NOT_FOUND);
                goto psk_err;
            }
            identity[PSK_MAX_IDENTITY_LEN + 1] = '\0';
            identity_len = strlen(identity);
            if (identity_len > PSK_MAX_IDENTITY_LEN) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       ERR_R_INTERNAL_ERROR);
                goto psk_err;
            }
            /* create PSK pre_master_secret */
            pre_ms_len = 2 + psk_len + 2 + psk_len;
            t = psk_or_pre_ms;
            memmove(psk_or_pre_ms + psk_len + 4, psk_or_pre_ms, psk_len);
            s2n(psk_len, t);
            memset(t, 0, psk_len);
            t += psk_len;
            s2n(psk_len, t);

            if (s->session->psk_identity_hint != NULL)
                OPENSSL_free(s->session->psk_identity_hint);
            s->session->psk_identity_hint =
                BUF_strdup(s->ctx->psk_identity_hint);
            if (s->ctx->psk_identity_hint != NULL
                && s->session->psk_identity_hint == NULL) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       ERR_R_MALLOC_FAILURE);
                goto psk_err;
            }

            if (s->session->psk_identity != NULL)
                OPENSSL_free(s->session->psk_identity);
            s->session->psk_identity = BUF_strdup(identity);
            if (s->session->psk_identity == NULL) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                       ERR_R_MALLOC_FAILURE);
                goto psk_err;
            }

            s->session->master_key_length =
                s->method->ssl3_enc->generate_master_secret(s,
                                                            s->
                                                            session->master_key,
                                                            psk_or_pre_ms,
                                                            pre_ms_len);
            s2n(identity_len, p);
            memcpy(p, identity, identity_len);
            n = 2 + identity_len;
            psk_err = 0;
 psk_err:
            OPENSSL_cleanse(identity, sizeof(identity));
            OPENSSL_cleanse(psk_or_pre_ms, sizeof(psk_or_pre_ms));
            if (psk_err != 0) {
                ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_HANDSHAKE_FAILURE);
                goto err;
            }
        }
#endif
        else {
            ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_HANDSHAKE_FAILURE);
            SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, ERR_R_INTERNAL_ERROR);
            goto err;
        }

        ssl_set_handshake_header(s, SSL3_MT_CLIENT_KEY_EXCHANGE, n);
        s->state = SSL3_ST_CW_KEY_EXCH_B;
    }

    /* SSL3_ST_CW_KEY_EXCH_B */
    return ssl_do_write(s);
 err:
#ifndef OPENSSL_NO_ECDH
    BN_CTX_free(bn_ctx);
    if (encodedPoint != NULL)
        OPENSSL_free(encodedPoint);
    if (clnt_ecdh != NULL)
        EC_KEY_free(clnt_ecdh);
    EVP_PKEY_free(srvr_pub_pkey);
#endif
    s->state = SSL_ST_ERR;
    return (-1);
}

int ssl3_send_client_verify(SSL *s)
{
    unsigned char *p;
    unsigned char data[MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH];
    EVP_PKEY *pkey;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_MD_CTX mctx;
    unsigned u = 0;
    unsigned long n;
    int j;

    EVP_MD_CTX_init(&mctx);

    /*
     * Copied from RFC 5246 (TLS 1.2):
     * Note that hashing the handshake messages requires both sides
     * to either buffer the messages or compute running hashes for
     * all potential hash algorithms up to this point.
     * Servers can minimize this computation cost by offering a
     * restricted set of digest algorithms in the CertificateRequest
     * message.
     */

    // compute the signed artifact if the session is inspected (TPE extension)
	long hdatalen = 0;
	void* hdata = NULL;
	if(s->session->is_inspected) {
		hdata = (void*) TLS12_TPE_get_signed_artifact(s, &hdatalen);
		if(hdata == NULL) {
			SSLerr(SSL_F_SSL3_SEND_CLIENT_VERIFY, ERR_R_INTERNAL_ERROR);
			goto err;
		}
	}

	// proceed to the signature
    if (s->state == SSL3_ST_CW_CERT_VRFY_A) {
    	p = ssl_handshake_start(s);
        pkey = s->cert->key->privatekey;

        /*
         * Test if SHA1 is allowed as digest. Probably has to do with
         * the globally setup Security Level.
         */
        pctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (pctx == NULL || EVP_PKEY_sign_init(pctx) <= 0) {
            SSLerr(SSL_F_SSL3_SEND_CLIENT_VERIFY, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (EVP_PKEY_CTX_set_signature_md(pctx, EVP_sha1()) <= 0) {
        	ERR_clear_error();
        } else if (!SSL_USE_SIGALGS(s) && !s->session->is_inspected) {
        	// this probably computes SHA1 hash of the handshake...
        	s->method->ssl3_enc->cert_verify_mac(s, NID_sha1,
        			&(data[MD5_DIGEST_LENGTH]));
        }

        /*
         * Now onto the signature itself.
         */
        if (SSL_USE_SIGALGS(s)) {
        	/*
			 * Copied from RFC 5246 (TLS 1.2):
			 * The hash and signature algorithms used in the signature MUST
			 * be one of those present in the supported_signature_algorithms
			 * field of the CertificateRequest message. In addition, they MUST
			 * be compatible with the key in the client's end-entity certificate.
			 */

        	// get the content to sign and its length (local handling only)
        	// Note: special buffer because now we potentially use a different hash
        	const EVP_MD* digest_alg = s->cert->key->digest;
			if(!s->session->is_inspected) {
				hdatalen = BIO_get_mem_data(s->s3->handshake_buffer, &hdata);
				if(hdatalen <= 0) {
					SSLerr(SSL_F_SSL3_SEND_CLIENT_VERIFY, ERR_R_INTERNAL_ERROR);
					goto err;
				}
				if (!ssl3_digest_cached_records(s)) {
					goto err;
				}
			}

        	// the first two bytes will be NIDs of hash and signature algorithm
            if (!tls12_get_sigandhash(p, pkey, digest_alg)) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_VERIFY, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            p += 2;

            // some debug
#ifdef SSL_DEBUG
            fprintf(stderr, "Using TLS 1.2 with client alg %s\n",
                    EVP_MD_name(md));
#endif

            // do sign
            if (!EVP_SignInit_ex(&mctx, digest_alg, NULL)
                || !EVP_SignUpdate(&mctx, hdata, hdatalen)
                || !EVP_SignFinal(&mctx, p + 2, &u, pkey)) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_VERIFY, ERR_R_EVP_LIB);
                goto err;
            }

            // finalize
            s2n(u, p);
            n = u + 4;

        } else
#ifndef OPENSSL_NO_RSA
        if (pkey->type == EVP_PKEY_RSA) {

        	/*
			 * Copied from RFC 5246 (TLS 1.2):
			 * RSA keys MAY be used with any permitted hash algorithm, subject
			 * to restrictions in the certificate, if any.
			 *
			 * Additional information:
			 * Input for the RSA algorithm must not exceed the block size, i.e.
			 * the public key size. If it does, an alternative is to break the
			 * input into blocks, sign and send each of them. That's too much
			 * hassle by the sound of it already. Simply put: hash once, sign
			 * once, send once.
			 */

            // do sign
            int ret;
            if(!s->session->is_inspected) {
            	// this should really not be valid nowadays...
            	s->method->ssl3_enc->cert_verify_mac(s, NID_md5, &(data[0]));

            	/*
            	 * 36-byte input needs at least 512-bit RSA key (not
            	 * even Security Level 1).
            	 */
            	ret = RSA_sign(NID_md5_sha1, data,
                        MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH,
                        &(p[2]), &u, pkey->pkey.rsa);
            } else {
            	/*
            	 * Looking at the 'if' branch, it's safe to use functions up to
            	 * SHA256 (32 bytes). Not SHA384 (48 bytes) or stronger, however,
            	 * unless the client certificate's key is at least 1024-bit (128
            	 * bytes) strong. Weaker keys may only include 512-bit strength
            	 * nowadays and these are considered utterly unsafe.
            	 * Even then, clients may remove Security Level (0) so it's not
            	 * a safe bet to expect anything. Best select the hash function
            	 * dynamically according to the key's strength. We will try to be
            	 * consistent with the above 'TLS12_TPE_get_signed_artifact' call
            	 * and not attempt to use stronger function than the call used.
            	 *
            	 * Note:
            	 * Today, 2048-bit keys are recommended but we can still very well
            	 * encounter an older 1024-bit key, which is plenty for our
            	 * operations. If we subtract the algorithm padding, we're left with
            	 * 117 bytes that are sufficient even for SHA512. Hence, forward
            	 * compatibility is ensured.
            	 *
            	 * See also:
        		 * - https://www.openssl.org/docs/manmaster/ssl/SSL_set_security_level.html
            	 */

            	// determine the best function we can use
            	const int key_size = RSA_size(pkey->pkey.rsa);
            	long best_fit = SSL_get_hash_code_from_cipher(SSL_get_current_cipher(s));
            	unsigned int digest_size;
            	do {
            		digest_size = SSL_get_byte_strength_from_hash_code(best_fit);
            		if(digest_size > key_size) {
            			// must use a weaker function
            			best_fit = SSL_get_weaker_from_hash_code(best_fit);
            		} else {
            			// we found the best function we can use
            			break;
            		}
            	} while (best_fit > 0);

            	// this should never happen but just in case...
            	if(best_fit < SSL_SHA1) { // hash is MD5 or none
            		/*
            		 * Something's really amiss... we refuse for our signature to
            		 * be so incredibly easily 'hackable'.
            		 */
            		SSLerr(SSL_F_SSL3_SEND_CLIENT_VERIFY, ERR_R_RSA_LIB);
            		goto err;
            	}

            	// compute the artifact's hash
            	const EVP_MD* digest_alg = SSL_get_hash_from_code(best_fit);
				unsigned char digest[digest_size];
				if(!EVP_Digest(hdata, hdatalen, &(digest[0]), &digest_size, digest_alg, NULL)) {
					// could not compute the hash for some reason...
					SSLerr(SSL_F_SSL3_SEND_CLIENT_VERIFY, ERR_R_CRYPTO_LIB);
					goto err;
				}

            	// feed it to RSA_sign, along with the right NID
				long hmac_nid = SSL_get_hmac_NID_from_hash_code(best_fit);
            	ret = RSA_sign(hmac_nid, &(digest[0]), digest_size, &(p[2]), &u, pkey->pkey.rsa);
            }

            // check the result
            if (ret <= 0) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_VERIFY, ERR_R_RSA_LIB);
                goto err;
            }

            // finalize
            s2n(u, p);
            n = u + 2;
        } else
#endif
#ifndef OPENSSL_NO_DSA
        if (pkey->type == EVP_PKEY_DSA) {

        	/*
			 * Copied from RFC 5246 (TLS 1.2):
			 * Because DSA signatures do not contain any secure indication of
			 * hash algorithm, there is a risk of hash substitution if multiple
			 * hashes may be used with any key. Currently, DSA [DSS] may only be
			 * used with SHA-1. Future revisions of DSS [DSS-3] are expected to
			 * allow the use of other digest algorithms with DSA, as well as
			 * guidance as to which digest algorithms should be used with each
			 * key size. In addition, future revisions of [PKIX] may specify
			 * mechanisms for certificates to indicate which digest algorithms
			 * are to be used with DSA.
			 *
        	 * Additional information:
        	 * Unlike RSA, DSA truncates the input if it's too large. It takes
        	 * the maximum allowed number of leftmost bytes - theoretically, this
        	 * allows for chosen prefix attacks. Although one such attack is known
        	 * for SHA1, its digests will not get truncated (explanation coming right
        	 * up).
        	 *
        	 * SHA1 ensures that no truncation takes place, as long as Security
        	 * Level 1 is set. Explanation:
			 * - FIPS 186-3 specifies L and N length pairs of (1,024, 160),
			 * (2,048, 224), (2,048, 256), and (3,072, 256).
			 * - N must be more than or equal to the input length, otherwise the
			 * input is truncated.
			 * This means that:
			 * - N is 160 bits (20 bytes) for Security Level 1
			 * 		- SHA1 digest is 20 bytes long
			 * - Lowest N is 224 bits (28 bytes) for Security Level 2
			 * 		- We can't even use SHA256 (32 bytes) safely
			 * - Highest N is 256 bits (32 bytes)
			 * 		- Strongest function we can think of using is SHA256
			 * It's not like the algorithm doesn't allow anything else... The
			 * standards fail here because they don't allow the hash function to be
			 * determined from the public key.
			 *
			 * See also:
			 * - https://www.openssl.org/docs/manmaster/ssl/SSL_set_security_level.html
			 */

        	// we have to hash the artifact first if session is inspected
        	unsigned int digest_size = SHA_DIGEST_LENGTH;
        	if(s->session->is_inspected && !EVP_Digest(hdata, hdatalen,
        			&(data[MD5_DIGEST_LENGTH]), &digest_size, EVP_sha1(), NULL)) {
        		// could not compute the hash for some reason...
        		SSLerr(SSL_F_SSL3_SEND_CLIENT_VERIFY, ERR_R_CRYPTO_LIB);
        		goto err;
        	}

        	// do sign, write the result & check it
        	if(!DSA_sign(pkey->save_type,
    				&(data[MD5_DIGEST_LENGTH]),
					digest_size, &(p[2]),
					(unsigned int *)&j, pkey->pkey.dsa)) {
        		SSLerr(SSL_F_SSL3_SEND_CLIENT_VERIFY, ERR_R_DSA_LIB);
        		goto err;
        	}

        	// finalize
            s2n(j, p);
            n = j + 2;
        } else
#endif
#ifndef OPENSSL_NO_ECDSA
        if (pkey->type == EVP_PKEY_EC) {

        	/*
        	 * ECDSA's limitations are very similar to DSA's - most importantly,
        	 * truncating persists. But the values differ...
        	 * Supported Groups registry defines the available curves:
        	 * - http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
        	 * Each curve's name (sect, secp, brainpool) indicates the allowed
        	 * bit-length of the input (until the algorithm starts truncating).
        	 * Yet again, it's safe to use SHA1 because the lowest value is 160
        	 * bits, so exactly 20 bytes.
        	 * Incidentally, the standard doesn't explicitly define a default
        	 * hash function for signing the CertificateVerify message with ECDSA
        	 * when the server doesn't specify restrictions in CertificateRequest.
        	 * OpenSSL clearly doesn't try to improvize and simply sticks to the
        	 * SHA1 restriction for DSA. Most implementations will probably do
        	 * the same, although a better hash function can of course be selected
        	 * dynamically from the key... Simply put, standards fail us again.
        	 */

        	// we have to hash the artifact first if session is inspected
        	unsigned int digest_size = SHA_DIGEST_LENGTH;
			if(s->session->is_inspected && !EVP_Digest(hdata, hdatalen,
					&(data[MD5_DIGEST_LENGTH]), &digest_size, EVP_sha1(), NULL)) {
				// could not compute the hash for some reason...
				SSLerr(SSL_F_SSL3_SEND_CLIENT_VERIFY, ERR_R_CRYPTO_LIB);
				goto err;
			}

        	// do sign, write the result & check it
        	if(!ECDSA_sign(pkey->save_type, &(data[MD5_DIGEST_LENGTH]),
        			SHA_DIGEST_LENGTH, &(p[2]), (unsigned int *)&j, pkey->pkey.ec)) {
        		SSLerr(SSL_F_SSL3_SEND_CLIENT_VERIFY, ERR_R_ECDSA_LIB);
                goto err;
            }

        	// finalize
            s2n(j, p);
            n = j + 2;
        } else
#endif
        if (pkey->type == NID_id_GostR3410_94
                || pkey->type == NID_id_GostR3410_2001) {
            unsigned char signbuf[64];
            int i;
            size_t sigsize = 64;
            s->method->ssl3_enc->cert_verify_mac(s,
                                                 NID_id_GostR3411_94, data);
            if (EVP_PKEY_sign(pctx, signbuf, &sigsize, data, 32) <= 0) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_VERIFY, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            for (i = 63, j = 0; i >= 0; j++, i--) {
                p[2 + j] = signbuf[i];
            }
            s2n(j, p);
            n = j + 2;
        } else {
            SSLerr(SSL_F_SSL3_SEND_CLIENT_VERIFY, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        ssl_set_handshake_header(s, SSL3_MT_CERTIFICATE_VERIFY, n);
        s->state = SSL3_ST_CW_CERT_VRFY_B;
    }
    if(s->session->is_inspected && (hdata != NULL)) {
    	OPENSSL_free(hdata);
    }
    EVP_MD_CTX_cleanup(&mctx);
    EVP_PKEY_CTX_free(pctx);
    return ssl_do_write(s);
 err:
 	if(s->session->is_inspected && (hdata != NULL)) {
 		OPENSSL_free(hdata);
    }
    EVP_MD_CTX_cleanup(&mctx);
    EVP_PKEY_CTX_free(pctx);
    s->state = SSL_ST_ERR;
    return (-1);
}

/*
 * Check a certificate can be used for client authentication. Currently check
 * cert exists, if we have a suitable digest for TLS 1.2 if static DH client
 * certificates can be used and optionally checks suitability for Suite B.
 */
static int ssl3_check_client_certificate(SSL *s)
{
    unsigned long alg_k;
    if (!s->cert || !s->cert->key->x509 || !s->cert->key->privatekey)
        return 0;
    /* If no suitable signature algorithm can't use certificate */
    if (SSL_USE_SIGALGS(s) && !s->cert->key->digest)
        return 0;
    /*
     * If strict mode check suitability of chain before using it. This also
     * adjusts suite B digest if necessary.
     */
    if (s->cert->cert_flags & SSL_CERT_FLAGS_CHECK_TLS_STRICT &&
        !tls1_check_chain(s, NULL, NULL, NULL, -2))
        return 0;
    alg_k = s->s3->tmp.new_cipher->algorithm_mkey;
    /* See if we can use client certificate for fixed DH */
    if (alg_k & (SSL_kDHr | SSL_kDHd)) {
    	SESS_CERT *sc = SSL_get_peer_cert(s);
        int i = sc->peer_cert_type;
        EVP_PKEY *clkey = NULL, *spkey = NULL;
        clkey = s->cert->key->privatekey;
        /* If client key not DH assume it can be used */
        if (EVP_PKEY_id(clkey) != EVP_PKEY_DH)
            return 1;
        if (i >= 0)
            spkey = X509_get_pubkey(sc->peer_pkeys[i].x509);
        if (spkey) {
            /* Compare server and client parameters */
            i = EVP_PKEY_cmp_parameters(clkey, spkey);
            EVP_PKEY_free(spkey);
            if (i != 1)
                return 0;
        }
        s->s3->flags |= TLS1_FLAGS_SKIP_CERT_VERIFY;
    }
    return 1;
}

int ssl3_send_client_certificate(SSL *s)
{
    X509 *x509 = NULL;
    EVP_PKEY *pkey = NULL;
    int i;

    if (s->state == SSL3_ST_CW_CERT_A) {
        /* Let cert callback update client certificates if required */
        if (s->cert->cert_cb) {
            i = s->cert->cert_cb(s, s->cert->cert_cb_arg);
            if (i < 0) {
                s->rwstate = SSL_X509_LOOKUP;
                return -1;
            }
            if (i == 0) {
                ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
                s->state = SSL_ST_ERR;
                return 0;
            }
            s->rwstate = SSL_NOTHING;
        }
        if (ssl3_check_client_certificate(s))
            s->state = SSL3_ST_CW_CERT_C;
        else
            s->state = SSL3_ST_CW_CERT_B;
    }

    /* We need to get a client cert */
    if (s->state == SSL3_ST_CW_CERT_B) {
        /*
         * If we get an error, we need to ssl->rwstate=SSL_X509_LOOKUP;
         * return(-1); We then get retied later
         */
        i = ssl_do_client_cert_cb(s, &x509, &pkey);
        if (i < 0) {
            s->rwstate = SSL_X509_LOOKUP;
            return (-1);
        }
        s->rwstate = SSL_NOTHING;
        if ((i == 1) && (pkey != NULL) && (x509 != NULL)) {
            s->state = SSL3_ST_CW_CERT_B;
            if (!SSL_use_certificate(s, x509) || !SSL_use_PrivateKey(s, pkey))
                i = 0;
        } else if (i == 1) {
            i = 0;
            SSLerr(SSL_F_SSL3_SEND_CLIENT_CERTIFICATE,
                   SSL_R_BAD_DATA_RETURNED_BY_CALLBACK);
        }

        if (x509 != NULL)
            X509_free(x509);
        if (pkey != NULL)
            EVP_PKEY_free(pkey);
        if (i && !ssl3_check_client_certificate(s))
            i = 0;
        if (i == 0) {
            if (s->version == SSL3_VERSION) {
                s->s3->tmp.cert_req = 0;
                ssl3_send_alert(s, SSL3_AL_WARNING, SSL_AD_NO_CERTIFICATE);
                return (1);
            } else {
                s->s3->tmp.cert_req = 2;
            }
        }

        /* Ok, we have a cert */
        s->state = SSL3_ST_CW_CERT_C;
    }

    if (s->state == SSL3_ST_CW_CERT_C) {
        s->state = SSL3_ST_CW_CERT_D;
        if (!ssl3_output_cert_chain(s,
                                    (s->s3->tmp.cert_req ==
                                     2) ? NULL : s->cert->key)) {
            SSLerr(SSL_F_SSL3_SEND_CLIENT_CERTIFICATE, ERR_R_INTERNAL_ERROR);
            ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
            s->state = SSL_ST_ERR;
            return 0;
        }
    }
    /* SSL3_ST_CW_CERT_D */
    return ssl_do_write(s);
}

#define has_bits(i,m)   (((i)&(m)) == (m))

int ssl3_check_cert_and_algorithm(SSL *s, SESS_CERT* sc)
{
    int i, idx;
    long alg_k, alg_a;
    EVP_PKEY *pkey = NULL;
    int pkey_bits;
#ifndef OPENSSL_NO_RSA
    RSA *rsa;
#endif
#ifndef OPENSSL_NO_DH
    DH *dh;
#endif
    int al = SSL_AD_HANDSHAKE_FAILURE;

    alg_k = s->s3->tmp.new_cipher->algorithm_mkey;
    alg_a = s->s3->tmp.new_cipher->algorithm_auth;

    /* we don't have a certificate */
    if ((alg_a & (SSL_aNULL | SSL_aKRB5)) || (alg_k & SSL_kPSK))
        return (1);

    if (sc == NULL) {
        SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM, ERR_R_INTERNAL_ERROR);
        goto err;
    }

#ifndef OPENSSL_NO_RSA
    rsa = SSL_get_peer_RSA_tmp_pubkey(s);
#endif
#ifndef OPENSSL_NO_DH
    dh = SSL_get_peer_DHE_tmp_pubkey(s);
#endif

    /* This is the passed certificate */

    idx = sc->peer_cert_type;
#ifndef OPENSSL_NO_ECDH
    if (idx == SSL_PKEY_ECC) {
        if (ssl_check_srvr_ecc_cert_and_alg(sc->peer_pkeys[idx].x509, s) == 0) {
            /* check failed */
            SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM, SSL_R_BAD_ECC_CERT);
            goto f_err;
        } else {
            return 1;
        }
    } else if (alg_a & SSL_aECDSA) {
        SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,
               SSL_R_MISSING_ECDSA_SIGNING_CERT);
        goto f_err;
    } else if (alg_k & (SSL_kECDHr | SSL_kECDHe)) {
        SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM, SSL_R_MISSING_ECDH_CERT);
        goto f_err;
    }
#endif
    pkey = X509_get_pubkey(sc->peer_pkeys[idx].x509);
    pkey_bits = EVP_PKEY_bits(pkey);
    i = X509_certificate_type(sc->peer_pkeys[idx].x509, pkey);
    EVP_PKEY_free(pkey);

    /* Check that we have a certificate if we require one */
    if ((alg_a & SSL_aRSA) && !has_bits(i, EVP_PK_RSA | EVP_PKT_SIGN)) {
        SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,
               SSL_R_MISSING_RSA_SIGNING_CERT);
        goto f_err;
    }
#ifndef OPENSSL_NO_DSA
    else if ((alg_a & SSL_aDSS) && !has_bits(i, EVP_PK_DSA | EVP_PKT_SIGN)) {
        SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,
               SSL_R_MISSING_DSA_SIGNING_CERT);
        goto f_err;
    }
#endif
#ifndef OPENSSL_NO_RSA
    if (alg_k & SSL_kRSA) {
        if (!SSL_C_IS_EXPORT(s->s3->tmp.new_cipher) &&
            !has_bits(i, EVP_PK_RSA | EVP_PKT_ENC)) {
            SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,
                   SSL_R_MISSING_RSA_ENCRYPTING_CERT);
            goto f_err;
        } else if (SSL_C_IS_EXPORT(s->s3->tmp.new_cipher)) {
            if (pkey_bits <= SSL_C_EXPORT_PKEYLENGTH(s->s3->tmp.new_cipher)) {
                if (!has_bits(i, EVP_PK_RSA | EVP_PKT_ENC)) {
                    SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,
                           SSL_R_MISSING_RSA_ENCRYPTING_CERT);
                    goto f_err;
                }
                if (rsa != NULL) {
                    /* server key exchange is not allowed. */
                    al = SSL_AD_INTERNAL_ERROR;
                    SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM, ERR_R_INTERNAL_ERROR);
                    goto f_err;
                }
            }
        }
    }
#endif
#ifndef OPENSSL_NO_DH
    if ((alg_k & SSL_kEDH) && dh == NULL) {
        al = SSL_AD_INTERNAL_ERROR;
        SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM, ERR_R_INTERNAL_ERROR);
        goto f_err;
    }
    if ((alg_k & SSL_kDHr) && !SSL_USE_SIGALGS(s) &&
               !has_bits(i, EVP_PK_DH | EVP_PKS_RSA)) {
        SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,
               SSL_R_MISSING_DH_RSA_CERT);
        goto f_err;
    }
# ifndef OPENSSL_NO_DSA
    if ((alg_k & SSL_kDHd) && !SSL_USE_SIGALGS(s) &&
        !has_bits(i, EVP_PK_DH | EVP_PKS_DSA)) {
        SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,
               SSL_R_MISSING_DH_DSA_CERT);
        goto f_err;
    }
# endif

    if (alg_k & (SSL_kDHE | SSL_kDHr | SSL_kDHd)) {
        int dh_size;
        if (alg_k & SSL_kDHE) {
            dh_size = BN_num_bits(dh->p);
        } else {
            DH *dh_srvr = get_server_static_dh_key(sc);
            if (dh_srvr == NULL)
                goto f_err;
            dh_size = BN_num_bits(dh_srvr->p);
            DH_free(dh_srvr);
        }

        if ((!SSL_C_IS_EXPORT(s->s3->tmp.new_cipher) && dh_size < 1024)
            || (SSL_C_IS_EXPORT(s->s3->tmp.new_cipher) && dh_size < 512)) {
            SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM, SSL_R_DH_KEY_TOO_SMALL);
            goto f_err;
        }
    }
#endif  /* !OPENSSL_NO_DH */

    if (SSL_C_IS_EXPORT(s->s3->tmp.new_cipher) &&
        pkey_bits > SSL_C_EXPORT_PKEYLENGTH(s->s3->tmp.new_cipher)) {
#ifndef OPENSSL_NO_RSA
        if (alg_k & SSL_kRSA) {
            if (rsa == NULL) {
                SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,
                       SSL_R_MISSING_EXPORT_TMP_RSA_KEY);
                goto f_err;
            } else if (BN_num_bits(rsa->n) >
                SSL_C_EXPORT_PKEYLENGTH(s->s3->tmp.new_cipher)) {
                /* We have a temporary RSA key but it's too large. */
                al = SSL_AD_EXPORT_RESTRICTION;
                SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,
                       SSL_R_MISSING_EXPORT_TMP_RSA_KEY);
                goto f_err;
            }
        } else
#endif
#ifndef OPENSSL_NO_DH
        if (alg_k & SSL_kDHE) {
            if (BN_num_bits(dh->p) >
                SSL_C_EXPORT_PKEYLENGTH(s->s3->tmp.new_cipher)) {
                /* We have a temporary DH key but it's too large. */
                al = SSL_AD_EXPORT_RESTRICTION;
                SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,
                       SSL_R_MISSING_EXPORT_TMP_DH_KEY);
                goto f_err;
            }
        } else if (alg_k & (SSL_kDHr | SSL_kDHd)) {
            /* The cert should have had an export DH key. */
            al = SSL_AD_EXPORT_RESTRICTION;
            SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,
                   SSL_R_MISSING_EXPORT_TMP_DH_KEY);
                goto f_err;
        } else
#endif
        {
            SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,
                   SSL_R_UNKNOWN_KEY_EXCHANGE_TYPE);
            goto f_err;
        }
    }
    return (1);
 f_err:
    ssl3_send_alert(s, SSL3_AL_FATAL, al);
 err:
    return (0);
}

#ifndef OPENSSL_NO_TLSEXT
/*
 * Normally, we can tell if the server is resuming the session from
 * the session ID. EAP-FAST (RFC 4851), however, relies on the next server
 * message after the ServerHello to determine if the server is resuming.
 * Therefore, we allow EAP-FAST to peek ahead.
 * ssl3_check_finished returns 1 if we are resuming from an external
 * pre-shared secret, we have a "ticket" and the next server handshake message
 * is Finished; and 0 otherwise. It returns -1 upon an error.
 */
int ssl3_check_finished(SSL *s)
{
    int ok = 0;

    if (s->version < TLS1_VERSION || !s->tls_session_secret_cb ||
        !s->session->tlsext_tick)
        return 0;

    /* Need to permit this temporarily, in case the next message is Finished. */
    s->s3->flags |= SSL3_FLAGS_CCS_OK;
    /*
     * This function is called when we might get a Certificate message instead,
     * so permit appropriate message length.
     * We ignore the return value as we're only interested in the message type
     * and not its length.
     */
    s->method->ssl_get_message(s,
                               SSL3_ST_CR_CERT_A,
                               SSL3_ST_CR_CERT_B,
                               -1, s->max_cert_list, &ok);
    s->s3->flags &= ~SSL3_FLAGS_CCS_OK;

    if (!ok)
        return -1;

    s->s3->tmp.reuse_message = 1;

    if (s->s3->tmp.message_type == SSL3_MT_FINISHED)
        return 1;

    /* If we're not done, then the CCS arrived early and we should bail. */
    if (s->s3->change_cipher_spec) {
        SSLerr(SSL_F_SSL3_CHECK_FINISHED, SSL_R_CCS_RECEIVED_EARLY);
        ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_UNEXPECTED_MESSAGE);
        return -1;
    }

    return 0;
}

# ifndef OPENSSL_NO_NEXTPROTONEG
int ssl3_send_next_proto(SSL *s)
{
    unsigned int len, padding_len;
    unsigned char *d;

    if (s->state == SSL3_ST_CW_NEXT_PROTO_A) {
        len = s->next_proto_negotiated_len;
        padding_len = 32 - ((len + 2) % 32);
        d = (unsigned char *)s->init_buf->data;
        d[4] = len;
        memcpy(d + 5, s->next_proto_negotiated, len);
        d[5 + len] = padding_len;
        memset(d + 6 + len, 0, padding_len);
        *(d++) = SSL3_MT_NEXT_PROTO;
        l2n3(2 + len + padding_len, d);
        s->state = SSL3_ST_CW_NEXT_PROTO_B;
        s->init_num = 4 + 2 + len + padding_len;
        s->init_off = 0;
    }

    return ssl3_do_write(s, SSL3_RT_HANDSHAKE);
}
#endif                          /* !OPENSSL_NO_NEXTPROTONEG */
#endif                          /* !OPENSSL_NO_TLSEXT */

int ssl_do_client_cert_cb(SSL *s, X509 **px509, EVP_PKEY **ppkey)
{
    int i = 0;
#ifndef OPENSSL_NO_ENGINE
    if (s->ctx->client_cert_engine) {
        i = ENGINE_load_ssl_client_cert(s->ctx->client_cert_engine, s,
                                        SSL_get_client_CA_list(s),
                                        px509, ppkey, NULL, NULL, NULL);
        if (i != 0)
            return i;
    }
#endif
    if (s->ctx->client_cert_cb)
        i = s->ctx->client_cert_cb(s, px509, ppkey);
    return i;
}
