/* ssl/t1_prx.c */
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

// system includes
#include <stdio.h>

// openssl includes
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/bn.h>
#ifndef OPENSSL_NO_DH
# include <openssl/dh.h>
#endif
#include "ssl_locl.h"
#include "../crypto/constant_time_locl.h"

/*
 * -----------------------------------------------------------------
 * Message queue utility functions and structures.
 * -----------------------------------------------------------------
 */

// forward declare a message queue item
typedef struct msg_queue_item_st MSG_QUEUE_ITEM;

// define message queue item
struct msg_queue_item_st {
	int msg_type;
	unsigned long msg_len;
	void* msg;
	MSG_QUEUE_ITEM* next;
};

// define message queue
typedef struct msg_queue_st {
	MSG_QUEUE_ITEM* first;
	MSG_QUEUE_ITEM* last;
} MSG_QUEUE;

MSG_QUEUE_ITEM* msg_queue_item_new(const unsigned char* msg,
		const unsigned long msg_len, const int msg_type)
{
	MSG_QUEUE_ITEM* result = OPENSSL_malloc(sizeof(MSG_QUEUE_ITEM));
	if (result != NULL) {
		result->msg_type = msg_type;
		result->msg_len = msg_len;
		result->msg = BUF_memdup(msg, msg_len);
		result->next = NULL;
	}
	return result;
}

void msg_queue_push(MSG_QUEUE* queue, const unsigned char* msg,
		const unsigned long msg_len, const int msg_type)
{
	MSG_QUEUE_ITEM* item = msg_queue_item_new(msg, msg_len, msg_type);
	if (queue->first == NULL) {
		queue->first = item;
	}
	if (queue->last != NULL) {
		queue->last->next = item;
	}
	queue->last = item; // item->next is assumed to be NULL
}

MSG_QUEUE_ITEM* msg_queue_peek(MSG_QUEUE* queue)
{
	return queue->first;
}

MSG_QUEUE_ITEM* msg_queue_pop(MSG_QUEUE* queue)
{
	MSG_QUEUE_ITEM* result = msg_queue_peek(queue);
	if (result != NULL) {
		queue->first = result->next;
		if(queue->first == NULL) {
			queue->last = NULL;
		}
		result->next = NULL;
	}
	return result;
}

void msg_queue_item_free(MSG_QUEUE_ITEM* item)
{
	OPENSSL_free(item);
}

void msg_queue_free(MSG_QUEUE* queue)
{
	while (queue->first != NULL) {
		msg_queue_item_free(msg_queue_pop(queue));
	}
}

/*
 * -----------------------------------------------------------------
 * Global variables.
 * -----------------------------------------------------------------
 */

// connections to both endpoints
static SSL* conn_prx_is_server = NULL;
static SSL* conn_prx_is_client = NULL;

// message queues for both endpoints
static MSG_QUEUE pq_prx_is_server;
static MSG_QUEUE pq_prx_is_client;

/*
 * -----------------------------------------------------------------
 * Entry point methods.
 * -----------------------------------------------------------------
 */

/*
 * This method is called when the proxy accepts a new connection
 * from a client. The connection is passed as an argument, wrapped
 * into the SSL handler.
 */
int tls12_prx_accept(SSL *s)
{
	/*
	 * Called from the 'ssl3_accept' method... for now, just register
	 * the connection.
	 */
	if (conn_prx_is_server) {
		// SSL_free(conn_prx_is_server);
	}
	conn_prx_is_server = s;
	return 2; // must return something distinct from the usual codes...
}

// forward declare the main method:
int tls12_prx_do_handshake();

/*
 * This method is called when the proxy connects to the given server.
 * The connection is passed as an argument, wrapped into the SSL handler.
 */
int tls12_prx_connect(SSL *s)
{
	// called from the 'ssl3_connect' method...
	if (conn_prx_is_client) {
		// SSL_free(conn_prx_is_client);
	}
	conn_prx_is_client = s;
	return tls12_prx_do_handshake();
}

/*
 * -----------------------------------------------------------------
 * Special informative functions.
 * -----------------------------------------------------------------
 */

/*
 * Determines whether the proxy has decided to only forward
 * the communication. Documents the result of the following
 * functions, after they are called:
 * - tls12_prx_should_inspect_early()
 * - tls12_should_inspect_final()
 */
int tls12_prx_only_forward_comm()
{
	return conn_prx_is_server->prx_simply_forward;
}

/*
 * Determines whether the proxy has applied public mode to the
 * communication.
 * Note: undefined behavior if communication is forwarded.
 */
int tls12_prx_is_public_mode()
{
	return conn_prx_is_client->tpe_value == TLSEXT_TPE_PROXY;
}

/*
 * Determines whether the proxy has applied private mode to the
 * communication.
 * Note: undefined behavior if communication is forwarded.
 */
int tls12_prx_is_private_mode()
{
	return conn_prx_is_client->tpe_value == TLSEXT_TPE_CLIENT;
}

/*
 * Determines whether the client allowed inspection at all.
 */
int tls12_prx_clnt_allowed_proxy()
{
	return conn_prx_is_server->tpe_value > 0;
}

/*
 * Determines whether the server demanded client authentication.
 * Note: undefined behavior if communication is forwarded.
 */
int tls12_prx_is_clnt_auth_required()
{
	return conn_prx_is_client->s3->tmp.cert_req;
}

/*
 * -----------------------------------------------------------------
 * Application callbacks.
 * -----------------------------------------------------------------
 */

/*
 * Called in forwarding mode, when the proxy faces a choice: either to let
 * the client attempt to resume a proxy session with the server (server will
 * then issue a new session instead), or spawn an error and invalidate the
 * session. Successive connection attempts will no longer attempt to resume
 * the same session and proxy can just forward the communication with no loss
 * of privacy.
 * Application should return 1 if it's alright with forwarding the session
 * information.
 */
int tls12_prx_frwrd_own_resumption()
{
	return 0;
}

/*
 * Called after the proxy receives ClientHello from client
 * and before the following is automatically checked:
 * - TLS 1.2
 * - client allows inspection
 *
 * This method makes an early decision whether to inspect
 * the communication. The only alternative is to forward it
 * without alterations (inspection). If zero is returned,
 * decision has been made to only forward the communication.
 * In that case, much of the code defined in this file will
 * become unreachable, while some will face undefined behavior.
 * As a result, every function description in this file should
 * contain a note regarding this.
 */
int tls12_prx_should_inspect_early()
{
	/*
	 * Decision can be either static or dynamic. Some information
	 * is available at this point and some is not. For example,
	 * the server hasn't declared whether it requires client
	 * authentication yet.
	 *
	 * There should be several primary decision factors:
	 * - host/IP of the server, IP of the client, previous experience
	 * - session resumption
	 * - if session resumption, then also client authentication status
	 * of the original session
	 * - did the client initiate a TLS 1.2 session?
	 * - did the client allow inspection at all?
	 * Advanced applications will probably use most of these factors
	 * but for our demo, the last two will be entirely sufficient.
	 */

	int tls12_confirmed = conn_prx_is_server->client_version == TLS1_2_VERSION;
	int clnt_allowed_inspection = tls12_prx_clnt_allowed_proxy();
	return tls12_confirmed && clnt_allowed_inspection;
}

/*
 * Called when the proxy is about to send ClientHello to the server.
 * This method should return the TPE value to send - can be
 * TLSEXT_TPE_PROXY, TLSEXT_TPE_CLIENT or 0. Use zero to denote that
 * no value should be sent (there's still a chance to abandon inspection
 * decision from 'tls12_prx_should_inspect_early()'.
 * Note: unreachable if communication is forwarded.
 */
int tls12_prx_clnt_get_tpe_value()
{
	/*
	 * Public mode is the best default when we want to inspect
	 * communication with client authentication.
	 * Private mode is the best default when we want to make a
	 * final decision about inspection later, after we receive
	 * ServerHello from the server. But that also means re-sending
	 * the client's ClientHello without a single alteration which
	 * is not too easy implementation-wise. For instance, this
	 * demo doesn't support averting the early inspection decision.
	 *
	 * Despite we check the following condition again later (just
	 * to be sure), its real place is here.
	 */

	// only send it if the client sent it (public mode by default)
	return tls12_prx_clnt_allowed_proxy() ? TLSEXT_TPE_PROXY : 0;
}

/*
 * Called at the latest point possible to determine the proxy's final
 * decision about inspecting the ongoing communication.
 * At this point, all information is available, including whether
 * the server requires client authentication. A boolean should be
 * returned.
 * Note: unreachable if communication is forwarded.
 */
int tls12_should_inspect_final()
{
	/*
	 * The semantics of this method is a slight extension of
	 * 'tls12_prx_should_inspect_early()'. There's more information
	 * available now:
	 * - The early decision.
	 * - The server's certificate.
	 * - Whether the server requires client authentication.
	 * Advanced applications will probably define a bit more complex
	 * code but for our demo, the first factor and a static value will
	 * be entirely sufficient.
	 *
	 * Important note: developers should check out all the checks in
	 * 'tls12_prx_srvr_get_tpe_value()' to see the hidden pitfalls of
	 * this method.
	 */

	// early decision should be respected in most situations
	return tls12_prx_only_forward_comm() ? 0 : 1;
}

/*
 * -----------------------------------------------------------------
 * Some internal (not application) callbacks/routines.
 * -----------------------------------------------------------------
 */

/*
 * Sends the given alert messages to both connections and thus,
 * interrupts the handshake/protocol.
 */
int tls12_prx_terminate_one(SSL* which, int al_default)
{
	// determine the alert to send (incoming alert has more priority)
	int al_code = al_default;
	al_code = which->s3->warn_alert ? which->s3->warn_alert : al_code;
	al_code = which->s3->fatal_alert ? which->s3->fatal_alert : al_code;

	// send it
	ssl3_send_alert(which, SSL3_AL_FATAL, al_code);

	// and exit
	SSLerr(SSL_F_SSL3_CONNECT, SSL_R_INSPECTION);
	return (-1);
}

/*
 * Sends the given alert messages to both connections and thus,
 * interrupts the handshake/protocol.
 */
int tls12_prx_terminate_both(int al_client, int al_server)
{
	/*
	 * Note: even if 'ssl3_send_alert()' gets called again later, it
	 * won't send another alert and will still succeed. Convenient.
	 */
	SSLerr(SSL_F_SSL3_CONNECT, SSL_R_INSPECTION);
	ssl3_send_alert(conn_prx_is_server, SSL3_AL_FATAL, al_client);
	ssl3_send_alert(conn_prx_is_client, SSL3_AL_FATAL, al_server);
	return (-1);
}

/*
 * Called whenever the proxy receives a message from either of the endpoints.
 * Return codes:
 * - 1 if execution should continue.
 * - 2 if execution should be stopped.
 */
int tls12_prx_msg_rcvd_early_cb(const SSL* s, const unsigned char* msg,
		const unsigned long msg_len, const int msg_type)
{
	// for now, simply queue the message (forward it later)
	MSG_QUEUE* target_queue = s == conn_prx_is_server ? &pq_prx_is_client :
			&pq_prx_is_server;
	msg_queue_push(target_queue, msg, msg_len, msg_type);

	// and return
	int only_forward = tls12_prx_only_forward_comm();
	if (!only_forward && (s == conn_prx_is_server)) {
		only_forward |= (msg_type == SSL3_MT_CERTIFICATE) ||
				(msg_type == SSL3_MT_CERTIFICATE_VERIFY);
	}
	return only_forward ? 2 : 1;
}

/*
 * This method calls 'tls12_should_inspect_final()' and checks all
 * related conditions to determine whether inspection can be initiated.
 * Based on all that, it chooses a TPE value to send to the client.
 * Note: unreachable if communication is forwarded.
 */
int tls12_prx_srvr_get_tpe_value(SSL* s)
{
	// whether we'll need to restart the communication after all
	int restart = 0;

	// it's time for a final decision about inspection
	int forwarded = tls12_prx_only_forward_comm();
	int will_inspect = tls12_should_inspect_final();

	/*
	 * Note: 'tls12_prx_srvr_hll_rcvd_cb()' guarantees that either
	 * both sessions are being resumed or none.
	 */
	if (s->hit && (SSL_is_session_inspected(s) != will_inspect)) {
		/*
		 * So far, we have successfully negotiated session resumption
		 * with both endpoints but application decisions do not comply
		 * with the extension's definition (session inspection status
		 * must be maintained for all connections that belong to it).
		 * This method can not ignore application decisions and it also
		 * can not apply them - the only choice left is to abort.
		 */
		return tls12_prx_terminate_both(SSL_AD_INTERNAL_ERROR,
				SSL_AD_INTERNAL_ERROR);
	}

	// if the early and final decisions differ, we must do some checks
	if (forwarded && will_inspect) {
		/*
		 * Decision changed from forwarding to inspection. Since the
		 * proxy didn't alter ClientHello, there are only two options:
		 * - server received no TPE value
		 * - server received TLSEXT_TPE_CLIENT (private mode)
		 */

		/*
		 * First and foremost, check client's cooperation again. The
		 * 'tls12_prx_clnt_hll_rcvd_cb()' function received a decision
		 * to simply forward communication so it didn't check.
		 */
		if (!tls12_prx_clnt_allowed_proxy()) {
			/*
			 * Conflict: we want to inspect but client doesn't allow it.
			 * This is a major fail in decision-making...
			 */
			return tls12_prx_terminate_both(SSL_AD_INSPECTION_REQUIRED,
					SSL_AD_HANDSHAKE_FAILURE);
		} else if (tls12_prx_is_clnt_auth_required()) {
			/*
			 * Client authentication means public mode so the proxy just
			 * got itself into a no-go situation and must restart server
			 * connection. Next time, it MUST decide to inspect early.
			 */
			restart = 1;
		}
	} else if (!forwarded && !will_inspect) {
		/*
		 * Decision changed from inspection to forwarding. At this point,
		 * we know we have altered ClientHello and can't go back to
		 * forwarding easily because the endpoints will NOT be able to
		 * confirm handshake integrity. We must restart.
		 */
		restart = 1;
	}

	// handle result of the checks
	if (restart) {
		/*
		 * Nothing but bad choices and bad luck. Proxy should try to
		 * minimize the chance for this event. Depending on the situation
		 * that got us here, there are two ways to react:
		 * 1) Halt client connection and redo server connection, this
		 * time with correct choices.
		 * 2) Abort both connections.
		 *
		 * Note: client will ignore HelloRequest when in the midst
		 * of a handshake (dictated by standard) so we can not use
		 * the message.
		 *
		 * Normally, the first option would do nicely but because
		 * of implementation difficulty, we're forced to stick with
		 * the second option. However, it doesn't really matter as this
		 * conditional branch is not reachable in the demo.
		 * TODO: Unimplemented thus far because of difficulty. For now,
		 * just terminate both connections.
		 */
		return tls12_prx_terminate_both(SSL_AD_HANDSHAKE_FAILURE,
				SSL_AD_HANDSHAKE_FAILURE);
	} else {
		// all conditions have been asserted and inspection is on
		return TLSEXT_TPE_PROXY;
	}
}

/*
 * -----------------------------------------------------------------
 * Main control methods to establish communication.
 * -----------------------------------------------------------------
 */

/*
 * Initialization taken from 'ssl3_connect' and 'ssl3_accept'.
 * They are almost identical.
 */
void tls12_prx_handshake_init(SSL* s)
{
	// just init...
	s->in_handshake++;
	if (!SSL_in_init(s) || SSL_in_before(s)) {
		SSL_clear(s);
	}

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
}

/*
 * This method controls when we stop the connection to client
 * so that the other connection can continue.
 */
int tls12_stop_prx_srvr_at(SSL* s, int last_finished_state)
{
	if (s->hit) {
		// abbreviated handshake...
		switch (last_finished_state) {
			// phase 1 - server receives ClientHello
			case SSL3_ST_SR_CLNT_HELLO_A:
			case SSL3_ST_SR_CLNT_HELLO_B:
			case SSL3_ST_SR_CLNT_HELLO_C:
				return 1;

			default:
				return 0;
		}
	} else {
		// regular handshake...
		switch (last_finished_state) {
			// phase 0 - proxy sends HelloRequest to client
			case SSL3_ST_SW_HELLO_REQ_A:
			case SSL3_ST_SW_HELLO_REQ_B:

			// phase 1 - proxy receives ClientHello from client
			case SSL3_ST_SR_CLNT_HELLO_A:
			case SSL3_ST_SR_CLNT_HELLO_B:
			case SSL3_ST_SR_CLNT_HELLO_C:

			// phase 2 - proxy receives Finished from client
			case SSL3_ST_SR_FINISHED_A:
			case SSL3_ST_SR_FINISHED_B:
				return 1;

			default:
				return 0;
		}
	}
}

/*
 * This method controls when we stop the connection to server
 * so that the other connection can continue.
 */
int tls12_stop_prx_clnt_at(SSL* s, int last_finished_state)
{
	if (s->hit) {
		// abbreviated handshake...
		switch (last_finished_state) {
			// phase 1 - proxy receives Finished from server
			case SSL3_ST_CR_FINISHED_A:
			case SSL3_ST_CR_FINISHED_B:
				return 1;

			default:
				return 0;
		}
	} else {
		// regular handshake...
		switch (last_finished_state) {
			// phase 1 - proxy receives ServerHelloDone from server
			case SSL3_ST_CR_SRVR_DONE_A:
			case SSL3_ST_CR_SRVR_DONE_B:
				return 1;

			default:
				return 0;
		}
	}
}

/*
 * Called to forward a particular message from the given queue. This
 * method will evict from the queue as long as the message is not
 * found, unless the 'optional' flag is set. In that case, there will
 * only be eviction if the target message is at the first position.
 * Returns a boolean indicating whether the target message has been
 * sent.
 */
int tls12_prx_frwrd_msg(SSL* target_conn, MSG_QUEUE* source_queue,
		const int msg_type, const int optional)
{
	int sent = 0;
	while (!sent && (msg_queue_peek(source_queue) != NULL)) {
		MSG_QUEUE_ITEM* item = msg_queue_peek(source_queue);
		if (item->msg_type == msg_type) {
			/*
			 * Messages we receive in the callbacks don't include
			 * the header (first 4 bytes). Luckily, OpenSSL handles
			 * that almost automatically.
			 * Note: we have to copy the message buffers as we have
			 * to free the queued message right afterwards and
			 * OpenSSL may buffer the outgoing message only to
			 * flush it at a later time.
			 */
			unsigned char *msg_buff = ssl_handshake_start(target_conn);
			memcpy(msg_buff, item->msg, item->msg_len);
			ssl_set_handshake_header(target_conn, msg_type, item->msg_len);
			ssl_do_write(target_conn);
			sent = 1;
		} else if (optional) {
			/*
			 * Optional messages only get one try (they won't evict
			 * from the queue unless there's a match.
			 */
			break;
		}

		// if we have a match or match is not optional, evict and free
		msg_queue_item_free(msg_queue_pop(source_queue));
	}
	return sent;
}

/*
 * Called when buffered messages should be actually sent into the
 * underlying channel.
 */
int tls12_prx_flush(SSL* s)
{
	/*
	 * This code originally checked to see if any data was pending
	 * using BIO_CTRL_INFO and then flushed. This caused problems as
	 * documented in PR#1939. The proposed fix doesn't completely
	 * resolve this issue as buggy implementations of
	 * BIO_CTRL_PENDING still exist. So instead we just flush
	 * unconditionally.
	 */
	s->rwstate = SSL_WRITING;
	if (BIO_flush(s->wbio) <= 0) {
		return -1;
	}
	s->rwstate = SSL_NOTHING;
	return 1;
}

// forward declare handshake functions
int do_connect(SSL* s, int (*stop)(SSL*, int));
int do_accept(SSL* s, int (*stop)(SSL*, int));

/*
 * Called when the proxy establishes a connection to both
 * endpoints and when it's ready to forward messages amongst
 * them.
 */
int tls12_prx_do_handshake()
{
	/*
	 * Initialize globals.
	 */

	pq_prx_is_client.first = NULL;
	pq_prx_is_client.last = NULL;
	pq_prx_is_server.first = NULL;
	pq_prx_is_server.last = NULL;
	tls12_prx_handshake_init(conn_prx_is_server);
	tls12_prx_handshake_init(conn_prx_is_client);

	// done once although connection-dependent calls might be more appropriate
	ERR_clear_error();
	clear_sys_error();

	// connection-dependent initialization
	if (conn_prx_is_server->cert == NULL) {
		// proxy certificate not set... this is an embarrassing moment
		SSLerr(SSL_F_SSL3_ACCEPT, SSL_R_NO_CERTIFICATE_SET);
		return tls12_prx_terminate_both(SSL_AD_INTERNAL_ERROR,
				SSL_AD_INTERNAL_ERROR);
	}

	/*
	 * Do handshakes...
	 */

	int done = 0;
	int handshake_client = 1;
	int ret = 0;
	while (!done) {
		// continue with the right connection
		if(handshake_client) {
			// first handle the current part of a handshake
			ret = do_accept(conn_prx_is_server, tls12_stop_prx_srvr_at);
		} else {
			// advance the handshake with server
			ret = do_connect(conn_prx_is_client, tls12_stop_prx_clnt_at);
		}

		// handle result
		if (ret > 0) {
			/*
			 * Handshake has either finished or control told us to stop
			 * and let the other connection continue.
			 */
			handshake_client = !handshake_client;
			done = (conn_prx_is_server->state == SSL_ST_OK) &&
					(conn_prx_is_client->state == SSL_ST_OK);
		} else {
			// some kind of an error occurred
			break;
		}
	}

	/*
	 * At this point we either received an error or both
	 * handshakes are done.
	 */

	// always free any remainders of allocated memory
	msg_queue_free(&pq_prx_is_client);
	msg_queue_free(&pq_prx_is_server);

	// determine the status of both connections
	int is_conn_prx_is_srvr_shut = conn_prx_is_server->shutdown &
			(SSL_RECEIVED_SHUTDOWN | SSL_SENT_SHUTDOWN);
	int is_conn_prx_is_clnt_shut = conn_prx_is_client->shutdown &
			(SSL_RECEIVED_SHUTDOWN | SSL_SENT_SHUTDOWN);

	/*
	 * As the proxy's main cycle first accepts client connection
	 * and then connects to the server, both connections need to
	 * be treated as one.
	 */

	// the calling code treats (ret == 0) as a reading/writing error
	if (ret <= 0) {
		// test if only one of the connections is down
		if (is_conn_prx_is_srvr_shut != is_conn_prx_is_clnt_shut) {
			// if so, shut the other
			SSL* which = is_conn_prx_is_clnt_shut ? conn_prx_is_server :
					conn_prx_is_client;
			ret = tls12_prx_terminate_one(which, SSL_AD_INTERNAL_ERROR);
		}
	}

	// and return
	return ret;
}

/*
 * Called to do handshake of the proxy and server. It's a copy of
 * 'ssl3_connect' but adjusted for the proxy's needs. TLS extensions
 * must have been allowed for us to get this far so we explicitly
 * removed the related #ifndef invocations.
 */
int do_connect(SSL* s, int (*stop)(SSL*, int))
{
	/*
	 * Declare & initialize variables.
	 */
	int ret = -1;
	BUF_MEM *buf = NULL;

	unsigned long Time = (unsigned long)time(NULL);
	RAND_add(&Time, sizeof(Time), 0);

	void (*cb) (const SSL *ssl, int type, int val) = NULL;
	if (s->info_callback != NULL) {
		cb = s->info_callback;
	} else if (s->ctx->info_callback != NULL) {
		cb = s->ctx->info_callback;
	}

	// we will forward messages from this queue
	MSG_QUEUE* queue_source = &pq_prx_is_client;

	/*
	 * Continue with the handshake...
	 */

	for (;;) {

		// declare variables
		int skip = 0;

		// backup current state
		int last_state = s->state;

		// and continue...
		switch (s->state) {

		case SSL_ST_RENEGOTIATE:
			// there's a thin line between regular handshake & renegotiation:
			s->renegotiate = 1;
			s->state = SSL_ST_CONNECT;
			s->ctx->stats.sess_connect_renegotiate++;
			// notice the silent transition to a regular handshake

		case SSL_ST_BEFORE:
		case SSL_ST_CONNECT:
		case SSL_ST_BEFORE | SSL_ST_CONNECT:
		case SSL_ST_OK | SSL_ST_CONNECT:
			if (cb != NULL) {
				cb(s, SSL_CB_HANDSHAKE_START, 1);
			}

			s->type = SSL_ST_CONNECT;
			if (s->init_buf == NULL) {
				if ((buf = BUF_MEM_new()) == NULL) {
					s->state = SSL_ST_ERR;
					goto err;
				}
				if (!BUF_MEM_grow(buf, SSL3_RT_MAX_PLAIN_LENGTH)) {
					s->state = SSL_ST_ERR;
					goto err;
				}
				s->init_buf = buf;
				buf = NULL;
			}

			if (!ssl3_setup_buffers(s)) {
				goto err;
			}

			/* setup buffing BIO */
			if (!ssl_init_wbio_buffer(s, 0)) {
				s->state = SSL_ST_ERR;
				goto err;
			}

			// don't push the buffering BIO quite yet
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
			// send the message
			s->shutdown = 0;
			if (tls12_prx_only_forward_comm()) {
				ret = tls12_prx_frwrd_msg(s, queue_source, SSL3_MT_CLIENT_HELLO, 0);
			} else {
				ret = ssl3_send_client_hello(s);
			}

			// handle result
			if (ret <= 0) {
				goto err;
			}

			// this method handles handshake as seen from the client
			s->state = SSL3_ST_CR_SRVR_HELLO_A;
			s->init_num = 0;

			/* turn on buffering for the next lot of output */
			if (s->bbio != s->wbio) {
				s->wbio = BIO_push(s->bbio, s->wbio);
			}
			break;

		case SSL3_ST_CR_SRVR_HELLO_A:
		case SSL3_ST_CR_SRVR_HELLO_B:
			ret = ssl3_get_server_hello(s);
			if (ret <= 0) {
				goto err;
			}

			if (s->hit) {
				// we're reusing a previous session => abbreviated handshake
				if (s->tlsext_ticket_expected) {
					s->state = SSL3_ST_CR_SESSION_TICKET_A;
				} else {
					s->state = SSL3_ST_CR_FINISHED_A;
				}
			} else {
				// we're creating a new session => full handshake
				s->state = SSL3_ST_CR_CERT_A;
			}
			s->init_num = 0;
			break;

		case SSL3_ST_CR_CERT_A:
		case SSL3_ST_CR_CERT_B:
			// received message will be queued via a callback
			ret = ssl3_check_finished(s);
			if (ret < 0) {
				goto err;
			} else if (ret == 1) {
				s->hit = 1;
				s->state = SSL3_ST_CR_FINISHED_A;
				s->init_num = 0;
				break;
			} else {
				// should only trigger for EAP-FAST
			}

			// the following is valid for non-anon, non-SRP and non-PSK connections
			ret = ssl3_get_certificate(s, 0);
			if (ret <= 0) {
				goto err;
			}

			// finish up
			s->state = s->tlsext_status_expected ? SSL3_ST_CR_CERT_STATUS_A :
					SSL3_ST_CR_KEY_EXCH_A;
			s->init_num = 0;
			break;

		case SSL3_ST_CR_CERT_STATUS_A:
		case SSL3_ST_CR_CERT_STATUS_B:
			// received message will be queued via a callback
			ret = ssl3_get_cert_status(s, 0);
			if (ret <= 0) {
				goto err;
			}

			// finish up
			s->state = SSL3_ST_CR_KEY_EXCH_A;
			s->init_num = 0;
			break;

		case SSL3_ST_CR_KEY_EXCH_A:
		case SSL3_ST_CR_KEY_EXCH_B:
			// received message will be queued via a callback
			ret = ssl3_get_key_exchange(s, &(s->session->end_cert));
			if (ret <= 0) {
				goto err;
			}

			// check current requirements
			if (!tls12_prx_only_forward_comm() &&
					!ssl3_check_cert_and_algorithm(s, s->session->end_cert)) {
				ret = -1;
				s->state = SSL_ST_ERR;
				goto err;
			}

			// finish up
			s->state = SSL3_ST_CR_CERT_REQ_A;
			s->init_num = 0;
			break;

		case SSL3_ST_CR_CERT_REQ_A:
		case SSL3_ST_CR_CERT_REQ_B:
			// received message will be queued via a callback
			ret = ssl3_get_certificate_request(s);
			if (ret <= 0) {
				goto err;
			}

			// finish up
			s->state = SSL3_ST_CR_SRVR_DONE_A;
			s->init_num = 0;
			break;

		case SSL3_ST_CR_SRVR_DONE_A:
		case SSL3_ST_CR_SRVR_DONE_B:
			// no special action to take for the proxy
			ret = ssl3_get_server_done(s);
			if (ret <= 0) {
				goto err;
			}

			// finish up
			s->state = tls12_prx_is_clnt_auth_required() ? SSL3_ST_CW_CERT_A :
					SSL3_ST_CW_KEY_EXCH_A;
			s->init_num = 0;
			break;

		case SSL3_ST_CW_CERT_A:
		case SSL3_ST_CW_CERT_B:
		case SSL3_ST_CW_CERT_C:
		case SSL3_ST_CW_CERT_D:
			// always forward what we received from client
			ret = tls12_prx_frwrd_msg(s, queue_source, SSL3_MT_CERTIFICATE, 0);

			// handle result
			if (ret <= 0) {
				goto err;
			}

			// finish up
			s->state = SSL3_ST_CW_KEY_EXCH_A;
			s->init_num = 0;
			break;

		case SSL3_ST_CW_KEY_EXCH_A:
		case SSL3_ST_CW_KEY_EXCH_B:
			// send the message
			if (tls12_prx_only_forward_comm()) {
				ret = tls12_prx_frwrd_msg(s, queue_source, SSL3_MT_CLIENT_KEY_EXCHANGE, 0);
			} else {
				ret = ssl3_send_client_key_exchange(s, SSL_get_peer_cert(s));
			}

			// check result
			if (ret <= 0) {
				goto err;
			}

			/*
			 * Finish up.
			 * XXX: For now, OpenSSL does not support client authentication
			 * in ECDH cipher suites with ECDH (rather than ECDSA) certificates.
			 * CertificateVerify message needs to be skipped when client's
			 * ECDH public key is sent inside the client certificate.
			 */
			if (s->s3->flags & TLS1_FLAGS_SKIP_CERT_VERIFY) {
				s->state = SSL3_ST_CW_CHANGE_A;
			} else {
				s->state = tls12_prx_is_clnt_auth_required() ? SSL3_ST_CW_CERT_VRFY_A :
						SSL3_ST_CW_CHANGE_A;
			}
			s->init_num = 0;
			break;

		case SSL3_ST_CW_CERT_VRFY_A:
		case SSL3_ST_CW_CERT_VRFY_B:
			// always forward what we received from client
			ret = tls12_prx_frwrd_msg(s, queue_source, SSL3_MT_CERTIFICATE_VERIFY, 0);

			// handle result
			if (ret <= 0) {
				goto err;
			}

			// finish up
			s->state = SSL3_ST_CW_CHANGE_A;
			s->init_num = 0;
			break;

		case SSL3_ST_CW_CHANGE_A:
		case SSL3_ST_CW_CHANGE_B:
			// no special action to take for the proxy
			ret = ssl3_send_change_cipher_spec(s,
					SSL3_ST_CW_CHANGE_A,
					SSL3_ST_CW_CHANGE_B);

			// handle result
			if (ret <= 0) {
				goto err;
			}

			// finish up
#if defined(OPENSSL_NO_NEXTPROTONEG)
			s->state = SSL3_ST_CW_FINISHED_A;
#else
			if (s->s3->next_proto_neg_seen) {
				s->last_state = SSL3_ST_CW_NEXT_PROTO_A;
			} else {
				s->last_state = SSL3_ST_CW_FINISHED_A;
			}
#endif

#ifdef OPENSSL_NO_COMP
			s->session->compress_meth = 0;
#else
			if (s->s3->tmp.new_compression == NULL) {
				s->session->compress_meth = 0;
			} else {
				s->session->compress_meth = s->s3->tmp.new_compression->id;
			}
#endif
			s->init_num = 0;
			s->session->cipher = s->s3->tmp.new_cipher;

			if (!s->method->ssl3_enc->setup_key_block(s) ||
					!s->method->ssl3_enc->change_cipher_state(s,
					SSL3_CHANGE_CIPHER_CLIENT_WRITE)) {
				s->state = SSL_ST_ERR;
			}
			break;

#if !defined(OPENSSL_NO_NEXTPROTONEG)
		case SSL3_ST_CW_NEXT_PROTO_A:
		case SSL3_ST_CW_NEXT_PROTO_B:
			// always forward what we received from client
			ret = tls12_prx_frwrd_msg(s, queue_source, SSL3_MT_NEXT_PROTO, 0);
			if (ret <= 0) {
				goto end;
			}
			s->last_state = SSL3_ST_CW_FINISHED_A;
			break;
#endif

		case SSL3_ST_CW_FINISHED_A:
		case SSL3_ST_CW_FINISHED_B:
			// send the message
			if (tls12_prx_only_forward_comm()) {
				ret = tls12_prx_frwrd_msg(s, queue_source, SSL3_MT_FINISHED, 0);
			} else {
				// all received and sent messages are automatically included
				ret = ssl3_send_finished(s,
						SSL3_ST_CW_FINISHED_A,
						SSL3_ST_CW_FINISHED_B,
						s->method->ssl3_enc->client_finished_label,
						s->method->ssl3_enc->client_finished_label_len);
			}

			// handle result
			if (ret <= 0) {
				goto err;
			}

			// finish up
			s->s3->flags &= ~SSL3_FLAGS_POP_BUFFER;
			if (s->hit) {
				// we're renegotiating...
				s->s3->tmp.next_state = SSL_ST_OK;

				/*
				 * Handling of the SSL3_FLAGS_DELAY_CLIENT_FINISHED flag has been
				 * removed here because it was a bit unfortunate for the proxy
				 * to implement. Also, it shouldn't really be needed as the client
				 * can delay as long as he wishes.
				 */
			} else {
				s->state = s->tlsext_ticket_expected ?
						SSL3_ST_CR_SESSION_TICKET_A : SSL3_ST_CR_FINISHED_A;
			}
			s->init_num = 0;

			// and before continuing, flush
			if (tls12_prx_flush(s) <= 0) {
				goto err;
			}
			break;

		case SSL3_ST_CR_FINISHED_A:
		case SSL3_ST_CR_FINISHED_B:
			if (!s->s3->change_cipher_spec) {
				s->s3->flags |= SSL3_FLAGS_CCS_OK;
			}

			// all received and sent messages are automatically included
			ret = ssl3_get_finished(s, SSL3_ST_CR_FINISHED_A,
					SSL3_ST_CR_FINISHED_B);

			// handle result
			if (ret <= 0) {
				goto err;
			}

			// finish up
			s->state = s->hit ? SSL3_ST_CW_CHANGE_A : SSL_ST_OK;
			s->init_num = 0;
			break;

		case SSL3_ST_CR_SESSION_TICKET_A:
		case SSL3_ST_CR_SESSION_TICKET_B:
			// always receive the message, regardless of inspection
			ret = ssl3_get_new_session_ticket(s);
			if (ret <= 0) {
				goto err;
			}

			// finish up
			s->state = SSL3_ST_CR_FINISHED_A;
			s->init_num = 0;
			break;

		case SSL_ST_OK:
			/*
			 * Cleanup.
			 */

			ssl3_cleanup_key_block(s);
			if (s->init_buf != NULL) {
				BUF_MEM_free(s->init_buf);
				s->init_buf = NULL;
			}

			if (!(s->s3->flags & SSL3_FLAGS_POP_BUFFER)) {
				ssl_free_wbio_buffer(s);
			} else {
				// it will done later (ssl3_write)
			}

			s->init_num = 0;
			s->renegotiate = 0;
			s->new_session = 0;

			ssl_update_cache(s, SSL_SESS_CACHE_CLIENT);
			if (s->hit) {
				s->ctx->stats.sess_hit++;
			}

			s->handshake_func = ssl3_connect;
			s->ctx->stats.sess_connect_good++;

			ret = 1;
			if (cb != NULL) {
				cb(s, SSL_CB_HANDSHAKE_DONE, 1);
			}
			goto done; // no break

		case SSL_ST_ERR:
		default:
			ret = -1;
			SSLerr(SSL_F_SSL3_CONNECT, SSL_R_UNKNOWN_STATE);
			goto err; // no break
		}

		// if the last iteration did something...
		if (!s->s3->tmp.reuse_message && !skip) {
			// output some info if the '-debug' option is used
			if (s->debug) {
				if ((ret = BIO_flush(s->wbio)) <= 0)
					goto err;
			}

			/*
			 * Inform application layer about a completed
			 * handshake step.
			 */
			if ((cb != NULL) && (s->state != last_state)) {
				// temporarily restore the state that was completed
				int state_bckp = s->state;
				s->state = last_state;
				cb(s, SSL_CB_CONNECT_LOOP, 1);

				// and revert the change
				s->state = state_bckp;
			}
		}

		// if control wants us to stop for now, we have to oblige
		if ((s->state != SSL_ST_ERR) && (s->state != SSL_ST_OK) &&
				stop(s, last_state)) {
			ret = 2; // special code just for this
			goto exit_for_now;
		} else {
			skip = 0;
		}
	}

 err:
 	ret = -1;
 done:
 	s->in_handshake--;
 	if (cb != NULL) {
		cb(s, SSL_CB_CONNECT_EXIT, ret);
	}
 exit_for_now:
	return (ret);
}

/**
 * Called to do handshake of the proxy and client. It's a copy of
 * 'ssl3_accept' but adjusted for the proxy's needs. TLS extensions
 * must have been allowed for us to get this far so we explicitly
 * removed the related #ifndef invocations.
 */
int do_accept(SSL* s, int (*stop)(SSL*, int))
{
	/*
	 * Declare & initialize variables.
	 */
	int ret = -1;
	unsigned long alg_k;
	int new_state, skip = 0;
	BUF_MEM *buf = NULL;
	int cert_msg_sent = 0;

	unsigned long Time = (unsigned long)time(NULL);
	RAND_add(&Time, sizeof(Time), 0);

	void (*cb) (const SSL *ssl, int type, int val) = NULL;
	if (s->info_callback != NULL) {
		cb = s->info_callback;
	} else if (s->ctx->info_callback != NULL) {
		cb = s->ctx->info_callback;
	}

	// we will forward messages from this queue
	MSG_QUEUE* queue_source = &pq_prx_is_server;

	/*
	 * Continue with the handshake...
	 */

	for (;;) {
		// declare variables
		int skip = 0;

		// backup current state
		int last_state = s->state;

		switch (s->state) {
		case SSL_ST_RENEGOTIATE:
			// there's a thin line between regular handshake & renegotiation:
			s->renegotiate = 1;
			// notice the silent transition to a regular handshake

		case SSL_ST_BEFORE:
		case SSL_ST_ACCEPT:
		case SSL_ST_BEFORE | SSL_ST_ACCEPT:
		case SSL_ST_OK | SSL_ST_ACCEPT:
			if (cb != NULL) {
				cb(s, SSL_CB_HANDSHAKE_START, 1);
			}

			s->type = SSL_ST_ACCEPT;
			if (s->init_buf == NULL) {
				if ((buf = BUF_MEM_new()) == NULL) {
					s->state = SSL_ST_ERR;
					goto err_or_done;
				}
				if (!BUF_MEM_grow(buf, SSL3_RT_MAX_PLAIN_LENGTH)) {
					BUF_MEM_free(buf);
					s->state = SSL_ST_ERR;
					goto err_or_done;
				}
				s->init_buf = buf;
				buf = NULL;
			}

			if (!ssl3_setup_buffers(s)) {
				s->state = SSL_ST_ERR;
				goto err_or_done;
			}

			s->init_num = 0;
			s->s3->flags &= ~TLS1_FLAGS_SKIP_CERT_VERIFY;
			s->s3->flags &= ~SSL3_FLAGS_CCS_OK;

			// should have been reset by ssl3_get_finished, too
			s->s3->change_cipher_spec = 0;

			if (s->state != SSL_ST_RENEGOTIATE) {
				/*
				 * Ok, we now need to push on a buffering BIO so that the
				 * output is sent in a way that TCP likes :-)
				 */
				if (!ssl_init_wbio_buffer(s, 1)) {
					s->state = SSL_ST_ERR;
					goto err_or_done;
				}

				ssl3_init_finished_mac(s);
				s->state = SSL3_ST_SR_CLNT_HELLO_A;
				s->ctx->stats.sess_accept++;
			} else if (!s->s3->send_connection_binding &&
					   !(s->options &
						 SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION)) {
				/*
				 * Server attempting to renegotiate with client that doesn't
				 * support secure renegotiation.
				 */
				SSLerr(SSL_F_SSL3_ACCEPT,
					   SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED);
				ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_HANDSHAKE_FAILURE);
				s->state = SSL_ST_ERR;
				goto err_or_done;
			} else {
				/*
				 * s->state == SSL_ST_RENEGOTIATE, we will just send a
				 * HelloRequest
				 */
				s->ctx->stats.sess_accept_renegotiate++;
				s->state = SSL3_ST_SW_HELLO_REQ_A;
			}
			break;

		case SSL3_ST_SW_HELLO_REQ_A:
		case SSL3_ST_SW_HELLO_REQ_B:
			// TODO: unimplemented because of difficulty.
			goto err_or_done;

		case SSL3_ST_SR_CLNT_HELLO_A:
		case SSL3_ST_SR_CLNT_HELLO_B:
		case SSL3_ST_SR_CLNT_HELLO_C:
			s->shutdown = 0;
			ret = ssl3_get_client_hello(s);
			if (ret <= 0) {
				goto err_or_done;
			}

			// finish up
			s->renegotiate = 2;
			s->state = SSL3_ST_SW_SRVR_HELLO_A;
			s->init_num = 0;
			break;

		case SSL3_ST_SW_SRVR_HELLO_A:
		case SSL3_ST_SW_SRVR_HELLO_B:
			// send the message
			if (tls12_prx_only_forward_comm()) {
				ret = tls12_prx_frwrd_msg(s, queue_source, SSL3_MT_SERVER_HELLO, 0);
			} else {
				ret = ssl3_send_server_hello(s);
			}

			// handle result
			if (ret <= 0) {
				goto err_or_done;
			}

			// finish up
			if (s->hit) {
				// TODO: for now, tickets are only supported in forwarding mode...
				s->state = (tls12_prx_only_forward_comm() && s->tlsext_ticket_expected) ?
						SSL3_ST_SW_SESSION_TICKET_A : SSL3_ST_SW_CHANGE_A;
			} else {
				s->state = SSL3_ST_SW_CERT_A;
			}
			s->init_num = 0;
			break;

		case SSL3_ST_SW_CERT_A:
		case SSL3_ST_SW_CERT_B:
			// send the message
			if (tls12_prx_only_forward_comm() || (cert_msg_sent == 0)) {
				// simply forward what we received from the server
				ret = tls12_prx_frwrd_msg(s, queue_source, SSL3_MT_CERTIFICATE, 0);
			} else {
				// proxy sends its own Certificate
				ret = ssl3_send_server_certificate(s);
			}

			// check result
			if (ret <= 0) {
				goto err_or_done;
			}

			// finish up
			if (!tls12_prx_only_forward_comm() && (cert_msg_sent == 0)) {
				s->state = s->tlsext_status_expected ? SSL3_ST_SW_CERT_STATUS_A :
						SSL3_ST_SW_CERT_A;
			} else {
				s->state = s->tlsext_status_expected ? SSL3_ST_SW_CERT_STATUS_A :
						SSL3_ST_SW_KEY_EXCH_A;
			}
			s->init_num = 0;
			cert_msg_sent++;
			break;

		case SSL3_ST_SW_CERT_STATUS_A:
		case SSL3_ST_SW_CERT_STATUS_B:
			// send the message
			if (tls12_prx_only_forward_comm() || (cert_msg_sent == 1)) {
				// simply forward what we received from the server
				ret = tls12_prx_frwrd_msg(s, queue_source, SSL3_MT_CERTIFICATE_STATUS, 1);
			} else {
				// proxy sends its own CertificateStatus
				ret = ssl3_send_cert_status(s);
			}

			// check result
			if (ret <= 0) {
				goto err_or_done;
			}

			// finish up
			if (!tls12_prx_only_forward_comm() && (cert_msg_sent == 1)) {
				s->state = SSL3_ST_SW_CERT_A;
			} else {
				s->state = SSL3_ST_SW_KEY_EXCH_A;
			}
			s->init_num = 0;
			break;

		case SSL3_ST_SW_KEY_EXCH_A:
		case SSL3_ST_SW_KEY_EXCH_B:
			/*
			 * A note to OpenSSL developers: how about we turn "may" into
			 * "will" and get rid of this here?
			 * Although this may get reset by 'send_server_key_exchange',
			 * do it now as well.
			 */
			s->s3->tmp.use_rsa_tmp = 0;

			/*
			 * Only send this message if we negotiate a DHE, ECDHE or RSA
			 * key exchange algorithm.
			 */

			alg_k = s->s3->tmp.new_cipher->algorithm_mkey;
			if ((alg_k & SSL_kEDH) || (alg_k & SSL_kEECDH) || (alg_k & SSL_kRSA)) {
				// send the message
				if (tls12_prx_only_forward_comm()) {
					// simply forward what we received from the server
					ret = tls12_prx_frwrd_msg(s, queue_source, SSL3_MT_SERVER_KEY_EXCHANGE, 0);
				} else {
					/*
					 * This is one of the proxy's crucial points. Although it is currently
					 * communicating with the client, the proxy will generate its public
					 * key for the server now, if RSA. Requirements:
					 * - server certificate must have been copied into this conn
					 * - the result RSA key (if any) must be copied into the other conn
					 * - the result (EC)DHE key (if any) must be copied into the other conn
					 */
					ret = ssl3_send_server_key_exchange(s);
				}

				// handle result
				if (ret <= 0) {
					goto err_or_done;
				}
			} else {
				skip = 1;
			}

			// finish up
			s->state = SSL3_ST_SW_CERT_REQ_A;
			s->init_num = 0;
			break;

		case SSL3_ST_SW_CERT_REQ_A:
		case SSL3_ST_SW_CERT_REQ_B:
			if (tls12_prx_is_clnt_auth_required()) {
				// always forward server's demand for client authentication
				ret = tls12_prx_frwrd_msg(s, queue_source, SSL3_MT_CERTIFICATE_REQUEST, 0);
				if (ret <= 0) {
					goto err_or_done;
				}

				// finish up
				s->init_num = 0;
#ifndef NETSCAPE_HANG_BUG
				s->state = SSL3_ST_SW_SRVR_DONE_A;
#else
				s->state = SSL3_ST_SR_CERT_A;
				// and before continuing, flush
				if (tls12_prx_flush(s) <= 0) {
					goto err_or_done;
				}
#endif
			} else {
				/*
				 * Normally, we would digest cached messages here but
				 * the proxy doesn't need to do that.
				 */
				skip = 1;
				s->state = SSL3_ST_SW_SRVR_DONE_A;
			}
			break;

		case SSL3_ST_SW_SRVR_DONE_A:
		case SSL3_ST_SW_SRVR_DONE_B:
			// no special action to take for the proxy
			ret = ssl3_send_server_done(s);
			if (ret <= 0) {
				goto err_or_done;
			}

			// finish up
			s->state = SSL3_ST_SR_CERT_A;
			s->init_num = 0;

			// and before continuing, flush
			if (tls12_prx_flush(s) <= 0) {
				goto err_or_done;
			}
			break;

		case SSL3_ST_SR_CERT_A:
		case SSL3_ST_SR_CERT_B:
			// received message will be queued via a callback
			if (tls12_prx_is_clnt_auth_required()) {
				ret = ssl3_get_client_certificate(s);
				if (ret <= 0) {
					goto err_or_done;
				}
			}

			// finish up
			s->state = SSL3_ST_SR_KEY_EXCH_A;
			s->init_num = 0;
			break;

		case SSL3_ST_SR_KEY_EXCH_A:
		case SSL3_ST_SR_KEY_EXCH_B:
			// received message will be queued via a callback
			ret = ssl3_get_client_key_exchange(s);
			if (ret <= 0) {
				goto err_or_done;
			}

			if (ret == 2) {
				/*
				 * Skip CertificateVerify if we negotiated an ECDH cipher
				 * suite. More details at RFC 4492, sections 3.2 and 3.3.
				 * At the moment, TPE doesn't support ECDH key exchange anyway
				 * so this code should be unreachable.
				 */
#if !defined(OPENSSL_NO_NEXTPROTONEG)
				if (s->s3->next_proto_neg_seen) {
					s->state = SSL3_ST_SR_NEXT_PROTO_A;
				} else {
					s->state = SSL3_ST_SR_FINISHED_A;
				}
#else
				s->state = SSL3_ST_SR_FINISHED_A;
#endif
				s->init_num = 0;
			} else if (SSL_USE_SIGALGS(s)) {
				/*
				 * Normally, we would digest & check cached handshake
				 * messages here. We would also verify that we received
				 * client's certificate. The proxy doesn't need to do
				 * any of that.
				 */

				// finish up
				s->state = SSL3_ST_SR_CERT_VRFY_A;
				s->init_num = 0;
				s->s3->flags |= TLS1_FLAGS_KEEP_HANDSHAKE;
			} else {
				/*
				 * Normally, we would digest and check cached messages
				 * here but the proxy doesn't need to do that as it is
				 * decided by now that we inspect the session.
				 */

				// finish up
				s->state = SSL3_ST_SR_CERT_VRFY_A;
				s->init_num = 0;
			}
			break;

		case SSL3_ST_SR_CERT_VRFY_A:
		case SSL3_ST_SR_CERT_VRFY_B:
			// received message will be queued via a callback
			if (s->s3->tmp.cert_request) {
				ret = ssl3_get_cert_verify(s);
				if (ret <= 0) {
					goto err_or_done;
				}
			}

			// finish up
#if !defined(OPENSSL_NO_NEXTPROTONEG)
			if (s->s3->next_proto_neg_seen)
				s->state = SSL3_ST_SR_NEXT_PROTO_A;
			else
				s->state = SSL3_ST_SR_FINISHED_A;
#else
			s->state = SSL3_ST_SR_FINISHED_A;
#endif
			s->init_num = 0;
			break;

#if !defined(OPENSSL_NO_NEXTPROTONEG)
		case SSL3_ST_SR_NEXT_PROTO_A:
		case SSL3_ST_SR_NEXT_PROTO_B:
			/*
			 * Enable CCS for NPN. Receiving a CCS clears the flag, so make
			 * sure not to re-enable it to ban duplicates. This *should* be the
			 * first time we have received one - but we check anyway to be
			 * cautious.
			 * s->s3->change_cipher_spec is set when a CCS is
			 * processed in s3_pkt.c, and remains set until
			 * the client's Finished message is read.
			 */
			if (!s->s3->change_cipher_spec) {
				s->s3->flags |= SSL3_FLAGS_CCS_OK;
			}

			// received message will be queued via a callback
			ret = ssl3_get_next_proto(s);
			if (ret <= 0) {
				goto end;
			}

			// finish up
			s->init_num = 0;
			s->state = SSL3_ST_SR_FINISHED_A;
			break;
#endif

		case SSL3_ST_SR_FINISHED_A:
		case SSL3_ST_SR_FINISHED_B:
			/*
			 * Enable CCS for handshakes without NPN. In NPN the CCS flag has
			 * already been set. Receiving a CCS clears the flag, so make
			 * sure not to re-enable it to ban duplicates.
			 * s->s3->change_cipher_spec is set when a CCS is
			 * processed in s3_pkt.c, and remains set until
			 * the client's Finished message is read.
			 */
			if (!s->s3->change_cipher_spec) {
				s->s3->flags |= SSL3_FLAGS_CCS_OK;
			}

			// all received and sent messages are automatically included
			if (s->prx_simply_forward) {
				/*
				 * TODO: in the call below, we would receive ChangeCipherSpec and that
				 * is the end of our implementation for now. After receiving CCS, the
				 * call will fail because further content is encrypted and we don't
				 * have the needed key when simply forwarding communication.
				 * Direct reading/writing interface that bypasses encryption and integrity
				 * is needed to advance this functionality further. We can either try
				 * to hack OpenSSL's routines somehow or extract our own interface
				 * from them. Either way, it's not an easy thing to do... For now,
				 * simply fail.
				 */
				return tls12_prx_terminate_both(SSL_AD_INTERNAL_ERROR,
						SSL_AD_INTERNAL_ERROR);
			}
			ret = ssl3_get_finished(s, SSL3_ST_SR_FINISHED_A,
					SSL3_ST_SR_FINISHED_B);
			if (ret <= 0) {
				goto err_or_done;
			}

			// finish up
			if (s->hit) {
				s->state = SSL_ST_OK;
			} else if (tls12_prx_only_forward_comm() && s->tlsext_ticket_expected) {
				// for now, tickets are only supported in forwarding mode...
				s->state = SSL3_ST_SW_SESSION_TICKET_A;
			} else {
				s->state = SSL3_ST_SW_CHANGE_A;
			}
			s->init_num = 0;
			break;

		case SSL3_ST_SW_CHANGE_A:
		case SSL3_ST_SW_CHANGE_B:
			// oh well, could have done this much sooner...
			s->session->cipher = s->s3->tmp.new_cipher;

			// this is where we compute master secret and the keys
			if (!s->method->ssl3_enc->setup_key_block(s)) {
				ret = -1;
				s->state = SSL_ST_ERR;
				goto err_or_done;
			}

			// no special action for the proxy to take
			ret = ssl3_send_change_cipher_spec(s,
					SSL3_ST_SW_CHANGE_A, SSL3_ST_SW_CHANGE_B);
			if (ret <= 0) {
				goto err_or_done;
			}

			// finish up
			s->state = SSL3_ST_SW_FINISHED_A;
			s->init_num = 0;
			if (!s->method->ssl3_enc->change_cipher_state(s,
					SSL3_CHANGE_CIPHER_SERVER_WRITE))
			{
				ret = -1;
				s->state = SSL_ST_ERR;
				goto err_or_done;
			}
			break;

		case SSL3_ST_SW_FINISHED_A:
		case SSL3_ST_SW_FINISHED_B:
			// send the message
			if (tls12_prx_only_forward_comm()) {
				ret = tls12_prx_frwrd_msg(s, queue_source, SSL3_MT_FINISHED, 0);
			} else {
				ret = ssl3_send_finished(s,
						SSL3_ST_SW_FINISHED_A,
						SSL3_ST_SW_FINISHED_B,
						s->method->ssl3_enc->server_finished_label,
						s->method->ssl3_enc->server_finished_label_len);
			}

			// handle result
			if (ret <= 0) {
				goto err_or_done;
			}

			// finish up
			if (s->hit) {
#if !defined(OPENSSL_NO_NEXTPROTONEG)
				if (s->s3->next_proto_neg_seen) {
					s->state = SSL3_ST_SR_NEXT_PROTO_A;
				} else {
					s->state = SSL3_ST_SR_FINISHED_A;
				}
#else
				s->state = SSL3_ST_SR_FINISHED_A;
#endif
			} else {
				s->state = SSL_ST_OK;
			}
			s->init_num = 0;

			// and before continuing, flush
			if (tls12_prx_flush(s) <= 0) {
				goto err_or_done;
			}
			break;

		case SSL3_ST_SW_SESSION_TICKET_A:
		case SSL3_ST_SW_SESSION_TICKET_B:
			// send the message
			if (tls12_prx_only_forward_comm()) {
				// simply forward what we received from the server
				ret = tls12_prx_frwrd_msg(s, queue_source, SSL3_MT_NEWSESSION_TICKET, 0);
			} else {
				/*
				 * Proxy sends its own ticket, regardless of the handshake type.
				 * TODO: unimplemented thus far because of difficulty. The following function
				 * call relies on 'i2d_SSL_SESSION' and 'd2i_SSL_SESSION' where the key
				 * functionality should be defined.
				 */
				// ret = ssl3_send_newsession_ticket(s);
			}

			// check result
			if (ret <= 0) {
				goto err_or_done;
			}

			// finish up
			s->state = SSL3_ST_SW_CHANGE_A;
			s->init_num = 0;
			break;

		case SSL_ST_OK:
			// cleanup
			ssl3_cleanup_key_block(s);
			BUF_MEM_free(s->init_buf);
			s->init_buf = NULL;
			ssl_free_wbio_buffer(s);
			s->init_num = 0;

			// a little special handling of only sending HelloRequest
			if (s->renegotiate == 2) {
				s->renegotiate = 0;
				s->new_session = 0;

				ssl_update_cache(s, SSL_SESS_CACHE_SERVER);

				s->ctx->stats.sess_accept_good++;
				s->handshake_func = ssl3_accept;

				if (cb != NULL) {
					cb(s, SSL_CB_HANDSHAKE_DONE, 1);
				}
			}

			// finish up
			ret = 1;
			goto err_or_done; // no break

		case SSL_ST_ERR:
		default:
			ret = -1;
			SSLerr(SSL_F_SSL3_ACCEPT, SSL_R_UNKNOWN_STATE);
			goto err_or_done; // no break
		}

		// if the last iteration did something...
		if (!s->s3->tmp.reuse_message && !skip) {
			// output some info if the '-debug' option is used
			if (s->debug) {
				if ((ret = BIO_flush(s->wbio)) <= 0)
					goto err_or_done;
			}

			/*
			 * Inform application layer about a completed
			 * handshake step.
			 */
			if ((cb != NULL) && (s->state != last_state)) {
				// temporarily restore the state that was completed
				int state_bckp = s->state;
				s->state = last_state;
				cb(s, SSL_CB_CONNECT_LOOP, 1);

				// and revert the change
				s->state = state_bckp;
			}
		}

		// if control wants us to stop for now, we have to oblige
		if ((s->state != SSL_ST_ERR) && (s->state != SSL_ST_OK) &&
				stop(s, last_state)) {
			ret = 2; // special code just for this
			goto exit_for_now;
		} else {
			skip = 0;
		}
	}

 err_or_done:
	s->in_handshake--;
	if (cb != NULL) {
		cb(s, SSL_CB_ACCEPT_EXIT, ret);
	}
 exit_for_now:
	return (ret);
}

/*
 * Called to try to retrieve server-side session using the
 * mapping from client-side session.
 */
int tls12_prx_restore_srvr_session()
{
	/*
	 * Client can target server sessions (not ours) if previous communication
	 * was not inspected.
	 */
	if (!tls12_prx_only_forward_comm() &&
			!SSL_SESSION_is_mapped(conn_prx_is_server->session)) {
		/*
		 * Either the early decision about inspection was wrong (client
		 * targets a session that was not inspected before) or there's
		 * something fishy going on...
		 */
		if (SSL_is_session_inspected(conn_prx_is_server)) {
			// early decision was not wrong after all...
			tls12_prx_terminate_both(SSL_AD_INTERNAL_ERROR, SSL_AD_INTERNAL_ERROR);
			return -1;
		}
	}

	// try to retrieve the mapped session
	int ret = ssl_get_prev_session(conn_prx_is_client,
			conn_prx_is_server->session->mapped_sid,
			SSL_MAX_SSL_SESSION_ID_LENGTH,
			&(conn_prx_is_server->session->mapped_sid[0]) +
			SSL_MAX_SSL_SESSION_ID_LENGTH);

	/*
	 * Copied from 's3_srvr.c'.
	 *
	 * Only resume if the session's version matches the negotiated
	 * version. RFC 5246 does not provide much useful advice on
	 * resumption with a different protocol version. It doesn't
	 * forbid it but the sanity of such behaviour would be questionable.
	 * In practice, clients do not accept a version mismatch and
	 * will abort the handshake with an error.
	 */
	if (ret == -1) {
		// there was an error
		tls12_prx_terminate_both(SSL_AD_INTERNAL_ERROR, SSL_AD_INTERNAL_ERROR);
		return -1;
	} else if ((ret == 1) && !tls12_prx_only_forward_comm() && strcmp(
			(char*) &(conn_prx_is_client->session->mapped_sid[0]),
			(char*) &(conn_prx_is_server->session->session_id[0])) != 0) {
		// hmm, invalid session mapping (bijection is NOT confirmed)...
		tls12_prx_terminate_both(SSL_AD_INTERNAL_ERROR, SSL_AD_INTERNAL_ERROR);
		return -1;
	} else {
		// whether mapped session could not be restored
		int session_missing = ret == 0;

		// whether the session's and connection's versions match
		int version_check = conn_prx_is_client->session->ssl_version ==
				conn_prx_is_server->client_version;

		// whether the previous session is not compatible with the early inspection decision
		int bad_decision = !tls12_prx_only_forward_comm() &&
				!SSL_is_session_inspected(conn_prx_is_server);

		// now use these factors
		if (session_missing || !version_check || bad_decision) {
			// we have to respond with a new session
			if (!ssl_get_new_session(conn_prx_is_client, 1)) {
				tls12_prx_terminate_both(SSL_AD_INTERNAL_ERROR, SSL_AD_INTERNAL_ERROR);
				return 0;
			}
		}

		// and return
		return 1;
	}
}

/*
 * This method is called when a ClientHello message is received
 * from the client. It copies some information into the other
 * connection and specially handles extension data.
 */
int tls12_prx_clnt_hll_rcvd_cb(SSL* s)
{
	/*
	 * Note:
	 * 1) Final decision about inspection will come after receiving
	 * ServerHelloDone from server.
	 * 2) 's' is 'conn_prx_is_server'.
	 */

	// first, pick up from temporary storage...
	int resumption_attempted = s->prx_simply_forward != 0;

	// make an early choice about inspection and save it
	int forward = !tls12_prx_should_inspect_early();
	conn_prx_is_server->prx_simply_forward = forward;
	conn_prx_is_client->prx_simply_forward = forward;

	// double check circumstances (the above call may not handle this)
	if (!forward && ((s->client_version != TLS1_2_VERSION) ||
			!tls12_prx_clnt_allowed_proxy())) {
		/*
		 * We have decided to apply inspection but can not because
		 * client requested an older (or unsupported) protocol version,
		 * or because it refused to be inspected.
		 */
		tls12_prx_terminate_both(SSL_AD_HANDSHAKE_FAILURE, SSL_AD_INTERNAL_ERROR);
		return 0;
	} else if (forward && s->hit && SSL_is_session_inspected(s)) {
		/*
		 * We decided to forward the client's request and let him try to
		 * resume OUR session with the server. Technically speaking, this
		 * is NOT a problem because server will inevitably issue a new
		 * session, ignoring the ticket sent (if any). A quote from RFC 5077:
		 *    "If the server fails to verify the ticket, then it falls back
		 *    to performing a full handshake. If the ticket is accepted by
		 *    the server but the handshake fails, the client SHOULD delete
		 *    the ticket."
		 * However, certain applications (e.g. firewalls) might not want to
		 * send an issued ticket into the wild before invalidating it. There
		 * is also the matter of what's actually included in a ticket (some
		 * implementations might be nasty about this). The best solution is
		 * probably not to let this happen and spawn an error:
		 */
		if (!tls12_prx_frwrd_own_resumption()) {
			tls12_prx_terminate_both(SSL_AD_HANDSHAKE_FAILURE,
					SSL_AD_INTERNAL_ERROR);
			return 0;
		}
	} else if (forward && resumption_attempted && !s->hit) {
		/*
		 * When client attempts to resume a server session with us...
		 * Control must know about possible abbreviated handshake
		 * so that messages can be correctly forwarded.
		 */
		s->hit = 1;
	}

	/*
	 * Next, session with the server needs to be deserialized or
	 * initialized.
	 *
	 * Note: even if we only forward the communication, Hello messages
	 * must be parsed and processed because they influence the message
	 * flow. Otherwise, methods around 'tls12_prx_do_handshake()' can't
	 * do their job.
	 */

	// are we resuming a session or creating a new one?
	if (!forward && s->hit) {
		// make sure to try to resume server session as well
		int ret = tls12_prx_restore_srvr_session();
		if (ret <= 0) {
			// fail if there's an error or the server session is missing
			return 0;
		} else {
			SSL_renegotiate_abbreviated(conn_prx_is_client);
		}
	} else {
		/*
		 * Prepare server session in advance so we can copy some information
		 * into it right now.
		 */
		if (!ssl_get_new_session(conn_prx_is_client, 0)) {
			tls12_prx_terminate_both(SSL_AD_INTERNAL_ERROR, SSL_AD_INTERNAL_ERROR);
			return 0;
		}

		// if appropriate, try to renegotiate server-side session as well
		if (s->renegotiate) {
			SSL_renegotiate(conn_prx_is_client);
		}

		// and finally, make note that we're definitely creating a new session
		conn_prx_is_client->new_session = 1;
	}

	/*
	 * TODO: eventually, we should make the proxy connect to the
	 * server NOW, not before.
	 */

	/*
	 * And only then copy other important information.
	 */

	// proxy will always mirror the client's random data
	memcpy(&(conn_prx_is_client->s3->client_random[0]),
			&(s->s3->client_random[0]), SSL3_RANDOM_SIZE);

	if (!s->hit) {
		// proxy will mirror the client's protocol version
		conn_prx_is_client->version = s->version;
		conn_prx_is_client->client_version = s->client_version;

		// this shouldn't be really needed but who knows...
		conn_prx_is_server->session->ssl_version = s->client_version;
		conn_prx_is_client->session->ssl_version = s->client_version;

		// filter client's cipher suites (only in inspection mode)
		if (!forward) {
			/*
			 * For client authentication to work, we need to evict DH or ECDH from
			 * client's list of cipher suites ahead of time, just as we will do with
			 * the proxy's list, before sending it to the server. An alternative is
			 * to support independent key exchange negotiation.
			 */

			// filter out DH and ECDH cipher suites
			SSL_filter_DH_and_ECDH_kxchng(s->session->ciphers);

			// copy the result list over to the server connection
			if (conn_prx_is_client->session->ciphers) {
				// should never happen but just in case...
				sk_SSL_CIPHER_free(conn_prx_is_client->session->ciphers);
			}
			conn_prx_is_client->session->ciphers = sk_SSL_CIPHER_dup(s->session->ciphers);
		}
	}

	if (forward) {
		goto done;
	}

	/*
	 * Finally, copy important extension data if we're not just forwarding.
	 *
	 * WARNING: the following code must be kept in accordance with
	 * 'ssl_get_new_session()' - see the call in the next function.
	 */

	// server name indication
	if (s->session->tlsext_hostname) {
		// overwrite the proxy's record
		if (conn_prx_is_client->session->tlsext_hostname) {
			OPENSSL_free(conn_prx_is_client->session->tlsext_hostname);
		}
		conn_prx_is_client->session->tlsext_hostname = BUF_memdup(
				s->session->tlsext_hostname, strlen(s->session->tlsext_hostname));
		conn_prx_is_client->servername_done = s->servername_done;
	}

	// TODO - signature algorithms extension:
	// tls1_set_server_sigalgs(s);

	// TODO - 's->cert':
	// 1) status extension
	// 2) ALPN extension

	// ellyptic curve cryptography
#ifndef OPENSSL_NO_EC
	if (!s->hit) {
		if (s->session->tlsext_ecpointformatlist_length > 0) {
			// overwrite the proxy's formats with formats common to both proxy and client
			if (conn_prx_is_client->session->tlsext_ecpointformatlist) {
				OPENSSL_free(conn_prx_is_client->session->tlsext_ecpointformatlist);
			}
			conn_prx_is_client->session->tlsext_ecpointformatlist = BUF_memdup(
					s->session->tlsext_ecpointformatlist,
					s->session->tlsext_ecpointformatlist_length);
			conn_prx_is_client->session->tlsext_ecpointformatlist_length =
					s->session->tlsext_ecpointformatlist_length;
		}
		if (s->session->tlsext_ellipticcurvelist_length > 0) {
			// overwrite the proxy's curves with curves common to both proxy and client
			if (conn_prx_is_client->session->tlsext_ellipticcurvelist) {
				OPENSSL_free(conn_prx_is_client->session->tlsext_ellipticcurvelist);
			}
			conn_prx_is_client->session->tlsext_ellipticcurvelist = BUF_memdup(
					s->session->tlsext_ellipticcurvelist,
					s->session->tlsext_ellipticcurvelist_length);
			conn_prx_is_client->session->tlsext_ellipticcurvelist_length =
					s->session->tlsext_ellipticcurvelist_length;
		}
	}
#endif

	// NPN
#ifndef OPENSSL_NO_NEXTPROTONEG
	// proxy will mirror client's indication for NPN support
	conn_prx_is_client->s3->next_proto_neg_seen =
			s->s3->next_proto_neg_seen;
#endif

	// ALPN
	if (s->s3->alpn_selected) {
		conn_prx_is_client->s3->alpn_selected = BUF_memdup(
				s->s3->alpn_selected, strlen((char*) s->s3->alpn_selected));
		conn_prx_is_client->s3->alpn_selected_len = s->s3->alpn_selected_len;
	}

 done:
 	// and return
	return 1;
}

/*
 * This method is called when a ClientHello message is received
 * from the client. It copies some information into the other
 * connection and specially handles extension data.
 *
 * IMPORTANT CONTRACT: this method MUST guarantee that either both
 * sessions are being resumed or none.
 */
int tls12_prx_srvr_hll_rcvd_cb(SSL* s)
{
	/*
	 * Note:
	 * 1) Final decision about inspection will come after receiving
	 * ServerHelloDone from server.
	 * 2) 's' is 'conn_prx_is_client'.
	 */

	// proxy will mirror the server's random data
	memcpy(&(conn_prx_is_server->s3->server_random[0]),
			&(s->s3->server_random[0]), SSL3_RANDOM_SIZE);

	// proxy can't allow different types of handshakes in the sessions
	// Note: the inverse case shouldn't be reachable (see the previous function)
	if (conn_prx_is_server->hit && !s->hit) {
		/*
		 * We tried to resume and server responded with a new session.
		 * Proxy MUST behave exactly the same way.
		 */
		if (!ssl_get_new_session(conn_prx_is_server, 1)) {
			tls12_prx_terminate_both(SSL_AD_INTERNAL_ERROR, SSL_AD_INTERNAL_ERROR);
			return 0;
		}
	}

	// if server responds with a one-time session, proxy must mirror
	if (s->session->session_id_length == 0) {
		conn_prx_is_server->session->session_id_length = 0;
		memset(&(conn_prx_is_server->session[0]), 0, SSL_MAX_SSL_SESSION_ID_LENGTH);
	} else {
		/*
		 * Both sessions should have a session ID and we only
		 * have to handle mapping now.
		 */
		int clnt_sess_mapped = SSL_SESSION_is_mapped(conn_prx_is_server->session);
		int srvr_sess_mapped = SSL_SESSION_is_mapped(conn_prx_is_client->session);
		if (clnt_sess_mapped != srvr_sess_mapped) {
			// something weird is going on...
			tls12_prx_terminate_both(SSL_AD_INTERNAL_ERROR, SSL_AD_INTERNAL_ERROR);
			return 0;
		} else if (!clnt_sess_mapped) {
			// ensure that both session are mapped correctly
			memcpy(
					&(conn_prx_is_server->session->mapped_sid[0]), // to
					&(conn_prx_is_client->session->session_id[0]), // from
					SSL_MAX_SSL_SESSION_ID_LENGTH
			);
			memcpy(
					&(conn_prx_is_client->session->mapped_sid[0]), // to
					&(conn_prx_is_server->session->session_id[0]), // from
					SSL_MAX_SSL_SESSION_ID_LENGTH
			);
		} else {
			// confirm bijection
			int clnt_to_srvr_cmp = strcmp(
					(char*) &(conn_prx_is_server->session->mapped_sid[0]),
					(char*) &(conn_prx_is_client->session->session_id[0]));
			int srvr_to_clnt_cmp = strcmp(
					(char*) &(conn_prx_is_client->session->mapped_sid[0]),
					(char*) &(conn_prx_is_server->session->session_id[0]));
			if ((clnt_to_srvr_cmp != 0) || (srvr_to_clnt_cmp != 0)) {
				// something weird is going on...
				tls12_prx_terminate_both(SSL_AD_INTERNAL_ERROR, SSL_AD_INTERNAL_ERROR);
				return 0;
			}
		}
	}

	// time to stop if we only forward communication
	if (tls12_prx_only_forward_comm()) {
		goto done;
	}

	/*
	 * Copy important extension data if we're not just forwarding.
	 *
	 * Note: secure renegotiation, tickets and heartbeat extensions
	 * should be completely independent - don't copy any of related data.
	 */

	// server name indication
	conn_prx_is_server->servername_done = s->servername_done;
	if (!s->hit && s->tlsext_hostname &&
			!conn_prx_is_server->session->tlsext_hostname) {
		conn_prx_is_server->session->tlsext_hostname =
				BUF_strdup(s->session->tlsext_hostname);
	}

	/*
	 * Status extension - despite we copy the indicator, proxy can still
	 * simply omit the CertificateStatus message. TODO: eventually, the
	 * indicator should be independent of the server.
	 */
	conn_prx_is_server->tlsext_status_expected = s->tlsext_status_expected;

	// ellyptic curve cryptography
	if (!s->hit && s->session->tlsext_ecpointformatlist) {
		// first delete client's curves
		if (conn_prx_is_server->session->tlsext_ecpointformatlist) {
			OPENSSL_free(conn_prx_is_server->session->tlsext_ecpointformatlist);
		}

		// and then overwrite them with server's curves
		conn_prx_is_server->session->tlsext_ecpointformatlist = BUF_memdup(
				s->session->tlsext_ecpointformatlist,
				s->session->tlsext_ecpointformatlist_length);
		conn_prx_is_server->session->tlsext_ecpointformatlist_length =
				s->session->tlsext_ecpointformatlist_length;
	}

	// NPN
# ifndef OPENSSL_NO_NEXTPROTONEG
	// TODO: handling of this extension is wrong - proxy needs to copy
	// and forward server's response...
	if (s->next_proto_negotiated) {
		// first delete client's record
		if (conn_prx_is_server->next_proto_negotiated) {
			OPENSSL_free(conn_prx_is_server->s3->alpn_selected);
		}

		// and then overwrite it with server's record
		conn_prx_is_server->next_proto_negotiated = BUF_memdup(
				s->next_proto_negotiated, s->next_proto_negotiated_len);
		conn_prx_is_server->next_proto_negotiated_len =
				s->next_proto_negotiated_len;
	}
	// TODO: for now, don't send any response...
	conn_prx_is_server->s3->next_proto_neg_seen = 0;
# endif

	// ALPN
    if (s->s3->alpn_selected) {
    	// first delete client's record
    	if (conn_prx_is_server->s3->alpn_selected) {
    		OPENSSL_free(conn_prx_is_server->s3->alpn_selected);
    	}

    	// and then overwrite it with server's record
    	conn_prx_is_server->s3->alpn_selected = BUF_memdup(
    			s->s3->alpn_selected, s->s3->alpn_selected_len);
    	conn_prx_is_server->s3->alpn_selected_len =
    			s->s3->alpn_selected_len;
    }

 done:
 	// and return
    return 1;
}

/*
 * This method is called when a Certificate message is received
 * from the server.
 * Note: unreachable if communication is forwarded.
 */
int tls12_prx_srvr_crt_rcvd_cb(SSL* s)
{
	// copy the certificate into the other connection
	if (conn_prx_is_server->session->peer_cert) {
		ssl_sess_cert_free(conn_prx_is_server->session->peer_cert);
	}
	conn_prx_is_server->session->end_cert = BUF_memdup(
			conn_prx_is_client->session->peer_cert, sizeof(SESS_CERT));

	// and return
	return 1;
}

/*
 * This method is called when a CertificateRequest message is received
 * from the server.
 * Note: unreachable if communication is forwarded.
 */
int tls12_prx_crt_rqst_rcvd_cb(SSL* s)
{
	// copy client authentication requirement into the other connection
	conn_prx_is_server->s3->tmp.cert_request = s->s3->tmp.cert_req;

	// client authentication imposes special behavior
	if (s->s3->tmp.cert_req) {
		/*
		 * Note: the CertificateRequest message can only be received
		 * in full handshake so no need to check 's->hit'.
		 */

		/*
		 * Mirror the server's (EC)DHE parameters, if needed.
		 *
		 * Independent key exchange negotiation IS a simpler alternative but at the moment,
		 * it isn't supported.
		 */
		unsigned long targetK = s->s3->tmp.new_cipher->algorithm_mkey;
		if (targetK & SSL_kDHE) {
			// for DHE key exchange, proxy MUST mirror the server's parameters
			if (conn_prx_is_server->s3->tmp.dh) {
				// this should never happen but just in case...
				DH_free(conn_prx_is_server->s3->tmp.dh);
			}
			conn_prx_is_server->s3->tmp.dh = DHparams_dup(
					SSL_get_peer_DHE_tmp_pubkey(s));
			if (!conn_prx_is_server->s3->tmp.dh) {
				// this should never happen but just in case...
				tls12_prx_terminate_both(SSL_AD_INTERNAL_ERROR, SSL_AD_INTERNAL_ERROR);
				return 0;
			}
		} else if (targetK & SSL_kECDHE) {
			// for ECDHE key exchange, proxy MUST mirror the server's parameters
			if (conn_prx_is_server->s3->tmp.ecdh) {
				// this should never happen but just in case...
				EC_KEY_free(conn_prx_is_server->s3->tmp.ecdh);
			}
			conn_prx_is_server->s3->tmp.ecdh = SSL_get_peer_ECDHE_tmp_pubkey(s);
		}

		/*
		 * Proxy must re-pick the cipher suite for client. One was selected after receiving
		 * ClientHello but the server changed circumstances with client authentication.
		 * Newly selected cipher suite must be compatible with the server's chosen cipher
		 * suite, e.g. it must use identical key exchange algorithm and cryptographic hash
		 * function.
		 *
		 * Independent key exchange negotiation IS a simpler alternative but at the moment,
		 * it isn't supported.
		 */

		// filter the proxy's cipher list accordingly
		STACK_OF(SSL_CIPHER)* stack = sk_SSL_CIPHER_dup(s->session->ciphers);
		const unsigned long targetCode = SSL_get_hash_code_from_cipher(s->s3->tmp.new_cipher);
		for (int i = sk_SSL_CIPHER_num(stack) - 1; i >= 0; i--) {
			SSL_CIPHER* c = sk_SSL_CIPHER_value(stack, i);
			if ((c->algorithm_mkey != targetK) || (SSL_get_hash_code_from_cipher(c) != targetCode)) {
				sk_SSL_CIPHER_delete(stack, i);
			}
		}

		// at least one cipher suite MUST remain
		if (sk_SSL_CIPHER_num(stack) == 0) {
			// should never happen (server chooses cipher suite from the original list)...
			tls12_prx_terminate_both(SSL_AD_INTERNAL_ERROR, SSL_AD_INTERNAL_ERROR);
			return 0;
		}

		// and finally, pick a cipher suite for client
		conn_prx_is_server->s3->tmp.new_cipher = ssl3_choose_cipher(
				conn_prx_is_server,
				conn_prx_is_server->session->ciphers,
				stack
		);

		// check result
		if (conn_prx_is_server->s3->tmp.new_cipher == NULL) {
			tls12_prx_terminate_both(SSL_AD_HANDSHAKE_FAILURE, SSL_AD_HANDSHAKE_FAILURE);
			return 0;
		}
	}

	// and return
	return 1;
}

/*
 * This method is called when a Certificate message is received
 * from the client.
 * Note: unreachable if communication is forwarded.
 */
int tls12_prx_clnt_crt_rcvd_cb(SSL* s)
{
	/*
	 * At this point, we know that server demanded client authentication
	 * and we don't need to check.
	 * In reaction, we must copy the proxy's public key for client, and
	 * also use it as public key for server. In addition, copy related
	 * and required information.
	 */

	// first assert that proxy mirrors key exchange algorithm
	long alg_k_client = conn_prx_is_server->s3->tmp.new_cipher->algorithm_mkey;
	long alg_k_server = conn_prx_is_client->s3->tmp.new_cipher->algorithm_mkey;
	if (alg_k_client != alg_k_server) {
		return 0;
	}
	/*
	 * When we send ClientKeyExchange later, it must contain the pre-generated
	 * key that we sent in ServerKeyExchange.
	 */
	else if (alg_k_server & SSL_kRSA) {
		// copy pointers; later, we shall reset to avoid double-free
		conn_prx_is_client->proxy_pubkey_tmp = conn_prx_is_server->proxy_pubkey_tmp;
		conn_prx_is_client->proxy_pubkey_tmp_len = conn_prx_is_server->proxy_pubkey_tmp_len;

		// not a genuine master secret but rather temp storage for premaster secret
		memcpy(
				&(conn_prx_is_client->session->master_key[0]), // to
				&(conn_prx_is_server->session->master_key[0]), // from
				SSL_MAX_MASTER_KEY_LENGTH
		);

		// client-side session doesn't need the other session's premaster secret
		OPENSSL_cleanse(conn_prx_is_server->session->master_key,
				SSL_MAX_MASTER_KEY_LENGTH);
	} else if (alg_k_server & SSL_kEDH) {
		// copy pointers; later, we shall reset to avoid double-free
		conn_prx_is_client->s3->tmp.dh = conn_prx_is_server->s3->tmp.dh;
	} else if (alg_k_server & SSL_kEECDH) {
		// copy pointers; later, we shall reset to avoid double-free
		conn_prx_is_client->s3->tmp.ecdh = conn_prx_is_server->s3->tmp.ecdh;
	}

	// and return
	return 1;
}
