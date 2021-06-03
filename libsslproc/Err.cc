/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2021 SRI International
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
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
 */

#include <openssl/err.h>

#include "sslproc.h"
#include "sslproc_internal.h"

int PROC_lib;

static ERR_STRING_DATA PROC_strings[] = {
	{0, "sslproc"},
	{ERR_PACK(0, PROC_F_SSL_CTX_NEW, 0), "PSSL_CTX_new"},
	{ERR_PACK(0, PROC_F_READ_MESSAGE, 0), "MessageSocket::readMessage"},
	{ERR_PACK(0, PROC_F_WRITE_MESSAGE, 0), "MessageSocket::writeMessage"},
	{ERR_PACK(0, PROC_F_RECVMSG, 0), "recvmsg"},
	{ERR_PACK(0, PROC_F_WAIT_FOR_REPLY, 0),
	 "LibMessageSocket::waitForReply"},
	{ERR_PACK(0, PROC_F_SET_MESSAGE_ERROR, 0),
	 "LibMessageSocket::setMessageError"},
	{ERR_PACK(0, PROC_F_SSL_NEW, 0), "PSSL_new"},
	{ERR_PACK(0, PROC_F_SSL_CTX_USE_CERTIFICATE, 0),
	 "PSSL_CTX_use_certificate"},
	{ERR_PACK(0, PROC_F_SSL_CTX_USE_CERTIFICATE_ASN1, 0),
	 "PSSL_CTX_use_certificate_ASN1"},
	{ERR_PACK(0, PROC_F_SSL_CTX_USE_CERTIFICATE_FILE, 0),
	 "PSSL_CTX_use_certificate_file"},
	{ERR_PACK(0, PROC_F_SSL_CTX_USE_PRIVATEKEY, 0),
	 "PSSL_CTX_use_PrivateKey"},
	{ERR_PACK(0, PROC_F_SSL_CTX_USE_PRIVATEKEY_ASN1, 0),
	 "PSSL_CTX_use_PrivateKey_ASN1"},
	{ERR_PACK(0, PROC_F_SSL_CTX_USE_PRIVATEKEY_FILE, 0),
	 "PSSL_CTX_use_PrivateKey_file"},
	{ERR_PACK(0, PROC_F_CMDSOCK_HANDLE_MESSAGE, 0),
	 "CommandSocket::handleMessage"},
	{ERR_PACK(0, PROC_F_SSL_READ, 0), "PSSL_read"},
	{ERR_PACK(0, PROC_F_D2I_SSL_SESSION, 0), "d2i_PSSL_SESSION"},
	{ERR_PACK(0, PROC_F_SSL_CTX_SET_CIPHER_LIST, 0),
	 "PSSL_CTX_set_cipher_list"},
	{ERR_PACK(0, PROC_F_SSL_CTX_SET_CIPHERSUITES, 0),
	 "PSSL_CTX_set_ciphersuites"},
	{ERR_PACK(0, PROC_F_CONTROLSOCKET_INIT, 0), "ControlSocket_init"},
	{ERR_PACK(0, PROC_F_CREATECOMMANDSOCKET, 0), "createCommandSocket"},
	{ERR_PACK(0, PROC_F_SSL_CTX_CTRL, 0), "PSSL_CTX_ctrl"},
	{ERR_PACK(0, PROC_F_SSL_CTX_CHECK_PRIVATE_KEY, 0),
	 "PSSL_CTX_check_private_key"},
	{ERR_PACK(0, PROC_F_SSL_CTX_SET_SRP_USERNAME_CALLBACK, 0),
	 "PSSL_CTX_set_srp_username_callback"},
	{ERR_PACK(0, PROC_F_SSL_CTX_GET0_CERTIFICATE, 0),
	 "PSSL_CTX_get0_certificate"},
	{ERR_PACK(0, PROC_F_SSL_CTRL, 0), "PSSL_ctrl"},
	{ERR_PACK(0, PROC_F_SSL_GET_PEER_CERTIFICATE, 0),
	 "PSSL_get_peer_certificate"},
	{ERR_PACK(0, PROC_F_SSL_GET_VERIFY_RESULT, 0),
	 "PSSL_get_verify_result"},
	{ERR_PACK(0, PROC_F_SSL_GET_SRP_USERNAME, 0), "PSSL_get_srp_username"},
	{ERR_PACK(0, PROC_F_SSL_GET_SRP_USERINFO, 0), "PSSL_get_srp_userinfo"},
	{ERR_PACK(0, PROC_F_SSL_FETCH_CIPHER, 0), "PSSL_fetch_cipher"},
	{ERR_PACK(0, PROC_F_SSL_SET_SESSION_ID_CONTEXT, 0),
	 "PSSL_set_session_id_context"},
	{ERR_PACK(0, PROC_F_SSL_DO_HANDSHAKE, 0), "PSSL_do_handshake"},
	{ERR_PACK(0, PROC_F_SSL_ACCEPT, 0), "PSSL_accept"},
	{ERR_PACK(0, PROC_F_SSL_CONNECT, 0), "PSSL_connect"},
	{ERR_PACK(0, PROC_F_SSL_GET_SERVERNAME, 0), "PSSL_get_servername"},
	{ERR_PACK(0, PROC_F_SSL_WRITE, 0), "PSSL_write"},
	{ERR_PACK(0, PROC_F_SSL_SHUTDOWN, 0), "PSSL_shutdown"},
	{ERR_PACK(0, PROC_F_SSL_SET_SSL_CTX, 0), "PSSL_set_SSL_CTX"},
	{ERR_PACK(0, 0, ERR_R_IO_ERROR), "I/O error"},
	{ERR_PACK(0, 0, ERR_R_BAD_MESSAGE), "invalid message"},
	{ERR_PACK(0, 0, ERR_R_UNEXPECTED_EOF), "unexpected EOF"},
	{ERR_PACK(0, 0, ERR_R_MISMATCHED_REPLY), "mismatched reply"},
	{ERR_PACK(0, 0, ERR_R_MESSAGE_ERROR), "message error"},
	{ERR_PACK(0, 0, ERR_R_BAD_VERSION), "invalid version"},
	{ERR_PACK(0, 0, ERR_R_NO_BUFFER), "out of message buffers"},
	{ERR_PACK(0, 0, ERR_R_MISSING_TARGET), "invalid target object"},
	{ERR_PACK(0, 0, ERR_R_NO_COMMAND_SOCKET), "no command socket"},
	{0, nullptr},
};

void
PERR_init(void)
{
	PROC_lib = ERR_get_next_error_library();

	/* We have to patch the library-wide entry by hand. */
	PROC_strings[0].error = ERR_PACK(PROC_lib, 0, 0);
	ERR_load_strings(PROC_lib, PROC_strings);
}
