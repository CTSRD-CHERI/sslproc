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

/* Types */

#define	SSL_CONF_CTX		PSSL_CONF_CTX
#define	SSL_METHOD		PSSL_METHOD
#define	SSL_CIPHER		PSSL_CIPHER
#define	SSL_SESSION		PSSL_SESSION
#define	SSL_CTX			PSSL_CTX
#define	SSL			PSSL

/* SSL_CONF_CTX */

#define	SSL_CONF_CTX_new	PSSL_CONF_CTX_new
#define	SSL_CONF_CTX_finish	PSSL_CONF_CTX_finish
#define	SSL_CONF_CTX_free	PSSL_CONF_CTX_free
#define	SSL_CONF_CTX_set_flags	PSSL_CONF_CTX_set_flags
#define	SSL_CONF_cmd_value_type	PSSL_CONF_cmd_value_type
#define	SSL_CONF_cmd		PSSL_CONF_cmd
#define	SSL_CONF_CTX_set_ssl_ctx	PSSL_CONF_CTX_set_ssl_ctx

/* SSL_METHOD */

#define	TLS_method		PTLS_method
#define	TLS_server_method	PTLS_server_method
#define	TLS_client_method	PTLS_client_method

/* SSL_CIPHER */

#define	SSL_CIPHER_get_name	PSSL_CIPHER_get_name
#define	SSL_CIPHER_get_bits	PSSL_CIPHER_get_bits
#define	sk_SSL_CIPHER_dup	sk_PSSL_CIPHER_dup
#define	sk_SSL_CIPHER_find	sk_PSSL_CIPHER_find
#define	sk_SSL_CIPHER_free	sk_PSSL_CIPHER_free
#define	sk_SSL_CIPHER_num	sk_PSSL_CIPHER_num
#define	sk_SSL_CIPHER_value	sk_PSSL_CIPHER_value

/* SSL_SESSION */

#define	SSL_SESSION_new		PSSL_SESSION_new
#define	SSL_SESSION_up_ref	PSSL_SESSION_up_ref
#define	SSL_SESSION_free	PSSL_SESSION_free
#define	SSL_SESSION_get_id	PSSL_SESSION_get_id
#define	SSL_SESSION_get_compress_id	PSSL_SESSION_get_compress_id
#define	SSL_SESSION_get_time	PSSL_SESSION_get_time
#define	SSL_SESSION_set_timeout	PSSL_SESSION_set_timeout
#define	d2i_SSL_SESSION		d2i_PSSL_SESSION
#define	i2d_SSL_SESSION		i2d_PSSL_SESSION

/* SSL_CTX */

#define	SSL_CTX_new		PSSL_CTX_new
#define	SSL_CTX_up_ref		PSSL_CTX_up_ref
#define	SSL_CTX_free		PSSL_CTX_free
#define	SSL_CTX_set_options	PSSL_CTX_set_options
#define	SSL_CTX_clear_options	PSSL_CTX_clear_options
#define	SSL_CTX_get_options	PSSL_CTX_get_options
#define	SSL_CTX_ctrl		PSSL_CTX_ctrl
#define	SSL_CTX_callback_ctrl	PSSL_CTX_callback_ctrl
#define	SSL_CTX_set_ex_data	PSSL_CTX_set_ex_data
#define	SSL_CTX_get_ex_data	PSSL_CTX_get_ex_data
#define	SSL_CTX_use_certificate	PSSL_CTX_use_certificate
#define	SSL_CTX_use_certificate_ASN1	PSSL_CTX_use_certificate_ASN1
#define	SSL_CTX_use_certificate_file	PSSL_CTX_use_certificate_file
#define	SSL_CTX_use_PrivateKey	PSSL_CTX_use_PrivateKey
#define	SSL_CTX_use_PrivateKey_ASN1	PSSL_CTX_use_PrivateKey_ASN1
#define	SSL_CTX_use_PrivateKey_file	PSSL_CTX_use_PrivateKey_file
#define	SSL_CTX_check_private_key	PSSL_CTX_check_private_key
#define	SSL_client_hello_cb_fn	PSSL_client_hello_cb_fn
#define	SSL_CTX_set_client_hello_cb	PSSL_CTX_set_client_hello_cb
#define	SSL_CTX_set_srp_username_callback PSSL_CTX_set_srp_username_callback
#define	SSL_CTX_set_srp_cb_arg	PSSL_CTX_set_srp_cb_arg
#define	SSL_CTX_sess_set_new_cb	PSSL_CTX_sess_set_new_cb
#define	SSL_CTX_sess_set_remove_cb	PSSL_CTX_sess_set_remove_cb
#define	SSL_CTX_sess_set_get_cb	PSSL_CTX_sess_set_get_cb
#define	SSL_CTX_set_tmp_dh_callback	PSSL_CTX_set_tmp_dh_callback
#define	SSL_CTX_set_info_callback	PSSL_CTX_set_info_callback
#define	SSL_CTX_alpn_select_cb_func	PSSL_CTX_alpn_select_cb_func
#define	SSL_CTX_set_alpn_select_cb	PSSL_CTX_set_alpn_select_cb
#define	SSL_CTX_set_cipher_list	PSSL_CTX_set_cipher_list
#define	SSL_CTX_set_ciphersuites	PSSL_CTX_set_ciphersuites
#define	SSL_CTX_set_timeout	PSSL_CTX_set_timeout
#define	SSL_CTX_get0_certificate	PSSL_CTX_get0_certificate
#define	SSL_CTX_set_client_cert_cb	PSSL_CTX_set_client_cert_cb
#define	SSL_verify_cb		PSSL_verify_cb
#define	SSL_CTX_set_verify	PSSL_CTX_set_verify
#define	SSL_CTX_get_verify_callback	PSSL_CTX_get_verify_callback
#define	SSL_CTX_get_verify_mode	PSSL_CTX_get_verify_mode
#define	SSL_CTX_load_verify_locations	PSSL_CTX_load_verify_locations
#define	SSL_CTX_get_cert_store	PSSL_CTX_get_cert_store
#define	SSL_CTX_set_client_CA_list	PSSL_CTX_set_client_CA_list
#define	SSL_CTX_get_client_CA_list	PSSL_CTX_get_client_CA_list
#define	SSL_CTX_set_default_passwd_cb	PSSL_CTX_set_default_passwd_cb
#define	SSL_CTX_set_default_passwd_cb_userdata	PSSL_CTX_set_default_passwd_cb_userdata
#define	SSL_CTX_use_certificate_chain_file	PSSL_CTX_use_certificate_chain_file
#define	SSL_CTX_set_post_handshake_auth	PSSL_CTX_set_post_handshake_auth

/* SSL */

#define	SSL_new			PSSL_new
#define	SSL_up_ref		PSSL_up_ref
#define	SSL_free		PSSL_free
#define	SSL_set_options		PSSL_set_options
#define	SSL_clear_options	PSSL_clear_options
#define	SSL_get_options		PSSL_get_options
#define	SSL_ctrl		PSSL_ctrl
#define	SSL_set_ex_data		PSSL_set_ex_data
#define	SSL_get_ex_data		PSSL_get_ex_data
#define	SSL_use_certificate	PSSL_use_certificate
#define	SSL_use_certificate_ASN1	PSSL_use_certificate_ASN1
#define	SSL_use_certificate_file	PSSL_use_certificate_file
#define	SSL_use_PrivateKey	PSSL_use_PrivateKey
#define	SSL_use_PrivateKey_ASN1	PSSL_use_PrivateKey_ASN1
#define	SSL_use_PrivateKey_file	PSSL_use_PrivateKey_file
#define	SSL_check_private_key	PSSL_check_private_key
#define	SSL_get_SSL_CTX		PSSL_get_SSL_CTX
#define	SSL_set_SSL_CTX		PSSL_set_SSL_CTX
#define	SSL_get_peer_certificate	PSSL_get_peer_certificate
#define	SSL_get_verify_result	PSSL_get_verify_result
#define	SSL_set_verify_result	PSSL_set_verify_result
#define	SSL_get_verify_mode	PSSL_get_verify_mode
#define	SSL_get_verify_depth	PSSL_get_verify_depth
#define	SSL_set_verify		PSSL_set_verify
#define	SSL_verify_client_post_handshake	PSSL_verify_client_post_handshake
#define	SSL_set_alpn_protos	PSSL_set_alpn_protos
#define	SSL_set_cipher_list	PSSL_set_cipher_list
#define	SSL_set_ciphersuites	PSSL_set_ciphersuites
#define	SSL_set_srp_server_param	PSSL_set_srp_server_param
#define	SSL_get_srp_username	PSSL_get_srp_username
#define	SSL_get_srp_userinfo	PSSL_get_srp_userinfo
#define	SSL_get_current_cipher	PSSL_get_current_cipher
#define	SSL_get_pending_cipher	PSSL_get_pending_cipher
#define	SSL_set_session_id_context	PSSL_set_session_id_context
#define	SSL_set_msg_callback	PSSL_set_msg_callback
#define	SSL_get_rbio		PSSL_get_rbio
#define	SSL_get_wbio		PSSL_get_wbio
#define	SSL_set_bio		PSSL_set_bio
#define	SSL_set0_rbio		PSSL_set0_rbio
#define	SSL_set0_wbio		PSSL_set0_wbio
#define	SSL_get_error		PSSL_get_error
#define	SSL_set_connect_state	PSSL_set_connect_state
#define	SSL_set_accept_state	PSSL_set_accept_state
#define	SSL_is_server		PSSL_is_server
#define	SSL_do_handshake	PSSL_do_handshake
#define	SSL_accept		PSSL_accept
#define	SSL_connect		PSSL_connect
#define	SSL_in_init		PSSL_in_init
#define	SSL_in_before		PSSL_in_before
#define	SSL_is_init_finished	PSSL_is_init_finished
#define	SSL_client_version	PSSL_client_version
#define	SSL_get_version		PSSL_get_version
#define	SSL_version		PSSL_version
#define	SSL_get_servername	PSSL_get_servername
#define	SSL_get_servername_type	PSSL_get_servername_type
#define	SSL_read		PSSL_read
#define	SSL_peek		PSSL_peek
#define	SSL_write		PSSL_write
#define	SSL_set_shutdown	PSSL_set_shutdown
#define	SSL_get_shutdown	PSSL_get_shutdown
#define	SSL_shutdown		PSSL_shutdown
#define	SSL_get_ex_data_X509_STORE_CTX_idx PSSL_get_ex_data_X509_STORE_CTX_idx
#define	SSL_set_default_passwd_cb	PSSL_set_default_passwd_cb
#define	SSL_set_default_passwd_cb_userdata	PSSL_set_default_passwd_cb_userdata
#define	SSL_use_certificate_chain_file	PSSL_use_certificate_chain_file
#define	SSL_get_ciphers		PSSL_get_ciphers
#define	SSL_get_peer_cert_chain	PSSL_get_peer_cert_chain
#define	SSL_renegotiate		PSSL_renegotiate
#define	SSL_get_privatekey	PSSL_get_privatekey
#define	SSL_get_client_CA_list	PSSL_get_client_CA_list
#define	SSL_state_string_long	PSSL_state_string_long
#define	SSL_client_hello_get0_ext	PSSL_client_hello_get0_ext
