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

#undef SSL_CONF_CTX
#undef SSL_METHOD
#undef SSL_CIPHER
#undef SSL_SESSION
#undef SSL_CTX
#undef SSL

/* SSL_CONF_CTX */

#undef SSL_CONF_CTX_new
#undef SSL_CONF_CTX_finish
#undef SSL_CONF_CTX_free
#undef SSL_CONF_CTX_set_flags
#undef SSL_CONF_cmd_value_type
#undef SSL_CONF_cmd
#undef SSL_CONF_CTX_set_ssl_ctx

/* SSL_METHOD */

#undef TLS_method
#undef TLS_server_method
#undef TLS_client_method

/* SSL_CIPHER */

#undef SSL_CIPHER_get_name
#undef SSL_CIPHER_get_bits
#undef sk_SSL_CIPHER_dup
#undef sk_SSL_CIPHER_find
#undef sk_SSL_CIPHER_free
#undef sk_SSL_CIPHER_num
#undef sk_SSL_CIPHER_value

/* SSL_SESSION */

#undef SSL_SESSION_new
#undef SSL_SESSION_up_ref
#undef SSL_SESSION_free
#undef SSL_SESSION_get_id
#undef SSL_SESSION_get_compress_id
#undef SSL_SESSION_get_time
#undef d2i_SSL_SESSION
#undef i2d_SSL_SESSION

/* SSL_CTX */

#undef SSL_CTX_new
#undef SSL_CTX_up_ref
#undef SSL_CTX_free
#undef SSL_CTX_set_options
#undef SSL_CTX_clear_options
#undef SSL_CTX_get_options
#undef SSL_CTX_ctrl
#undef SSL_CTX_callback_ctrl
#undef SSL_CTX_set_ex_data
#undef SSL_CTX_get_ex_data
#undef SSL_CTX_use_certificate
#undef SSL_CTX_use_certificate_ASN1
#undef SSL_CTX_use_certificate_file
#undef SSL_CTX_use_PrivateKey
#undef SSL_CTX_use_PrivateKey_ASN1
#undef SSL_CTX_use_PrivateKey_file
#undef SSL_CTX_check_private_key
#undef SSL_client_hello_cb_fn
#undef SSL_CTX_set_client_hello_cb
#undef SSL_CTX_set_srp_username_callback
#undef SSL_CTX_set_srp_cb_arg
#undef SSL_CTX_sess_set_new_cb
#undef SSL_CTX_sess_set_remove_cb
#undef SSL_CTX_sess_set_get_cb
#undef SSL_CTX_set_tmp_dh_callback
#undef SSL_CTX_set_info_callback
#undef SSL_CTX_alpn_select_cb_func
#undef SSL_CTX_set_alpn_select_cb
#undef SSL_CTX_set_cipher_list
#undef SSL_CTX_set_ciphersuites
#undef SSL_CTX_set_timeout
#undef SSL_CTX_get0_certificate
#undef SSL_CTX_set_client_cert_cb
#undef SSL_verify_cb
#undef SSL_CTX_set_verify
#undef SSL_CTX_load_verify_locations
#undef SSL_CTX_get_cert_store
#undef SSL_CTX_set_client_CA_list
#undef SSL_CTX_get_client_CA_list
#undef SSL_CTX_set_default_passwd_cb
#undef SSL_CTX_set_default_passwd_cb_userdata
#undef SSL_CTX_use_certificate_chain_file
#undef SSL_CTX_set_post_handshake_auth

/* SSL */

#undef SSL_new
#undef SSL_up_ref
#undef SSL_free
#undef SSL_set_options
#undef SSL_clear_options
#undef SSL_get_options
#undef SSL_ctrl
#undef SSL_set_ex_data
#undef SSL_get_ex_data
#undef SSL_use_certificate
#undef SSL_use_certificate_ASN1
#undef SSL_use_certificate_file
#undef SSL_get_SSL_CTX
#undef SSL_set_SSL_CTX
#undef SSL_get_peer_certificate
#undef SSL_get_verify_result
#undef SSL_set_verify_result
#undef SSL_get_verify_mode
#undef SSL_get_verify_depth
#undef SSL_set_verify
#undef SSL_verify_client_post_handshake
#undef SSL_set_alpn_protos
#undef SSL_set_cipher_list
#undef SSL_set_ciphersuites
#undef SSL_get_srp_username
#undef SSL_get_srp_userinfo
#undef SSL_get_current_cipher
#undef SSL_get_pending_cipher
#undef SSL_set_session_id_context
#undef SSL_set_msg_callback
#undef SSL_get_rbio
#undef SSL_get_wbio
#undef SSL_set_bio
#undef SSL_set0_rbio
#undef SSL_set0_wbio
#undef SSL_get_error
#undef SSL_set_connect_state
#undef SSL_set_accept_state
#undef SSL_is_server
#undef SSL_do_handshake
#undef SSL_accept
#undef SSL_connect
#undef SSL_in_init
#undef SSL_in_before
#undef SSL_is_init_finished
#undef SSL_client_version
#undef SSL_get_version
#undef SSL_version
#undef SSL_get_servername
#undef SSL_get_servername_type
#undef SSL_read
#undef SSL_peek
#undef SSL_write
#undef SSL_set_shutdown
#undef SSL_get_shutdown
#undef SSL_shutdown
#undef SSL_get_ex_data_X509_STORE_CTX_idx
#undef SSL_set_default_passwd_cb
#undef SSL_set_default_passwd_cb_userdata
#undef SSL_use_certificate_chain_file
#undef SSL_get_ciphers
#undef SSL_get_peer_cert_chain
#undef SSL_renegotiate
#undef SSL_get_privatekey
#undef SSL_get_client_CA_list
