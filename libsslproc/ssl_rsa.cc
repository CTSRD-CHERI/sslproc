/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Borrowed from ssl_rsa.c in OpenSSL.
 */

#include <openssl/ssl.h>

#include "sslproc.h"
#include "sslproc_internal.h"

/*
 * Read a file that contains our certificate in "PEM" format, possibly
 * followed by a sequence of CA certificates that should be sent to the peer
 * in the Certificate message.
 */
static int use_certificate_chain_file(PSSL_CTX *ctx, PSSL *ssl, const char *file)
{
    BIO *in;
    int ret = 0;
    X509 *x = NULL;
    pem_password_cb *passwd_callback;
    void *passwd_callback_userdata;

    ERR_clear_error();          /* clear error stack for
                                 * SSL_CTX_use_certificate() */

    if (ctx != NULL) {
        passwd_callback = ctx->default_passwd_cb;
        passwd_callback_userdata = ctx->default_passwd_cb_userdata;
    } else {
        passwd_callback = ssl->default_passwd_cb;
        passwd_callback_userdata = ssl->default_passwd_cb_userdata;
    }

    in = BIO_new(BIO_s_file());
    if (in == NULL) {
	PROCerr(PROC_F_USE_CERTIFICATE_CHAIN_FILE, ERR_R_BUF_LIB);
        goto end;
    }

    if (BIO_read_filename(in, file) <= 0) {
        PROCerr(PROC_F_USE_CERTIFICATE_CHAIN_FILE, ERR_R_SYS_LIB);
        goto end;
    }

    x = PEM_read_bio_X509_AUX(in, NULL, passwd_callback,
                              passwd_callback_userdata);
    if (x == NULL) {
        PROCerr(PROC_F_USE_CERTIFICATE_CHAIN_FILE, ERR_R_PEM_LIB);
        goto end;
    }

    if (ctx)
        ret = PSSL_CTX_use_certificate(ctx, x);
    else
        ret = PSSL_use_certificate(ssl, x);

    if (ERR_peek_error() != 0)
        ret = 0;                /* Key/certificate mismatch doesn't imply
                                 * ret==0 ... */
    if (ret) {
        /*
         * If we could set up our certificate, now proceed to the CA
         * certificates.
         */
        X509 *ca;
        int r;
        unsigned long err;

        if (ctx)
            r = PSSL_CTX_clear_chain_certs(ctx);
        else
            r = PSSL_clear_chain_certs(ssl);

        if (r == 0) {
            ret = 0;
            goto end;
        }

        while ((ca = PEM_read_bio_X509(in, NULL, passwd_callback,
                                       passwd_callback_userdata))
               != NULL) {
            if (ctx)
                r = PSSL_CTX_add0_chain_cert(ctx, ca);
            else
                r = PSSL_add0_chain_cert(ssl, ca);
            /*
             * Note that we must not free ca if it was successfully added to
             * the chain (while we must free the main certificate, since its
             * reference count is increased by SSL_CTX_use_certificate).
             */
            if (!r) {
                X509_free(ca);
                ret = 0;
                goto end;
            }
        }
        /* When the while loop ends, it's usually just EOF. */
        err = ERR_peek_last_error();
        if (ERR_GET_LIB(err) == ERR_LIB_PEM
            && ERR_GET_REASON(err) == PEM_R_NO_START_LINE)
            ERR_clear_error();
        else
            ret = 0;            /* some real error */
    }

 end:
    X509_free(x);
    BIO_free(in);
    return ret;
}

int PSSL_CTX_use_certificate_chain_file(PSSL_CTX *ctx, const char *file)
{
    return use_certificate_chain_file(ctx, NULL, file);
}

int PSSL_use_certificate_chain_file(PSSL *ssl, const char *file)
{
    return use_certificate_chain_file(NULL, ssl, file);
}
