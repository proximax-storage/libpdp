/**
 * @file
 * Implementation of the A-PDP module for S3 storage.
 *
 * @author Copyright (c) 2012, Mark Gondree
 * @author Copyright (c) 2012, Alric Althoff
 * @author Copyright (c) 2008, Zachary N J Peterson
 * @date 2008-2013
 * @copyright BSD 2-Clause License,
 *            See http://opensource.org/licenses/BSD-2-Clause
 **/
/** @addtogroup APDP
 * @{ 
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <pdp.h>
#include <pdp/apdp.h>
#include "apdp_misc.h"
#include "pdp_misc.h"


/**
 * @brief Returns the upper bound of the serialized token
 *
 * Each token is of the form:
 *  <Tag len, Tag, index, nonce len, nonce>
 **/
unsigned int apdp_serialized_tag_size(const pdp_ctx_t *ctx)
{
    pdp_apdp_ctx_t *p = NULL;

    if (!is_apdp(ctx)) return -1;
    p = ctx->apdp_param;

    return (sizeof(__uint32_t) + (p->rsa_key_size + 7)/8 + sizeof(unsigned int) +
            sizeof(__uint32_t) + p->prf_w_size);
}


/**
 * @brief Write out tag data to a buffer
 *
 * @todo This serialization is not portable.
 * @param[in]  ctx         context
 * @param[in]  t           pointer to input tag data
 * @param[in]  buffer      the buffer for the serialized data
 * @param[in]  buffer_len  length of space available, output bytes written
 * @return 0 on success, non-zero on error
 **/
int apdp_serialize_tags(const pdp_ctx_t *ctx, const pdp_apdp_tagdata_t* t,
                        unsigned char **buffer, unsigned int *buffer_len)
{
    pdp_apdp_ctx_t *p = NULL;
    pdp_apdp_tag_t *tag = NULL;
    unsigned char *buf_ptr = NULL;
    unsigned char *buf = NULL;
    unsigned char *tim = NULL;
    unsigned char *prf = NULL;
    size_t tag_size, prf_size, buf_len;
    size_t tim_size, tim_len = 0;
    int i, status = -1;
    __uint32_t value;

    if (!is_apdp(ctx) || !t || !buffer || !buffer_len ||
                         !t->tags || !t->tags_num || !t->tags_size)
        return -1;
    p = ctx->apdp_param;

    // some useful constants: upper bounds on sizes of things
    tag_size = apdp_serialized_tag_size(ctx);
    tim_size = (p->rsa_key_size + 7)/8; // Tim is max size log2(rsa->n)
    prf_size = p->prf_w_size;
    
    // Tag is <tim_len, Tim, index, index_prf_size, index_prf>
    buf_len = t->tags_num * tag_size;

    // allocate buffers
    if ((prf = malloc(prf_size)) == NULL) goto cleanup;
    if ((tim = malloc(tim_size)) == NULL) goto cleanup;
    if ((buf = malloc(buf_len)) == NULL) goto cleanup;
    memset(buf, 0, buf_len);
    buf_ptr = buf;

    for(i = 0; i < t->tags_num; i++) {
        tag = t->tags[i];
        if (!tag) goto cleanup;
        memset(tim, 0, tim_size);
        memset(prf, 0, prf_size);

        // get real Tim byte len
        tim_len = BN_num_bytes(tag->Tim);

        // make sure our assumptions re: bounds are correct
        if (tim_len > tim_size) goto cleanup;
        if (tag->index_prf_size > prf_size) goto cleanup;

        // write Tim size
        WRITE_UINT32(buf_ptr, tim_size)
        
        // write Tim
        if (!BN_bn2bin(tag->Tim, tim)) goto cleanup;
        memcpy(buf_ptr, tim, tim_size);
        buf_ptr += tim_size;

        // write index
        WRITE_UINT32(buf_ptr, tag->index)
        
        // write index_prf_size
        WRITE_UINT32(buf_ptr, tag->index_prf_size)

        // write index_prf
        memcpy(prf, tag->index_prf, tag->index_prf_size);
        memcpy(buf_ptr, prf, prf_size);
        buf_ptr += prf_size;

#ifdef _PDP_DEBUG
//        DEBUG(1, "\n Writing - ");
//        DEBUG(1, "\n Tag %02d", i);
//        DEBUG(1, "\n  Tim byte len [%02d]", BN_num_bytes(tag->Tim));
//        DEBUG(1, "\n  Tim (hex) [%s]", BN_bn2hex(tag->Tim));
//        DEBUG(1, "\n  index [%d]",  tag->index);
//        DEBUG(1, "\n  prf_size [%lud]", tag->index_prf_size);
//        pdp_hexdump("  prf", i, tag->index_prf, tag->index_prf_size);
//        pdp_hexdump(" Ser. tag", i, buf_ptr - tag_size, tag_size);
#endif // _PDP_DEBUG

    }

    *buffer = buf;
    *buffer_len = buf_len;
    status = 0;

cleanup:
    sfree(tim, tim_size);
    sfree(prf, prf_size);
    if (status && buf) {
        sfree(buf, buf_len);
        *buffer = NULL;
        *buffer_len = 0;
    }
    return status;
}


/**
 * @brief Read an individual tag
 * @param[in]  ctx      context
 * @param[out] tag      pointer to tag that will be populated
 * @param[in]  buf      serialized structure to process
 * @param[in]  buf_len  length of data to process
 * @return 0 on success, non-zero on error
 **/
int apdp_deserialize_tag(const pdp_ctx_t *ctx, pdp_apdp_tag_t* tag,
                         unsigned char *buf, unsigned int buf_len)
{
    pdp_apdp_ctx_t *p = NULL;
    unsigned char *buf_ptr = buf;
    unsigned char *tim = NULL;
    size_t tag_size, prf_size;
    size_t tim_size = 0;
    int status = -1;
    
    if (!is_apdp(ctx) || !tag || !buf || !buf_len)
        return -1;
    p = ctx->apdp_param;

    // some useful constants: upper bounds on sizes of things
    tag_size = apdp_serialized_tag_size(ctx);
    prf_size = p->prf_w_size;

    // double-check size of buf
    if (!tag_size || (buf_len > tag_size)) goto cleanup;

    // read Tim size
    tim_size = uint32_in_expected_order(buf_ptr);
    buf_ptr += sizeof(__uint32_t);

    // read Tim
    if ((tim = malloc(tim_size)) == NULL) goto cleanup;
    memset(tim, 0, tim_size);
    memcpy(tim, buf_ptr, tim_size);
    buf_ptr += tim_size; // skip bytes of serialized Tim size
    if (!BN_bin2bn(tim, tim_size, tag->Tim)) goto cleanup;

    // read index
    tag->index = uint32_in_expected_order(buf_ptr);
    buf_ptr += sizeof(tag->index);
    
    // read index_prf_size
    tag->index_prf_size = uint32_in_expected_order(buf_ptr);
    buf_ptr += sizeof(tag->index_prf_size);

    // double check size of prf
    if (!tag->index_prf_size || (tag->index_prf_size > prf_size)) goto cleanup;

    // read index_ptr
    if ((tag->index_prf = malloc(tag->index_prf_size)) == NULL) goto cleanup;
    memset(tag->index_prf, 0, tag->index_prf_size);
    memcpy(tag->index_prf, buf_ptr, tag->index_prf_size);

    status = 0;

cleanup:
    sfree(tim, tim_size);
    return status;
}


/**
 * @brief Write out challenge data to a buffer
 *
 * @param[in]  ctx         context
 * @param[in]  t           pointer to input challenge data
 * @param[in]  buffer      the buffer for the serialized data
 * @param[in]  buffer_len  length of space available, output bytes written
 * @return 0 on success, non-zero on error
 **/
int apdp_serialize_challenge(const pdp_ctx_t *ctx, const pdp_apdp_challenge_t* t,
        unsigned char **buffer, unsigned int *buffer_len)
{
    pdp_apdp_ctx_t *p = NULL;
    unsigned char *buf_ptr = NULL;
    unsigned char *buf = NULL;
    unsigned char *g_s_buf = NULL;
    unsigned char *s_buf = NULL;
    size_t buf_len = 0;
    size_t g_s_len = 0;
    size_t s_len = 0;
    int status = -1;
    __uint32_t value;

    if (!is_apdp(ctx) || !t || !buffer || !buffer_len ||
        !t->g_s || !t->k1 || !t->k2)
        return -1;
    p = ctx->apdp_param;

    // Calculate 'g_s' length and allocate space for it.
    g_s_len = BN_num_bytes(t->g_s);
    if ((g_s_buf = malloc(g_s_len)) == NULL) goto cleanup;
    memset(g_s_buf, 0, g_s_len);

    // Calculate 's' length and allocate space for it.
    if (t->s) {
        s_len = BN_num_bytes(t->s);
        if ((s_buf = malloc(s_len)) == NULL) goto cleanup;
        memset(s_buf, 0, s_len);
    }

    // Calculate serialized challenge length and allocate space for it.
    buf_len = g_s_len + s_len + 5 * sizeof(__uint32_t) + p->prp_key_size + p->prf_key_size;
    if ((buf = malloc(buf_len)) == NULL) goto cleanup;
    memset(buf, 0, buf_len);
    buf_ptr = buf;

    // Write 'c'.
    WRITE_UINT32(buf_ptr, t->c)

    // Write length of 'g_s'.
    WRITE_UINT32(buf_ptr, g_s_len)

    // Write 'g_s'.
    if (!BN_bn2bin(t->g_s, g_s_buf)) goto cleanup;
    memcpy(buf_ptr, g_s_buf, g_s_len);
    buf_ptr += g_s_len;

    // Write length of 's'.
    WRITE_UINT32(buf_ptr, s_len)

    // Write 's'.
    if (t->s) {
        if (!BN_bn2bin(t->s, s_buf)) goto cleanup;
        memcpy(buf_ptr, s_buf, s_len);
        buf_ptr += s_len;
    }

    // Write length of 'k1'.
    WRITE_UINT32(buf_ptr, p->prp_key_size)

    // Write 'k1'.
    memcpy(buf_ptr, t->k1, p->prp_key_size);
    buf_ptr += p->prp_key_size;

    // Write length of 'k2'.
    WRITE_UINT32(buf_ptr, p->prf_key_size)

    // Write 'k2'.
    memcpy(buf_ptr, t->k2, p->prf_key_size);
    buf_ptr += p->prf_key_size;

    *buffer = buf;
    *buffer_len = buf_len;

    status = 0;

cleanup:
    sfree(g_s_buf, g_s_len);
    sfree(s_buf, s_len);
    if (status && buf) {
        sfree(buf, buf_len);
        *buffer = NULL;
        *buffer_len = 0;
    }

    return status;
}


/**
 * @brief Read a challenge
 * @param[in]  ctx         context
 * @param[out] t           pointer to challenge that will be populated
 * @param[in]  buffer      serialized structure to process
 * @param[in]  buffer_len  length of data to process
 * @return 0 on success, non-zero on error
 **/
int apdp_deserialize_challenge(const pdp_ctx_t *ctx, pdp_apdp_challenge_t* t,
                               const unsigned char *buffer, unsigned int buffer_len)
{
    pdp_apdp_ctx_t *p = NULL;
    const unsigned char *buf_ptr = buffer;
    size_t g_s_len = 0;
    size_t s_len = 0;

    if (!is_apdp(ctx) || !t || !buffer)
        return -1;
    p = ctx->apdp_param;

    // Read 'c'.
    t->c = uint32_in_expected_order(buf_ptr);
    buf_ptr += sizeof(__uint32_t);

    // Read 'g_s' size.
    g_s_len = uint32_in_expected_order(buf_ptr);
    buf_ptr += sizeof(__uint32_t);

    // Read 'g_s'.
    if ((t->g_s = BN_bin2bn(buf_ptr, g_s_len, NULL)) == NULL)
        return -1;
    buf_ptr += g_s_len;

    // Read 's' size.
    s_len = uint32_in_expected_order(buf_ptr);
    buf_ptr += sizeof(__uint32_t);

    // Read 's'.
    if (s_len) {
        if ((t->s = BN_bin2bn(buf_ptr, s_len, NULL)) == NULL)
            return -1;
        buf_ptr += s_len;
    }

    // Read 'prp_key_size'.
    p->prp_key_size = uint32_in_expected_order(buf_ptr);
    buf_ptr += sizeof(__uint32_t);

    // Allocate and read 'k1'.
    if ((t->k1 = malloc(p->prp_key_size)) == NULL)
        return -1;
    memset(t->k1, 0, p->prp_key_size);
    memcpy(t->k1, buf_ptr, p->prp_key_size);
    buf_ptr += p->prp_key_size;

    // Read 'prf_key_size'.
    p->prf_key_size = uint32_in_expected_order(buf_ptr);
    buf_ptr += sizeof(__uint32_t);

    // Read 'k2'.
    if ((t->k2 = malloc(p->prf_key_size)) == NULL)
        return -1;
    memset(t->k2, 0, p->prf_key_size);
    memcpy(t->k2, buf_ptr, p->prf_key_size);

    return 0;
}


/**
 * @brief Write out proof data to a buffer
 *
 * @param[in]  ctx         context
 * @param[in]  t           pointer to input proof data
 * @param[in]  buffer      the buffer for the serialized data
 * @param[in]  buffer_len  length of space available, output bytes written
 * @return 0 on success, non-zero on error
 **/
int apdp_serialize_proof(const pdp_ctx_t *ctx, const pdp_apdp_proof_t* t,
                             unsigned char **buffer, unsigned int *buffer_len)
{
    unsigned char *buf_ptr = NULL;
    unsigned char *buf = NULL;
    unsigned char *rho_temp_buf = NULL;
    unsigned char *T_buf = NULL;
    size_t buf_len = 0;
    size_t rho_temp_len = 0;
    size_t T_len = 0;
    int status = -1;
    __uint32_t value;

    if (!is_apdp(ctx) || !t || !buffer || !buffer_len ||
        !t->T || !t->rho_temp || !t->rho)
        return -1;

    // Calculate length of 'T' and allocate space for it.
    T_len = BN_num_bytes(t->T);
    if ((T_buf = malloc(T_len)) == NULL) goto cleanup;
    memset(T_buf, 0, T_len);

    // Calculate length of 'rho_temp' and allocate space for it.
    rho_temp_len = BN_num_bytes(t->rho_temp);
    if ((rho_temp_buf = malloc(rho_temp_len)) == NULL) goto cleanup;
    memset(rho_temp_buf, 0, rho_temp_len);

    // Calculate length of serialized proof and allocate space for it.
    buf_len = T_len + rho_temp_len + 3 * sizeof(__uint32_t) + t->rho_size;
    if ((buf = malloc(buf_len)) == NULL) goto cleanup;
    memset(buf, 0, buf_len);
    buf_ptr = buf;

    // Write length of 'T'.
    WRITE_UINT32(buf_ptr, T_len)

    // Write 's'.
    if (!BN_bn2bin(t->T, T_buf)) goto cleanup;
    memcpy(buf_ptr, T_buf, T_len);
    buf_ptr += T_len;

    // Write length of 'rho_temp'.
    WRITE_UINT32(buf_ptr, rho_temp_len)

    // Write 'rho_temp'.
    if (!BN_bn2bin(t->rho_temp, rho_temp_buf)) goto cleanup;
    memcpy(buf_ptr, rho_temp_buf, rho_temp_len);
    buf_ptr += rho_temp_len;

    // Write length of 'rho'.
    WRITE_UINT32(buf_ptr, t->rho_size)

    // Write 'rho'.
    memcpy(buf_ptr, t->rho, t->rho_size);

    *buffer = buf;
    *buffer_len = buf_len;

    status = 0;

cleanup:
    sfree(rho_temp_buf, rho_temp_len);
    sfree(T_buf, T_len);
    if (status && buf) {
        sfree(buf, buf_len);
        *buffer = NULL;
        *buffer_len = 0;
    }

    return status;
}


/**
 * @brief Read a proof
 * @param[in]  ctx         context
 * @param[out] t           pointer to proof that will be populated
 * @param[in]  buffer      serialized structure to process
 * @param[in]  buffer_len  length of data to process
 * @return 0 on success, non-zero on error
 **/
int apdp_deserialize_proof(const pdp_ctx_t *ctx, pdp_apdp_proof_t* t,
                               const unsigned char *buffer, unsigned int buffer_len)
{
    const unsigned char *buf_ptr = buffer;
    size_t rho_temp_len = 0;
    size_t T_len = 0;

    if (!is_apdp(ctx) || !t || !buffer)
        return -1;

    // Read size of 'T'.
    T_len = uint32_in_expected_order(buf_ptr);
    buf_ptr += sizeof(__uint32_t);

    // Read 'T'.
    if ((t->T = BN_bin2bn(buf_ptr, T_len, NULL)) == NULL)
        return -1;
    buf_ptr += T_len;

    // Read length of 'rho_temp'.
    rho_temp_len = uint32_in_expected_order(buf_ptr);
    buf_ptr += sizeof(__uint32_t);

    // Read 'rho_temp'.
    if ((t->rho_temp = BN_bin2bn(buf_ptr, rho_temp_len, NULL)) == NULL)
        return -1;
    buf_ptr += rho_temp_len;

    // Read 'rho_size'.
    t->rho_size = uint32_in_expected_order(buf_ptr);
    buf_ptr += sizeof(__uint32_t);

    // Allocate and read 'rho'.
    if ((t->rho = malloc(t->rho_size)) == NULL)
        return -1;
    memset(t->rho, 0, t->rho_size);
    memcpy(t->rho, buf_ptr, t->rho_size);

    return 0;
}

/** @} */
