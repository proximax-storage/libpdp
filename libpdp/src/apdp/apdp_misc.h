/**
 * @file
 * Interfaces for A-PDP module backend storage logic.
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
#ifndef __A_PDP_MISC_H__
#define __A_PDP_MISC_H__


#define WRITE_UINT32(BUF, VALUE)                            \
    value = uint32_to_little_endian((__uint32_t)VALUE);     \
    memcpy(BUF, &value, sizeof(__uint32_t));                \
    BUF += sizeof(__uint32_t);

unsigned int get_num_blocks(off_t file_st_size, unsigned int block_size);

/*
 * function prototypes - apdp.c
 */
pdp_apdp_tag_t *apdp_tag_new(void);
void apdp_tag_free(pdp_apdp_tag_t *tag);

/*
 * function prototypes - apdp_serialize.c
 */
unsigned int apdp_serialized_tag_size(const pdp_ctx_t *ctx);
int apdp_serialize_tags(const pdp_ctx_t *ctx, const pdp_apdp_tagdata_t* t,
        unsigned char **buffer, unsigned int *buffer_len);
int apdp_deserialize_tag(const pdp_ctx_t *ctx, pdp_apdp_tag_t* tag,
        unsigned char *buffer, unsigned int buffer_len);
int apdp_serialize_challenge(const pdp_ctx_t *ctx, const pdp_apdp_challenge_t* t,
        unsigned char **buffer, unsigned int *buffer_len);
int apdp_deserialize_challenge(const pdp_ctx_t *ctx, pdp_apdp_challenge_t* tag,
        const unsigned char *buffer, unsigned int buffer_len);
int apdp_serialize_proof(const pdp_ctx_t *ctx, const pdp_apdp_proof_t* t,
        unsigned char **buffer, unsigned int *buffer_len);
int apdp_deserialize_proof(const pdp_ctx_t *ctx, pdp_apdp_proof_t* tag,
        const unsigned char *buffer, unsigned int buffer_len);

int apdp_tag_block(pdp_ctx_t *ctx, pdp_apdp_key_t *key,
                   unsigned char *block, size_t block_len,
                   int index, pdp_apdp_tag_t **t);

#endif
/** @} */
