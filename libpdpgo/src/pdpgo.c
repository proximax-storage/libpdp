// Copyright 2018 ProximaX Limited. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

#include "pdpgo.h"
#include <openssl/evp.h>

int go_pdp_check_struct(go_pdp_data_t* pdp_data, const char* func) {
    if (!pdp_data) {
        DEBUG(1, "%s: null pointer passed", func);
        return -1;
    }

    if (pdp_data->fail) {
        return -1;
    }

    return 0;
}

int apdp_get_tag_memory(const pdp_ctx_t* ctx, unsigned int index,
                        void* buffer, unsigned int* length) {
    pdp_apdp_tag_t** tag_ptr = (pdp_apdp_tag_t**) buffer;
    go_pdp_data_t* pdp_data = NULL;
    pdp_apdp_tag_t* tag = NULL;
    unsigned char* serialized_tag = NULL;
    unsigned int serialized_tag_start = 0, serialized_tag_size = 0;
    int status = -1;

    if (!ctx || !tag_ptr || !ctx->optional_data) return -1;

    pdp_data = (go_pdp_data_t*)ctx->optional_data;
    if (go_pdp_check_struct(pdp_data, __FUNCTION__)) return -1;

    serialized_tag_size = apdp_serialized_tag_size(ctx);
    serialized_tag_start = index * serialized_tag_size;
    if (serialized_tag_start > pdp_data->serialized_tags_size) {
        DEBUG(1, "%s: invalid tag index", __FUNCTION__);
        goto cleanup;
    }

    serialized_tag = pdp_data->serialized_tags + serialized_tag_start;

    // Allocate space for the tag
    if ((tag = apdp_tag_new()) == NULL) goto cleanup;
    if (*tag_ptr != NULL) {
        // there is already a tag here, so free it
        apdp_tag_free(*tag_ptr);
    }
    *tag_ptr = tag;

    if (apdp_deserialize_tag(ctx, tag, serialized_tag, serialized_tag_size) != 0) {
        DEBUG(1, "%s: couldn't deserialize tag", __FUNCTION__);
        goto cleanup;
    }

    status = 0;

cleanup:
    if (status && tag_ptr && *tag_ptr) {
        apdp_tag_free(*tag_ptr);
        *tag_ptr = NULL;
    }

    return status;
}

int go_pdp_data_key_create(go_pdp_data_t* pdp_data, pdp_key_t* key) {
    pdp_key_free(&pdp_data->ctx, key);
    memset(key, 0, sizeof(pdp_key_t));

    switch(pdp_data->ctx.algo) {
        case PDP_APDP:
            if ((key->apdp = malloc(sizeof(pdp_apdp_key_t))) == NULL) {
                DEBUG(1, "%s: couldn't allocate A-PDP key struct", __FUNCTION__);
                return -1;
            }
            memset(key->apdp, 0, sizeof(pdp_apdp_key_t));
            return 0;
        default:
            DEBUG(1, "%s: algorithm is not supported (%u)", __FUNCTION__, pdp_data->ctx.algo);
            break;
    }

    return -1;
}

int go_pdp_data_challenge_create(go_pdp_data_t* pdp_data, pdp_challenge_t* challenge) {
    pdp_challenge_free(&pdp_data->ctx, challenge);
    memset(challenge, 0, sizeof(pdp_challenge_t));

    switch(pdp_data->ctx.algo) {
        case PDP_APDP:
            if ((challenge->apdp = malloc(sizeof(pdp_apdp_challenge_t))) == NULL) {
                DEBUG(1, "%s: couldn't allocate A-PDP challenge struct", __FUNCTION__);
                return -1;
            }
            memset(challenge->apdp, 0, sizeof(pdp_apdp_challenge_t));
            return 0;
        default:
            DEBUG(1, "%s: algorithm is not supported (%u)", __FUNCTION__, pdp_data->ctx.algo);
            break;
    }

    return -1;
}

int go_pdp_data_proof_create(go_pdp_data_t* pdp_data) {
    pdp_proof_free(&pdp_data->ctx, &pdp_data->proof);
    memset(&pdp_data->proof, 0, sizeof(pdp_proof_t));

    switch(pdp_data->ctx.algo) {
        case PDP_APDP:
            if ((pdp_data->proof.apdp = malloc(sizeof(pdp_apdp_proof_t))) == NULL) {
                DEBUG(1, "%s: couldn't allocate A-PDP proof struct", __FUNCTION__);
                return -1;
            }
            memset(pdp_data->proof.apdp, 0, sizeof(pdp_apdp_proof_t));
            return 0;
        default:
            DEBUG(1, "%s: algorithm is not supported (%u)", __FUNCTION__, pdp_data->ctx.algo);
            break;
    }

    return -1;
}

int go_pdp_serialize_keys(go_pdp_data_t* pdp_data) {
    if (go_pdp_check_struct(pdp_data, __FUNCTION__)) {
        return -1;
    }

    if (pdp_data->ctx.algo != PDP_APDP) {
        DEBUG(1, "%s: algorithm is not supported (%u)", __FUNCTION__, pdp_data->ctx.algo);
        return -1;
    }

    if (!pdp_data->private_key.apdp) {
        DEBUG(1, "%s: no keys", __FUNCTION__);
        return -1;
    }

    sfree(pdp_data->serialized_private_key, pdp_data->serialized_private_key_size);
    pdp_data->serialized_private_key = NULL;
    pdp_data->serialized_private_key_size = 0;

    sfree(pdp_data->serialized_public_key, pdp_data->serialized_public_key_size);
    pdp_data->serialized_public_key = NULL;
    pdp_data->serialized_public_key_size = 0;

    return pdp_key_store(&pdp_data->ctx, &pdp_data->private_key, NULL,
            &pdp_data->serialized_private_key, &pdp_data->serialized_private_key_size,
            &pdp_data->serialized_public_key, &pdp_data->serialized_public_key_size);
}

int go_pdp_deserialize_keys(go_pdp_data_t* pdp_data) {
    if (go_pdp_check_struct(pdp_data, __FUNCTION__)) {
        return -1;
    }

    if (pdp_data->ctx.algo != PDP_APDP) {
        DEBUG(1, "%s: algorithm is not supported (%u)", __FUNCTION__, pdp_data->ctx.algo);
        return -1;
    }

    if (go_pdp_data_key_create(pdp_data, &pdp_data->private_key)) {
        DEBUG(1, "%s: couldn't create private key", __FUNCTION__);
        return -1;
    }

    if (go_pdp_data_key_create(pdp_data, &pdp_data->public_key)) {
        DEBUG(1, "%s: couldn't create public key", __FUNCTION__);
        return -1;
    }

    return pdp_key_open(&pdp_data->ctx, &pdp_data->private_key, &pdp_data->public_key, NULL,
            pdp_data->serialized_private_key, pdp_data->serialized_public_key);
}

int go_pdp_deserialize_public_key(go_pdp_data_t* pdp_data) {
    if (go_pdp_check_struct(pdp_data, __FUNCTION__)) {
        return -1;
    }

    if (pdp_data->ctx.algo != PDP_APDP) {
        DEBUG(1, "%s: algorithm is not supported (%u)", __FUNCTION__, pdp_data->ctx.algo);
        return -1;
    }

    if (go_pdp_data_key_create(pdp_data, &pdp_data->public_key)) {
        DEBUG(1, "%s: couldn't create public key", __FUNCTION__);
        return -1;
    }

    return pdp_key_open(&pdp_data->ctx, NULL, &pdp_data->public_key, NULL, NULL, pdp_data->serialized_public_key);
}

int go_pdp_serialize_tags(go_pdp_data_t* pdp_data) {
    if (go_pdp_check_struct(pdp_data, __FUNCTION__)) {
        return -1;
    }

    if (!pdp_data->tags.apdp) {
        DEBUG(1, "%s: no tags", __FUNCTION__);
        return -1;
    }

    sfree(pdp_data->serialized_tags, pdp_data->serialized_tags_size);

    switch(pdp_data->ctx.algo) {
        case PDP_APDP:
            return apdp_serialize_tags(&pdp_data->ctx, pdp_data->tags.apdp, &pdp_data->serialized_tags,
                                       &pdp_data->serialized_tags_size);
        default:
            DEBUG(1, "%s: algorithm is not supported (%u)", __FUNCTION__, pdp_data->ctx.algo);
            break;
    }

    return -1;
}

int go_pdp_serialize_verifier_challenge(go_pdp_data_t* pdp_data) {
    if (go_pdp_check_struct(pdp_data, __FUNCTION__)) {
        return -1;
    }

    if (!pdp_data->verifier_challenge.apdp) {
        DEBUG(1, "%s: no verifier challenge", __FUNCTION__);
        return -1;
    }

    sfree(pdp_data->serialized_verifier_challenge, pdp_data->serialized_verifier_challenge_size);

    switch(pdp_data->ctx.algo) {
        case PDP_APDP:
            return apdp_serialize_challenge(&pdp_data->ctx, pdp_data->verifier_challenge.apdp,
                    &pdp_data->serialized_verifier_challenge,
                    &pdp_data->serialized_verifier_challenge_size);
        default:
            DEBUG(1, "%s: algorithm is not supported (%u)", __FUNCTION__, pdp_data->ctx.algo);
            break;
    }

    return -1;
}

int go_pdp_deserialize_verifier_challenge(go_pdp_data_t* pdp_data) {
    if (go_pdp_check_struct(pdp_data, __FUNCTION__)) {
        return -1;
    }

    if (go_pdp_data_challenge_create(pdp_data, &pdp_data->verifier_challenge)) {
        DEBUG(1, "%s: couldn't create verifier challenge", __FUNCTION__);
        return -1;
    }

    switch(pdp_data->ctx.algo) {
        case PDP_APDP:
            if ((pdp_data->verifier_challenge.apdp = malloc(sizeof(pdp_apdp_challenge_t))) == NULL) {
                DEBUG(1, "%s: couldn't allocate A-PDP challenge struct", __FUNCTION__);
                return -1;
            }
            memset(pdp_data->verifier_challenge.apdp, 0, sizeof(pdp_apdp_challenge_t));
            return apdp_deserialize_challenge(&pdp_data->ctx, pdp_data->verifier_challenge.apdp,
                    pdp_data->serialized_verifier_challenge,
                    pdp_data->serialized_verifier_challenge_size);
        default:
            DEBUG(1, "%s: algorithm is not supported (%u)", __FUNCTION__, pdp_data->ctx.algo);
            break;
    }

    return -1;
}

int go_pdp_serialize_prover_challenge(go_pdp_data_t* pdp_data) {
    if (go_pdp_check_struct(pdp_data, __FUNCTION__)) {
        return -1;
    }

    if (!pdp_data->prover_challenge.apdp) {
        DEBUG(1, "%s: no prover challenge", __FUNCTION__);
        return -1;
    }

    sfree(pdp_data->serialized_prover_challenge, pdp_data->serialized_prover_challenge_size);

    switch(pdp_data->ctx.algo) {
        case PDP_APDP:
            return apdp_serialize_challenge(&pdp_data->ctx, pdp_data->prover_challenge.apdp,
                    &pdp_data->serialized_prover_challenge,
                    &pdp_data->serialized_prover_challenge_size);
        default:
            DEBUG(1, "%s: algorithm is not supported (%u)", __FUNCTION__, pdp_data->ctx.algo);
            break;
    }

    return -1;
}

int go_pdp_deserialize_prover_challenge(go_pdp_data_t* pdp_data) {
    if (go_pdp_check_struct(pdp_data, __FUNCTION__)) {
        return -1;
    }

    if (go_pdp_data_challenge_create(pdp_data, &pdp_data->prover_challenge)) {
        DEBUG(1, "%s: couldn't create prover challenge", __FUNCTION__);
        return -1;
    }

    switch(pdp_data->ctx.algo) {
        case PDP_APDP:
            if ((pdp_data->prover_challenge.apdp = malloc(sizeof(pdp_apdp_challenge_t))) == NULL) {
                DEBUG(1, "%s: couldn't allocate A-PDP challenge struct", __FUNCTION__);
                return -1;
            }
            memset(pdp_data->prover_challenge.apdp, 0, sizeof(pdp_apdp_challenge_t));
            return apdp_deserialize_challenge(&pdp_data->ctx, pdp_data->prover_challenge.apdp,
                    pdp_data->serialized_prover_challenge,
                    pdp_data->serialized_prover_challenge_size);
        default:
            DEBUG(1, "%s: algorithm is not supported (%u)", __FUNCTION__, pdp_data->ctx.algo);
            break;
    }

    return -1;
}

int go_pdp_serialize_proof(go_pdp_data_t* pdp_data) {
    if (go_pdp_check_struct(pdp_data, __FUNCTION__)) {
        return -1;
    }

    if (!pdp_data->proof.apdp) {
        DEBUG(1, "%s: no proof", __FUNCTION__);
        return -1;
    }

    sfree(pdp_data->serialized_proof, pdp_data->serialized_proof_size);

    switch(pdp_data->ctx.algo) {
        case PDP_APDP:
            return apdp_serialize_proof(&pdp_data->ctx, pdp_data->proof.apdp, &pdp_data->serialized_proof,
                                        &pdp_data->serialized_proof_size);
        default:
            DEBUG(1, "%s: algorithm is not supported (%u)", __FUNCTION__, pdp_data->ctx.algo);
            break;
    }

    return -1;
}

int go_pdp_deserialize_proof(go_pdp_data_t* pdp_data) {
    if (go_pdp_check_struct(pdp_data, __FUNCTION__)) {
        return -1;
    }

    if (go_pdp_data_proof_create(pdp_data)) {
        DEBUG(1, "%s: couldn't create proof", __FUNCTION__);
        return -1;
    }

    switch(pdp_data->ctx.algo) {
        case PDP_APDP:
            return apdp_deserialize_proof(&pdp_data->ctx, pdp_data->proof.apdp, pdp_data->serialized_proof,
                                        pdp_data->serialized_proof_size);
        default:
            DEBUG(1, "%s: algorithm is not supported (%u)", __FUNCTION__, pdp_data->ctx.algo);
            break;
    }

    return -1;
}

go_pdp_data_t* create_apdp_data(unsigned short verbose, get_block_callback get_block) {
    go_pdp_data_t* pdp_data = NULL;

    if ((pdp_data = malloc(sizeof(go_pdp_data_t))) == NULL) {
        DEBUG(1, "%s: couldn't allocate PDP data", __FUNCTION__);
        goto cleanup;
    }

    memset(pdp_data, 0, sizeof(go_pdp_data_t));
    pdp_data->ctx.algo = PDP_APDP;

    if (pdp_ctx_init(&pdp_data->ctx)) {
        DEBUG(1, "%s: couldn't init PDP context", __FUNCTION__);
        goto cleanup;
    }

    pdp_data->ctx.opts |= PDP_OPT_EXT_STRG;
    pdp_data->ctx.opts |= PDP_OPT_THREADED;
    pdp_data->ctx.verbose = verbose;

    if (pdp_ctx_create(&pdp_data->ctx, NULL, NULL)) {
        DEBUG(1, "%s: couldn't populate PDP context", __FUNCTION__);
        goto cleanup;
    }

    pdp_data->ctx.ops->get_block = get_block;
    pdp_data->ctx.ops->get_tag = apdp_get_tag_memory;
    pdp_data->ctx.optional_data = pdp_data;

    return pdp_data;

cleanup:
    if (pdp_data) {
        sfree(pdp_data, sizeof(go_pdp_data_t));
    }

    return NULL;
}

void go_pdp_proof_free(go_pdp_data_t* pdp_data) {
    if (go_pdp_check_struct(pdp_data, __FUNCTION__)) {
        return;
    }
    pdp_proof_free(&pdp_data->ctx, &pdp_data->proof);
    sfree(pdp_data->serialized_proof, pdp_data->serialized_proof_size);
}

void go_pdp_data_fields_free(go_pdp_data_t* pdp_data) {
    pdp_key_free(&pdp_data->ctx, &pdp_data->private_key);
    pdp_key_free(&pdp_data->ctx, &pdp_data->public_key);
    pdp_tags_free(&pdp_data->ctx, &pdp_data->tags);
    pdp_challenge_free(&pdp_data->ctx, &pdp_data->verifier_challenge);
    pdp_challenge_free(&pdp_data->ctx, &pdp_data->prover_challenge);
    sfree(pdp_data->file_hash, pdp_data->file_hash_size);
    sfree(pdp_data->serialized_public_key, pdp_data->serialized_public_key_size);
    sfree(pdp_data->serialized_tags, pdp_data->serialized_tags_size);
    sfree(pdp_data->serialized_verifier_challenge, pdp_data->serialized_verifier_challenge_size);
    sfree(pdp_data->serialized_prover_challenge, pdp_data->serialized_prover_challenge_size);
    go_pdp_proof_free(pdp_data);
}

void go_pdp_data_free(go_pdp_data_t* pdp_data) {
    if (go_pdp_check_struct(pdp_data, __FUNCTION__)) {
        return;
    }
    go_pdp_data_fields_free(pdp_data);
    pdp_ctx_free(&pdp_data->ctx);
    sfree(pdp_data, sizeof(go_pdp_data_t));
}

int go_pdp_set_file_hash(go_pdp_data_t* pdp_data, unsigned char* file_hash, unsigned int file_hash_size) {
    if (go_pdp_check_struct(pdp_data, __FUNCTION__)) {
        return -1;
    }

    sfree(pdp_data->file_hash, pdp_data->file_hash_size);
    pdp_data->file_hash = file_hash;
    pdp_data->file_hash_size = file_hash_size;

    return 0;
}

int go_pdp_set_fail(go_pdp_data_t* pdp_data, char fail) {
    if (go_pdp_check_struct(pdp_data, __FUNCTION__)) {
        return -1;
    }

    pdp_data->fail = fail;

    return 0;
}

int go_pdp_set_file_and_block_size(go_pdp_data_t* pdp_data, off_t file_size, unsigned int block_size) {
    if (go_pdp_check_struct(pdp_data, __FUNCTION__)) {
        return -1;
    }

    pdp_data->ctx.apdp_param->block_size = adjust_block_size(block_size);
    pdp_data->ctx.file_st_size = file_size;

    return 0;
}

int go_pdp_generate_keys(go_pdp_data_t* pdp_data) {
    if (go_pdp_check_struct(pdp_data, __FUNCTION__)) {
        return -1;
    }

    // Generate keys.
    if (pdp_key_gen(&pdp_data->ctx, &pdp_data->private_key, &pdp_data->public_key)) {
        DEBUG(1, "%s: couldn't generate keys", __FUNCTION__);
        goto cleanup;
    }

    return 0;

cleanup:
    pdp_key_free(&pdp_data->ctx, &pdp_data->private_key);
    pdp_key_free(&pdp_data->ctx, &pdp_data->public_key);

    return -1;
}

int go_pdp_generate_tags(go_pdp_data_t* pdp_data) {
    if (go_pdp_check_struct(pdp_data, __FUNCTION__)) {
        return -1;
    }

    if (pdp_tags_gen(&pdp_data->ctx, &pdp_data->private_key, &pdp_data->tags)) {
        DEBUG(1, "%s: couldn't generate tags", __FUNCTION__);
        goto cleanup;
    }

    return 0;

cleanup:
    pdp_tags_free(&pdp_data->ctx, &pdp_data->tags);

    return -1;
}

int go_pdp_generate_challenge(go_pdp_data_t* pdp_data) {
    if (go_pdp_check_struct(pdp_data, __FUNCTION__)) {
        return -1;
    }

    // Generate verifier's challenge.
    if (pdp_challenge_gen(&pdp_data->ctx, &pdp_data->private_key, &pdp_data->verifier_challenge)) {
        DEBUG(1, "%s: couldn't generate verifier's challenge", __FUNCTION__);
        goto cleanup;
    }

    // Generate challenge for prover.
    if (pdp_challenge_for_prover(&pdp_data->ctx, &pdp_data->verifier_challenge, &pdp_data->prover_challenge)) {
        DEBUG(1, "%s: couldn't generate challenge for prover", __FUNCTION__);
        goto cleanup;
    }

    return 0;

cleanup:
    go_pdp_data_fields_free(pdp_data);

    return -1;
}

int go_pdp_generate_proof(go_pdp_data_t* pdp_data) {
    if (go_pdp_check_struct(pdp_data, __FUNCTION__)) {
        return -1;
    }

    if (pdp_proof_gen(&pdp_data->ctx, &pdp_data->public_key, &pdp_data->prover_challenge, &pdp_data->proof)) {
        DEBUG(1, "%s: couldn't generate proof", __FUNCTION__);
        goto cleanup;
    }

    return 0;

cleanup:
    pdp_proof_free(&pdp_data->ctx, &pdp_data->proof);

    return -1;
}

int go_pdp_verify_proof(go_pdp_data_t* pdp_data) {
    if (go_pdp_check_struct(pdp_data, __FUNCTION__)) {
        return -1;
    }

    return pdp_proof_verify(&pdp_data->ctx, &pdp_data->private_key, &pdp_data->verifier_challenge,
            &pdp_data->proof);
}

int go_pdp_generate_tags_init(go_pdp_data_t* pdp_data) {
    pdp_apdp_ctx_t *p = NULL;
    pdp_apdp_tagdata_t *t = NULL;
    int status = -1;

    if (go_pdp_check_struct(pdp_data, __FUNCTION__)) {
        return -1;
    }

    p = pdp_data->ctx.apdp_param;

    if (pdp_data->ctx.algo != PDP_APDP) {
        DEBUG(1, "%s: algorithm is not supported (%u)", __FUNCTION__, pdp_data->ctx.algo);
        return -1;
    }

    if (!pdp_data->private_key.apdp) {
        DEBUG(1, "%s: no private key", __FUNCTION__);
        return -1;
    }

    if (!pdp_data->ctx.file_st_size || !p->block_size) {
        DEBUG(1, "%s: file or block size is zero", __FUNCTION__);
        return -1;
    }

    OpenSSL_add_all_digests();

    p->num_blocks = get_num_blocks(pdp_data->ctx.file_st_size, p->block_size);

    // allocate space for tags
    if ((t = malloc(sizeof(pdp_apdp_tagdata_t))) == NULL) {
        DEBUG(1, "%s: couldn't allocate tag structure", __FUNCTION__);
        return -1;
    }
    memset(t, 0, sizeof(pdp_apdp_tagdata_t));
    t->tags_size = p->num_blocks * sizeof(pdp_apdp_tag_t *);
    t->tags_num = p->num_blocks;
    if ((t->tags = malloc(t->tags_size)) == NULL) {
        DEBUG(1, "%s: couldn't allocate space for tags", __FUNCTION__);
        goto cleanup;
    }
    memset(t->tags, 0, t->tags_size);

    pdp_data->tags.apdp = t;
    status = 0;

cleanup:
    if (status) {
        sfree(t->tags, t->tags_size);
        sfree(t, sizeof(pdp_apdp_tagdata_t));
    }
    return status;
}

int go_pdp_generate_tag(go_pdp_data_t* pdp_data, unsigned char *block, size_t block_len, int index) {
    if (go_pdp_check_struct(pdp_data, __FUNCTION__)) {
        return -1;
    }

    if (pdp_data->ctx.algo != PDP_APDP) {
        DEBUG(1, "%s: algorithm is not supported (%u)", __FUNCTION__, pdp_data->ctx.algo);
        return -1;
    }

    if (!pdp_data->private_key.apdp || !block || !block_len ||
        !pdp_data->tags.apdp || index >= pdp_data->tags.apdp->tags_num)
        return -1;

    return apdp_tag_block(&pdp_data->ctx, pdp_data->private_key.apdp, block, block_len, index,
        &pdp_data->tags.apdp->tags[index]);
}

int go_pdp_generate_tags_finalize() {
    EVP_cleanup();

    return 0;
}