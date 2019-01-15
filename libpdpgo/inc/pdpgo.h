// Copyright 2018 ProximaX Limited. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

#ifndef PDPGO_H
#define PDPGO_H

#include <string.h>
#include <pdp.h>
#include <pdp_misc.h>
#include <pdp/apdp.h>
#include <pdp/apdp_types.h>
#include <pdp/types.h>
#include <apdp/apdp_misc.h>

typedef int (*get_block_callback)(const pdp_ctx_t*, unsigned int, void*, unsigned int*);

/// Holds data for PDP
typedef struct {
    // PDP context.
    pdp_ctx_t ctx;
    // Private key.
    pdp_key_t private_key;
    // Public key.
    pdp_key_t public_key;
    // Tags data.
    pdp_tag_t tags;
    // Verifier's challenge.
    pdp_challenge_t verifier_challenge;
    // Challenge for prover.
    pdp_challenge_t prover_challenge;
    // Proof of data possession.
    pdp_proof_t proof;
    // (For unit testing) If set to non-zero value all functions return error.
    char fail;

    // Hash of the file to verify.
    unsigned char *file_hash;
    // Size of the file hash (including terminating zero).
    unsigned int file_hash_size;

    // Serialized private key.
    unsigned char *serialized_private_key;
    // Size of the serialized private key.
    unsigned int serialized_private_key_size;

    // Serialized public key.
    unsigned char *serialized_public_key;
    // Size of the serialized public key.
    unsigned int serialized_public_key_size;

    // Serialized tags.
    unsigned char *serialized_tags;
    // Size of the serialized tags.
    unsigned int serialized_tags_size;

    // Serialized verifier's challenge.
    unsigned char *serialized_verifier_challenge;
    // Size of the serialized verifier's challenge.
    unsigned int serialized_verifier_challenge_size;

    // Serialized challenge for prover.
    unsigned char *serialized_prover_challenge;
    // Size of the serialized challenge for prover.
    unsigned int serialized_prover_challenge_size;

    // Serialized proof.
    unsigned char *serialized_proof;
    // Size of the serialized proof.
    unsigned int serialized_proof_size;
} go_pdp_data_t;

// Data allocation/deallocation.
go_pdp_data_t* create_apdp_data(off_t file_size, unsigned int block_size, unsigned short verbose, get_block_callback get_block);
void go_pdp_data_free(go_pdp_data_t* pdp_data);
void go_pdp_proof_free(go_pdp_data_t* pdp_data);

// Set attributes.
void go_pdp_set_file_hash(go_pdp_data_t* pdp_data, unsigned char* file_hash, unsigned int file_hash_size);
void go_pdp_set_fail(go_pdp_data_t* pdp_data, char fail);

// Proof Of Data Possession.
int go_pdp_generate_keys(go_pdp_data_t* pdp_data);
int go_pdp_generate_tags_init(go_pdp_data_t* pdp_data);
int go_pdp_generate_tag(go_pdp_data_t* pdp_data, unsigned char *block, size_t block_len, int index);
int go_pdp_generate_tags_finalize();
int go_pdp_generate_tags(go_pdp_data_t* pdp_data);
int go_pdp_generate_challenge(go_pdp_data_t* pdp_data);
int go_pdp_generate_proof(go_pdp_data_t* pdp_data);
int go_pdp_verify_proof(go_pdp_data_t* pdp_data);

//Struct serialization/deserialization.
int go_pdp_serialize_keys(go_pdp_data_t* pdp_data);
int go_pdp_deserialize_keys(go_pdp_data_t* pdp_data);
int go_pdp_deserialize_public_key(go_pdp_data_t* pdp_data);
int go_pdp_serialize_tags(go_pdp_data_t* pdp_data);
int go_pdp_serialize_verifier_challenge(go_pdp_data_t* pdp_data);
int go_pdp_deserialize_verifier_challenge(go_pdp_data_t* pdp_data);
int go_pdp_serialize_prover_challenge(go_pdp_data_t* pdp_data);
int go_pdp_deserialize_prover_challenge(go_pdp_data_t* pdp_data);
int go_pdp_serialize_proof(go_pdp_data_t* pdp_data);
int go_pdp_deserialize_proof(go_pdp_data_t* pdp_data);

#endif //PDPGO_H
