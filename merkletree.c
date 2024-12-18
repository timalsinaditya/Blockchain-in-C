#include "merkletree.h"

#include <openssl/crypto.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/err.h>

Node *create_node(const unsigned char *hash) {
    Node *new_node = (Node *)malloc(sizeof(Node));
    if (! new_node) {
        fprintf(stderr, "ERROR: Failed to create new node!\n");
        return NULL;
    }

    memcpy(new_node->hash, hash, HASH_SIZE);

    new_node->left = NULL;
    new_node->right = NULL;
    new_node->isLeaf = TRUE;

    return new_node;
}

MerkleTree *create_tree(unsigned char **transaction_hashes, size_t num_transactions) {
    if (num_transactions == 0) {
        fprintf(stderr, "ERROR: No transactions to build the tree!\n");
        return NULL;
    }

    MerkleTree *tree = (MerkleTree *)malloc(sizeof(MerkleTree));
    if(!tree) {
        fprintf(stderr, "ERROR: Failed to create tree!\n");
        return NULL;
    }

    Node **nodes = (Node **)malloc(sizeof(Node *) * num_transactions);
    if(! nodes) {
        fprintf(stderr, "ERROR: Failed to creates leaf nodes!\n");
        free(tree);
        return NULL;
    }

    for(size_t i = 0; i < num_transactions; ++i) {
        nodes[i] = create_node(transaction_hashes[i]);

        if(! nodes[i]) {
            fprintf(stderr, "Error: Failed to create node for transaction %zu\n",i);

            for(size_t j = 0; j < i; j++) {
                free(nodes[j]);
            }
            free(nodes);
            free(tree);

            return NULL;
        }
    }

    while (num_transactions > 1) {
        size_t temp_size = (num_transactions + 1) / 2;
        Node **new_nodes = (Node **)malloc(sizeof(Node *) * num_transactions);
        if(! new_nodes) {
            fprintf(stderr, "ERROR: Failed to allocate memory for new nodes!\n");
            for(size_t i = 0; i < num_transactions; ++i) {
                free(nodes[i]);
            }
            free(nodes);
            free(tree);
            return NULL;
        }

        size_t j = 0;
        for(size_t i = 0; i < num_transactions; i += 2) {
           if(i + 1 < num_transactions) {
               unsigned char combined_hash[HASH_SIZE];
               combine_hashes(nodes[i]-> hash, nodes[i+1]->hash, combined_hash);
               new_nodes[j] = create_node(combined_hash);
           } else {
               new_nodes[j] = nodes[i];
           }

           if(! new_nodes[j]) {
               fprintf(stderr, "ERROR: Failed to create new node during tree construction!\n");

               for(size_t k = 0; k < j; ++k) {
                   free(new_nodes[k]);
               }
               free(new_nodes);
               for(size_t k = 0; k < num_transactions; ++k) {
                   free(nodes[k]);
               }
               free(nodes);
               free(tree);
               return NULL;
           }

           j++;
        }

        for(size_t i = 0; i < num_transactions; ++i) {
            free(nodes[i]);
        }
        free(nodes);

        nodes = new_nodes;
        num_transactions = temp_size;
    }

    tree->root = nodes[0];
    free(nodes);

    return tree;
}

void combine_hashes(const unsigned char *hash1, const unsigned char *hash2, unsigned char *combined_hash) {
    if(!hash1 || !hash2 || !combined_hash) {
        fprintf(stderr, "ERROR: Failed to combine hashes!\n");
        return;
    }

    unsigned char concatenated[2 * HASH_SIZE];
    unsigned int hash_size;

    memcpy(concatenated, hash1, HASH_SIZE);
    memcpy(concatenated + HASH_SIZE, hash2, HASH_SIZE);

    if(! calculate_hash(concatenated, 2 * HASH_SIZE, combined_hash, &hash_size)) {
        fprintf(stderr, "ERROR: Failed to calculate hash!\n");
        return;
    }
}

boolean calculate_hash(const unsigned char *data, size_t data_len, unsigned char *hash, unsigned int *hash_length) {
    OSSL_LIB_CTX *lib;
    boolean temp = FALSE;
    const char *opt_properties = NULL;
    EVP_MD *message_digest = NULL;
    EVP_MD_CTX *digest_context = NULL;

    lib = OSSL_LIB_CTX_new();
    if(! lib) {
        fprintf(stderr, "ERROR: OSSL_LIB_CTX_new() returned NULL!\n");
        goto cleanup;
    }

    message_digest = EVP_MD_fetch(lib, "SHA3-256", opt_properties);

    if(! message_digest) {
        fprintf(stderr, "ERROR: SHA3-256 couldnot be fetched!\n");
        goto cleanup;
    }

    *hash_length = EVP_MD_get_size(message_digest);

    if(*hash_length <= 0) {
        fprintf(stderr, "EVP_MP_get_size returned invalid size.\n");
        goto cleanup;
    }

    if (*hash_length > HASH_SIZE) {
        fprintf(stderr, "Provided digest buffer is too small.\n");
        goto cleanup;
    }

    digest_context = EVP_MD_CTX_new();

    if(digest_context == NULL) {
        fprintf(stderr, "EVP_MD_CTX_new failed.\n");
        goto cleanup;
    }

    if(EVP_DigestInit(digest_context, message_digest) != 1) {
        fprintf(stderr, "EVP_DigestInit failed.\n");
        goto cleanup;
    }

    if(EVP_DigestUpdate(digest_context, data, data_len) != 1) {
        fprintf(stderr, "EVP_DigestUpdate failed.\n");
        goto cleanup;
    }

    if(EVP_DigestFinal(digest_context, hash, hash_length) != 1) {
        fprintf(stderr, "EVP_DigestFinal failed.\n");
        goto cleanup;
    }

    temp = TRUE;

    cleanup:
        if(temp != TRUE)
            ERR_print_errors_fp(stderr);

        EVP_MD_CTX_free(digest_context);
        EVP_MD_free(message_digest);
        OSSL_LIB_CTX_free(lib);

    return temp;
}
