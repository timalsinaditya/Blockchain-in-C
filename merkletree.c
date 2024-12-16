#include "merkletree.h"

#include <stdlib.h>
#include <string.h>

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

void combine_hashes(unsigned char *hash1, unsigned char *hash2, unsigned char *combined_hash) {
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
