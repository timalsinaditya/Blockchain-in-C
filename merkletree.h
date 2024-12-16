#ifndef MERKLE_TREE_H
#define MERKLE_TREE_H

#include <stdio.h>
#define HASH_SIZE 64

typedef enum {
    FALSE,
    TRUE
} boolean;

typedef struct Node Node;

struct Node {
    unsigned char hash[HASH_SIZE];
    Node *left;
    Node *right;
    boolean isLeaf;
};

typedef struct {
    Node *root;
} MerkleTree;

MerkleTree *create_tree(unsigned char **transaction_hash, \
    size_t num_transactions);

// void free_tree(MerkleTree *tree);

int seralize_tree(const MerkleTree *tree, unsigned char *buffer, size_t buffer_size);
MerkleTree *deseralize_tree(const unsigned char *buffer, size_t buffer_size);

Node *create_node(const unsigned char *hash);
// void free_node(Node *node);

int calculate_hash(const unsigned char *data,\
    size_t data_len, unsigned char *hash, unsigned int *hash_length);

void combine_hashes(unsigned char *hash1,\
    unsigned char *hash2, unsigned char *combined_hash);

#endif
