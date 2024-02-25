#ifndef _TRIE_H_
#define _TRIE_H_

#include <stdlib.h>

typedef struct Trie {
    int index;
    int num_children;
    struct Trie* child[2];
} Trie;

int index_char (char c);
void init_trie(Trie **trie);
void insert(Trie *trie, char *prefix, int prefix_len, int table_index);
void free_trie(Trie **trie);

#endif