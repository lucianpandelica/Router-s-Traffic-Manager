#include "trie.h"
#include "lib.h"

#include <stdlib.h>
#include <string.h>

int index_char (char c) {

    if(c == '0')
        return 0;
    
    return 1;
}

void init_trie(Trie **trie) {

    (*trie) = malloc(sizeof(struct Trie));
    DIE((*trie) == NULL, "malloc");

    (*trie)->child[0] = NULL;
    (*trie)->child[1] = NULL;
    (*trie)->index = -1;
    (*trie)->num_children = 0;
}

void insert(Trie *trie, char *prefix, int prefix_len, int table_index) {

    int i;
    int bit;
    Trie *aux_trie = trie;

    for(i = 0; i < prefix_len; i++) {

        bit = index_char(prefix[i]);

        if(aux_trie->child[bit] == NULL) {
            init_trie(&(aux_trie->child[bit]));
            aux_trie->num_children++;
        }

        if(i == (prefix_len - 1)) {
            aux_trie->child[bit]->index = table_index;
        }

        aux_trie = aux_trie->child[bit];
    }
}

void free_trie(Trie **trie) {
    int i;

    for(i = 0; i < 2; i++) {
        if((*trie)->child[i] != NULL) {
            free_trie(&((*trie)->child[i]));
            (*trie)->num_children--;
        }
    }

    if((*trie)->num_children == 0) {
        free((*trie));
        return;
    }
}