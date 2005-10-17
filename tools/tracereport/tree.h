#ifndef TREE_H
#define TREE_H

typedef struct tree_t tree_t;
typedef int (*keycmp_t)(const void *a, const void *b);
typedef void (*visitor_t)(const void *key, void *value, void *data);

void tree_insert(struct tree_t **tree,void *key,keycmp_t cmp,void *value);
void *tree_replace(struct tree_t **tree,void *key,keycmp_t cmp,void *value);
void *tree_find(tree_t **tree,void *key,keycmp_t keycmp);
void *tree_delete(tree_t **tree,void *key,keycmp_t keycmp);
void tree_inorder(struct tree_t **tree,visitor_t visitor, void *data);

void dump_tree(tree_t *tree,int level);



#endif
