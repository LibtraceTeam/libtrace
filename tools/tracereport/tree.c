#include <stdlib.h>
#include <stdio.h>
#include "tree.h"

struct tree_t
{
	void *key;
	void *value;
	struct tree_t *left;
	struct tree_t *right;
};


void tree_insert(struct tree_t **tree,void *key,keycmp_t cmp,void *value)
{
	int cmpret;
	if (*tree == NULL) {
		*tree=malloc(sizeof(struct tree_t));
		(*tree)->key=key;
		(*tree)->value=value;
		(*tree)->left=NULL;
		(*tree)->right=NULL;
		return;
	}
	cmpret=cmp(key,(*tree)->key);
	if (cmpret<0) {
		tree_insert(&(*tree)->left,key,cmp,value);
	} else {
		tree_insert(&(*tree)->right,key,cmp,value);
	}
	return;
}

void *tree_replace(struct tree_t **tree,void *key,keycmp_t cmp,void *value)
{
	int cmpret;
	if (*tree == NULL) {
		*tree=malloc(sizeof(struct tree_t));
		(*tree)->key=key;
		(*tree)->value=value;
		(*tree)->left=NULL;
		(*tree)->right=NULL;
		return NULL;
	}
	cmpret=cmp(key,(*tree)->key);
	if (cmpret==0) {
		void *v = (*tree)->value;
		(*tree)->value=value;
		return v;
	}
	else if (cmpret<0) {
		return tree_replace(&(*tree)->left,key,cmp,value);
	} else {
		return tree_replace(&(*tree)->right,key,cmp,value);
	}
}

void *tree_find(tree_t **tree,void *key,keycmp_t keycmp)
{
	int cmpret;
	if (*tree == NULL) {
		return NULL;
	}
	cmpret=keycmp(key,(*tree)->key);
	if (cmpret==0) {
		return (*tree)->value;
	} else if (cmpret<0) {
		return tree_find(&(*tree)->left,key,keycmp);
	}
	else
		return tree_find(&(*tree)->right,key,keycmp);
}

void *tree_delete(tree_t **tree,void *key,keycmp_t keycmp)
{
	int cmpret;
	if (*tree == NULL) {
		printf("not found\n");
		return NULL;
	}
	cmpret=keycmp(key,(*tree)->key);
	if (cmpret==0) {
		void *v=(*tree)->value;
		tree_t *node_a = (*tree);
		tree_t *node_b = (*tree)->left;
		tree_t *node_c = (*tree)->right;
		tree_t **node_d;
		tree_t *node_f;
		if (!node_c) {
			(*tree)=node_a->left;
			free(node_a);
			return v;
		}
		for(node_d=&((*tree)->right); (*node_d)->left;
				node_d=&((*node_d)->left))
			;
		node_f=(*node_d)->right;
		(*tree)=*node_d;
		(*node_d)->left=node_b;
		if (*node_d != node_c)
			(*node_d)->right=node_c;
		else
			(*node_d)->right=NULL;
		(*node_d)=node_f;
		free(node_a);
		return v;
	} else if (cmpret<0) {
		return tree_delete(&(*tree)->left,key,keycmp);
	}
	else
		return tree_delete(&(*tree)->right,key,keycmp);
}

void tree_inorder(tree_t **tree,visitor_t visitor,void *data)
{
	if (*tree) {
		tree_inorder(&(*tree)->left,visitor,data);
		visitor((*tree)->key,(*tree)->value,data);
		tree_inorder(&(*tree)->right,visitor,data);
	}
}

#ifdef TEST
#include <string.h>
#include <stdio.h>

void dump_tree(tree_t *tree,int level)
{
	int i=0;
	for(i=0;i<level;++i) {
		printf(" ");
	}
	if (!tree) {
		printf("NULL\n");
		return;
	}
	printf("%s: %s\n",(char*)tree->key,(char*)tree->value);
	dump_tree(tree->left,level+1);
	dump_tree(tree->right,level+1);
}

int main(int argc, char *argv[])
{
	tree_t *tree = NULL;
	tree_insert(&tree,"fish",(keycmp_t)strcmp,"moo");
	dump_tree(tree,0); printf("\n");
	tree_insert(&tree,"cows",(keycmp_t)strcmp,"blubb lubb");
	dump_tree(tree,0); printf("\n");
	tree_replace(&tree,"cows",(keycmp_t)strcmp,"blubb blubb");
	dump_tree(tree,0); printf("\n");
	tree_insert(&tree,"mosquito",(keycmp_t)strcmp,"zzip!");
	tree_insert(&tree,"narf",(keycmp_t)strcmp,"nargle");
	tree_insert(&tree,"ghish",(keycmp_t)strcmp,"ghoo");
	dump_tree(tree,0); printf("\n");
	tree_delete(&tree,"mosquito",(keycmp_t)strcmp);
	dump_tree(tree,0); printf("\n");
	return 0;
}
#endif
