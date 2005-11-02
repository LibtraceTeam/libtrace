#include <stdio.h>
#include <stdlib.h>
#include "contain.h"

splay *splay_search_tree(splay *tree, splay_cmp_t cmp, splay *node) {
	splay N, *l, *r, *y;

	if (tree == 0) {
		return 0;
	}

	N.left = N.right = 0;
	l = r = &N;

	for (;;) {
		int cmpres = cmp(node,tree);
		if (cmpres<0) {
			if (tree->left == NULL)
				break;
			if (cmp(node,tree->left)<0) {
				y = tree->left;
				tree->left = y->right;
				y->right = tree;
				tree = y;
				if (tree->left == NULL)
					break;
			}
			r->left = tree;
			r = tree;
			tree = tree->left;
		} else if (cmpres>0) {
			if (tree->right == NULL)
				break;
			if (cmp(node,tree->right)>0) {
				y = tree->right;
				tree->right = y->left;
				y->left = tree;
				tree = y;
				if (tree->right == NULL)
					break;
			}
			l->right = tree;
			l = tree;
			tree = tree->right;
		} else {
			break;
		}
	}
	l->right = tree->left;
	r->left = tree->right;
	tree->left = N.right;
	tree->right = N.left;
	return tree;
}

splay *splay_delete(splay *tree, splay_cmp_t cmp, splay *node) {
	splay *s;

	if (!tree)
		return 0;

	tree = splay_search_tree(tree, cmp, node);
	if (cmp(tree,node)==0) {
		if (tree->left == NULL) {
			s = tree->right;
		} else {
			s = splay_search_tree(tree->left, cmp, node);
			s->right = tree->right;
		}
		free(tree);
		return s;
	}
	return tree;
}

void splay_purge(splay *tree) {

	if (!tree)
		return;

	if (tree->left)
		splay_purge(tree->left);
	if (tree->right)
		splay_purge(tree->right);
	free(tree);
}
	


splay *splay_insert(splay *tree, splay_cmp_t cmp, splay *node) 
{
	if (tree == NULL) {
		tree = node;
		return tree;
	}
	if (cmp(node,tree)<0) {
		node->left = tree->left;
		node->right = tree;
		tree->left = 0;
	} else if (cmp(node,tree)>0) {
		node->right = tree->right;
		node->left = tree;
		tree->right = 0;
	} else {
		free(node);
	}

	return node;
}

void splay_visit(const splay *tree, visitor_t pre,visitor_t inorder,visitor_t post,void *userdata)
{
	if (!tree) return;
	if (pre) pre(tree,userdata);
	splay_visit(tree->left,pre,inorder,post,userdata);
	if (inorder) inorder(tree,userdata);
	splay_visit(tree->right,pre,inorder,post,userdata);
	if (post) post(tree,userdata);
}


#ifdef TEST
#include <string.h>
struct foo_t {
	splay tree;
	char *key;
	char *value;
};


void visitor_pre(const struct foo_t *a)
{
	printf("{\n");
}
void visitor_inorder(const struct foo_t *a)
{
	printf("%s: %s\n",a->key,a->value);
}
void visitor_post(const struct foo_t *a)
{
	printf("}\n");
}

int cmp(const struct foo_t *a,const struct foo_t *b)
{
	int ret= strcmp(a->key,b->key);
	printf("cmp(%s,%s)==%i\n",a->key,b->key,ret);
	return ret;
}

int main(int argc, char *argv[])
{
	struct foo_t *tree = NULL;
	struct foo_t a = { { NULL, NULL }, "a","apple" };
	struct foo_t b = { { NULL, NULL }, "b","bear" };
	struct foo_t q = { { NULL, NULL }, "a", NULL };
	struct foo_t *node;

	tree=(struct foo_t *)splay_insert((splay*)tree,(splay_cmp_t)cmp,(splay*)&a);
	splay_dump((splay*)tree,visitor_pre,visitor_inorder,visitor_post);
	tree=(struct foo_t *)splay_insert((splay*)tree,(splay_cmp_t)cmp,(splay*)&b);
	splay_dump((splay*)tree,visitor_pre,visitor_inorder,visitor_post);
	tree=(struct foo_t*)splay_search_tree((splay*)tree,(splay_cmp_t)cmp,(splay *)&q);
	printf("%s is for %s\n",q.key,tree->value);
	splay_dump((splay*)tree,visitor_pre,visitor_inorder,visitor_post);
	tree=(struct foo_t*)splay_search_tree((splay*)tree,(splay_cmp_t)cmp,(splay *)&q);
	printf("%s is for %s\n",q.key,tree->value);
	splay_dump((splay*)tree,visitor_pre,visitor_inorder,visitor_post);
	q.key="b";
	tree=(struct foo_t*)splay_search_tree((splay*)tree,(splay_cmp_t)cmp,(splay *)&q);
	printf("%s is for %s\n",q.key,tree->value);
	splay_dump((splay*)tree,visitor_pre,visitor_inorder,visitor_post);
	tree=(struct foo_t*)splay_search_tree((splay*)tree,(splay_cmp_t)cmp,(splay *)&q);
	printf("%s is for %s\n",q.key,tree->value);
	splay_dump((splay*)tree,visitor_pre,visitor_inorder,visitor_post);

	return 0;
}

#endif
