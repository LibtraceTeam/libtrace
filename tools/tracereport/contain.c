/* Updated: 2006-04-07 to deal with duplicate inserts */
#include <stdio.h>
#include <inttypes.h>
#include <lt_inttypes.h>
#include <stdlib.h>
#include "contain.h"
#include <assert.h>

/* a -> b */
#define implies(a,b) (!(a) || (b))

static void assert_tree(splay *tree, splay_cmp_t cmp)
{
#ifndef NDEBUG
	if (!tree)
		return;

	assert(implies(tree->left,cmp(tree->left,tree)<0));
	assert(implies(tree->right,cmp(tree,tree->right)<0));
	assert(implies(tree->left && tree->right,
				cmp(tree->left,tree->right)<0));

	assert_tree(tree->left,cmp);
	assert_tree(tree->right,cmp);
#endif
}

#undef implies

splay *splay_search_tree(splay *tree, splay_cmp_t cmp, splay *node) {

	if (tree == NULL) {
		return NULL;
	}

	assert_tree(tree,cmp);

	for (;;) {
		int cmpres = cmp(node,tree);

		if (cmpres<0) {
			splay *y;
			if (tree->left == NULL)
				break;
			/* Rotate Right */
			y = tree->left;
			tree->left=y->right;
			y->right=tree;
			tree=y;
			/* Not found? */
			if (cmp(node,tree)>0) {
				break;
			}
		} else if (cmpres>0) {
			splay *y;
			if (tree->right == NULL)
				break;
			/* Rotate Left */
			y = tree->right;
			tree->right=y->left;
			y->left=tree;
			tree=y;
			/* Not found? */
			if (cmp(node,tree)<0) {
				break;
			}
		} else {
			/* Found it */
			break;
		}
	}

	assert_tree(tree,cmp);

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
	int cmpres;
	assert_tree(tree,cmp);
	if (tree == NULL) {
		tree = node;
		node->left = NULL;
		node->right = NULL;
		assert_tree(tree,cmp);
		return tree;
	}
	assert_tree(tree,cmp);
	cmpres=cmp(node,tree);
	if (cmpres<0) {
		tree=splay_insert(tree->left,cmp,node);
	} else if (cmpres>0) {
		tree=splay_insert(tree->right,cmp,node);
	} else {
		/* Replace the root node with the current node */
		node->left = tree->left;
		node->right = tree->right;
		free(tree);
		tree=node;
	}

	assert_tree(tree,cmp);
	return tree;
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


void visitor_inorder(const struct foo_t *a)
{
	printf("%s: %s\n",a->key,a->value);
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
